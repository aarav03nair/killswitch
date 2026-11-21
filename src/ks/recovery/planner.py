"""Recovery planner (ADR-05 §6, C5): taint set in, ordered steps out. Records and hashes only.

Inputs are the chained C2 records (via :class:`~ks.taint.RecordIndex`), a :class:`~ks.taint.Taint` from
``taint_from_alerts`` and, optionally, the live :class:`~ks.state.Store` (used only to ask whether a restore
source is redacted and what status an outbox item has). The planner never imports ``RunConfig`` and never reads
``fault``/``culprit``/``fault_tick`` (A3; AST guard in ``tests/recovery``): the culprit is ``Taint.suspect``.

Per object (ADR-05 §6.2, B6). For every object the suspect wrote in its seed window:

* head = the suspect's latest window version -> ``restore`` with ``expect`` = that version and ``to`` = the
  last untainted earlier version (a redacted ``to`` gives ``flag(redacted_restore_source)``);
* head = a later **tainted** version by someone else -> ``flag(write_write_conflict)``, no restore (B5, F2+x);
* head = a later **untainted** version (an honest blind write) -> no step, the object is *kept*;
* the suspect **created** the object (no earlier version) -> a tombstone restore (B3-03 note): C5 1.4
  ``RestoreStep.to = None`` (``to_absent``); :func:`apply_restore` writes ``put(None)``.
  :func:`restores_to_absent` also accepts the 1.3 marker ``to = VersionRef(ver=expect.ver, hash=TOMBSTONE_HASH)``.

Per tainted action, seq order (§6.3-6.6): the suspect's own window records are never re-run (their writes are
the seed). An honest deterministic action is ``rerun`` when every tainted version it read is repaired by then
(a seed version of a restored or kept object, or a version written by an earlier re-run); otherwise it *rides*
with the flag that blocks it (no step of its own, reported in :attr:`Planned.riders`). LLM agents
(``llm_agents``) get ``replan``. Class C gets ``compensate`` when a compensator is registered for its tool, else
``flag(no_compensator)``. Tainted I2 gets ``flag(tainted_i2)``. A ``no_compensator`` action with no outbox item and
all tainted reads repaired is a :attr:`Planned.c_candidates` entry: the dry-run replaces its flag with
``rerun(c_rerun_identical)`` only if the simulated re-run's writes equal the landed ones (B3-24, maya's ruling).

Outbox (§6.1, M14; B3-23). Every outbox id in a record is a real ``outbox:<id>`` object (C3 ``OutboxItem``)
written in the creating record; the planner reads its status from ``state``. Dispatched is irreversible: always
``flag(dispatched_tainted)``, never cancel; for a re-run action the dry-run (B3-24) drops that flag when the
simulated payload hash equals the dispatched one. Item of a re-run action otherwise: no step (the re-run writes v+1
of the same ``outbox:<id>``, back on hold). ``cancel_outbox`` (ADR-05 §6.1 as amended 20 Nov, maya B3-29 review,
B3-48) only for (a) queued/held/released items created by the **suspect's own window records** and (b) released
items of any other action that is not re-run (about to leave; cancel is the only stop). Every other tainted
queued/held item of a non-re-run action (rider, replan, ``flag(no_compensator | tainted_i2)``, compensate, or no
creating record) gets **no step and stays held**: it leaves only by approval (X4) and ``cancel_outbox`` is
irreversible, so it is not spent before a person resolves the flag or approves the replan. Each is listed in
:attr:`Planned.held` with what blocks it, and the dry-run renders one ``held`` line per item. An id with no
readable object (record and store disagree, or no ``state`` given) fails closed: ``flag(outbox_missing)``, scored
in R.

Resolver (D-18, ADR-05a; ``resolver="ww_rebase/1"``, default ``"off"``): right after the restore loop each
``flag(write_write_conflict, O, H)`` (obj order) is offered to :func:`ks.recovery.resolver.eligible`. If every
record-only check passes it becomes a ``resolve`` step (``rebased_hash`` and ``unblocked`` are filled by the
dry-run), O counts as repaired (the seed version and H's version ``vH``), and H gets no ``rerun`` step (the resolve
covers it), so H's readers are ordinary re-runs. A refused flag stays and :attr:`Planned.refused` names the first
failed check. ``no_resolve`` (the dry-run's one re-plan after a failed ``sim_clean``) keeps those objects as flags.
With ``resolver="off"`` the plan is byte-identical to the pre-1.7 planner.

Step order: cancel_outbox (by id), restore (by obj), resolve (by obj), rerun (by seq), compensate, replan (by seq),
flag.
The plan diff is filled by :mod:`ks.recovery.dryrun` (simulation in a rolled-back savepoint, §7).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ks.contracts import TOMBSTONE_HASH, OutboxItem, OutboxStatus, VersionRef, WriteEntry, row_obj_id
from ks.contracts.ids import SYSTEM_PRINCIPALS
from ks.contracts.record import ActionClass, Decision, Record
from ks.contracts.recovery import (ActionRef, CancelOutboxStep, CompensateStep, DiffEntry, FlagStep, RecoveryPlan,
                                   ReplanStep, RerunStep, ResolveStep, RestoreStep)
from ks.taint import RecordIndex, Taint

__all__ = ["NoPlan", "Kept", "Rider", "Held", "Planned", "plan_recovery", "restores_to_absent", "apply_restore",
           "action_ref", "default_plan_id", "with_diff"]

RECOVERY_AUTHOR = "ks.recovery"


class NoPlan(ValueError):
    """No suspended suspect, no t0 or no seed: "no suspended suspect gives no seed and no plan" (ADR-05 §4)."""


@dataclass(frozen=True)
class Kept:
    """An untainted honest write after t0 on a row the plan touches (B3 *kept* lane): no step."""

    obj: str
    ver: int
    hash: str
    author: str
    seq: int


@dataclass(frozen=True)
class Rider:
    """A tainted action with no step of its own: it read a version no step repairs (rides with the flag)."""

    action: ActionRef
    blocked_by: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class Held:
    """A tainted outbox item that gets no step and stays held (ADR-05 §6.1 amended, B3-48): it waits for a person.

    ``action`` is the creating action (``None`` if no record created it). ``blocked_by`` names what must be resolved
    first, e.g. ``replan seq 177``, ``flag(no_compensator) seq 178``, ``flag(write_write_conflict suppliers:S-22)``,
    ``rides seq 175`` (redacted args or a dry-run rider), ``sticky_taint`` (no repairable read)."""

    outbox_id: str
    status: OutboxStatus
    action: ActionRef | None
    blocked_by: tuple[str, ...]


@dataclass(frozen=True)
class Planned:
    """Planner output: the C5 plan (diff empty until the dry-run) plus the console lanes and t0 report."""

    plan: RecoveryPlan
    kept: tuple[Kept, ...]
    independent: tuple[str, ...]
    riders: tuple[Rider, ...]
    rerun_records: Mapping[int, Record]
    notes: tuple[str, ...] = field(default=())
    c_candidates: Mapping[int, Record] = field(default_factory=dict)
    """Class-C actions flagged ``no_compensator`` that the dry-run may clear (ADR-05 §6.4, B3-24 ruling "option A,
    narrowed"): the landed record has no outbox item (whole effect in its write set) and every tainted read is
    repaired by then. Cleared only if the simulated re-run's writes equal the landed ones by (obj, after.hash)."""
    held: tuple[Held, ...] = field(default=())
    """Tainted queued/held items with no step (ADR-05 §6.1 amended, B3-48), by outbox id; never cancelled here."""
    resolver: str = "off"
    """``RunConfig.resolver`` the plan was built with (ADR-05a)."""
    resolve_records: Mapping[int, Record] = field(default_factory=dict)
    """H's landed record per ``resolve`` step, by seq."""
    refused: Mapping[str, str] = field(default_factory=dict)
    """obj -> first failed check id, for each write-write flag the resolver refused (rendered on the flag line)."""
    ww_flags_before: int = 0
    """Write-write flags before the resolver pass (= resolves + remaining ww flags)."""
    replan: Any = None
    """``replan(no_resolve)`` -> :class:`Planned` with the same inputs (the dry-run's one re-plan, ADR-05a §8)."""


def action_ref(r: Record) -> ActionRef:
    return ActionRef(seq=r.seq, agent_id=r.envelope.agent_id, action_id=r.envelope.action_id)


def default_plan_id(as_of_seq: int) -> str:
    """Deterministic plan id from the record position: ``p-<as_of_seq:06d>``."""
    return f"p-{as_of_seq:06d}"


def restores_to_absent(step: RestoreStep) -> bool:
    """A tombstone restore of an object the suspect created: ``to is None`` (C5 1.4), or the 1.3 marker."""
    return step.to_absent or (step.to.hash == TOMBSTONE_HASH and step.to.ver == step.expect.ver)


def apply_restore(store: Any, step: RestoreStep, *, seq: int, action_id: str,
                  author: str = RECOVERY_AUTHOR) -> WriteEntry:
    """Execute one restore on a :class:`~ks.state.Store` inside the caller's transaction or savepoint (dry-run
    here; apply is B3-30 through the gateway). Fails closed with ``StaleExpect`` if ``expect`` moved."""
    from ks.state import StaleExpect

    if restores_to_absent(step):
        head = store.get(step.obj)
        if head is None or head.ver != step.expect.ver or head.hash != step.expect.hash:
            raise StaleExpect(f"{step.obj}: head is {None if head is None else head.ver}, plan expected "
                              f"v{step.expect.ver}")
        return store.put(step.obj, None, author=author, seq=seq, action_id=action_id)
    head = store.get(step.obj)
    if head is not None and head.ver == step.expect.ver and head.hash != step.expect.hash:
        raise StaleExpect(f"{step.obj} v{head.ver}: hash differs from the plan's expect")
    return store.restore(step.obj, step.to.ver, expect=step.expect.ver, seq=seq, action_id=action_id,
                         author=author)


def _outbox_status(state: Any, oid: str) -> OutboxStatus | None:
    """Status of the real ``outbox:<id>`` object (B3-23); ``None`` if there is none or it is unreadable."""
    if state is None:
        return None
    try:
        cur = state.get(f"outbox:{oid}")
    except Exception:  # RedactedValue: status unknown, fail closed
        return None
    if cur is None or cur.value is None:
        return None
    return OutboxItem.model_validate(cur.value).status


def _redacted(state: Any, obj: str, ver: int) -> bool:
    if state is None:
        return False
    from ks.state import RedactedValue

    try:
        state.value_at(obj, ver)
    except RedactedValue:
        return True
    return False


def plan_recovery(records: RecordIndex | Iterable[Record], taint: Taint | None, *, alert_id: str,
                  plan_id: str | None = None, state: Any = None, llm_agents: Iterable[str] = (),
                  compensators: Mapping[str, str] | None = None, resolver: str = "off",
                  no_resolve: frozenset[str] = frozenset(), alerts: Iterable[Any] = (),
                  args_of: Any = None) -> Planned:
    """Build the plan (steps, taint set; ``diff=()``) for ``taint``. Pure in records + ``taint`` (+ redaction and
    outbox status read from ``state``), so the same record gives a byte-identical plan.

    CALL-02 B2/M14: actions that created outbox items are re-run like any other deterministic reader and their
    items re-held as v+1 of the same ``outbox:<id>`` (no switch: B2 is binding, maya B3-21 review)."""
    if taint is None or taint.suspect is None or taint.t0_seq_est is None or not taint.seed:
        raise NoPlan("no suspended suspect: no seed and no plan")
    from .resolver import RESOLVERS
    if resolver not in RESOLVERS:
        raise ValueError(f"unknown resolver {resolver!r}")
    ix = RecordIndex.of(records)
    no_resolve = frozenset(no_resolve)
    alerts = tuple(alerts)

    def again(nr: frozenset[str]) -> Planned:
        return plan_recovery(ix, taint, alert_id=alert_id, plan_id=plan_id, state=state, llm_agents=llm_agents,
                             compensators=compensators, resolver=resolver, no_resolve=frozenset(nr) | no_resolve,
                             alerts=alerts, args_of=args_of)
    as_of = taint.as_of_seq
    culprit = taint.suspect
    t0 = taint.t0_seq_est
    llm = set(llm_agents)
    comps = dict(compensators or {})
    live = [r for r in ix.records if r.seq <= as_of and r.decision == Decision.EXEC]

    heads: dict[str, VersionRef] = {}
    vhash: dict[tuple[str, int], str] = {}
    for r in live:
        for w in r.write_set:
            heads[w.obj] = w.after
            vhash[(w.obj, w.after.ver)] = w.after.hash

    seed_by_obj: dict[str, list[int]] = {}
    for v in taint.seed:
        seed_by_obj.setdefault(v.obj, []).append(v.ver)

    restores: list[RestoreStep] = []
    flags: list[tuple[str, str | None, ActionRef | None]] = []
    repaired_objs: set[str] = set()      # restored or kept-by-blind-write: re-runs read a clean value
    touched_rows: set[str] = set()
    notes: list[str] = []
    for obj in sorted(seed_by_obj):
        cver = max(seed_by_obj[obj])
        head = heads[obj]
        touched_rows.add(row_obj_id(obj))
        if head.ver == cver:
            expect = VersionRef(ver=cver, hash=vhash[(obj, cver)])
            prior = [v for v in range(cver - 1, 0, -1) if not taint.is_tainted(obj, v)]
            if not prior:
                restores.append(RestoreStep(n=0, reason="tainted_create", obj=obj, expect=expect, to=None))
                repaired_objs.add(obj)
                continue
            to_ver = prior[0]
            if _redacted(state, obj, to_ver):
                flags.append(("redacted_restore_source", obj, None))
                continue
            restores.append(RestoreStep(n=0, reason="tainted_write", obj=obj, expect=expect,
                                        to=VersionRef(ver=to_ver, hash=vhash[(obj, to_ver)])))
            repaired_objs.add(obj)
        elif head.ver > cver:
            if taint.is_tainted(obj, head.ver):
                w = ix.writer(obj, head.ver)
                flags.append(("write_write_conflict", obj, None if w is None else action_ref(w)))
            else:
                repaired_objs.add(obj)  # honest blind write is the head: kept, no step
        else:  # pragma: no cover - a seed version above the head means the record does not fold
            raise ValueError(f"{obj}: seed v{cver} above head v{head.ver}")

    # --- resolver pass (ADR-05a §1-2): only flag(write_write_conflict), obj order ---------------------------------
    resolves: list[ResolveStep] = []
    resolve_records: dict[int, Record] = {}
    refused: dict[str, str] = {}
    resolved_written: set[tuple[str, int]] = set()
    covered: set[int] = set()
    ww_before = sum(1 for f in flags if f[0] == "write_write_conflict")
    if resolver != "off":
        from .resolver import RECORD_CHECKS, RULE_ID, RULE_VERSION, Context, eligible, undone_pairs
        tv = frozenset(taint.versions)

        def args_ok(r: Record) -> bool:
            try:
                args_of(r)
            except Exception:
                return False
            return True

        def args_value(r: Record) -> Any:
            return args_of(r)

        ctx = Context(ix=ix, as_of=as_of, suspect=culprit, taint=tv,
                      restored=frozenset(s.obj for s in restores), alerts=alerts,
                      llm_agents=frozenset(llm), args_ok=None if args_of is None else args_ok,
                      redacted=None if state is None else (lambda o, v: _redacted(state, o, v)),
                      undone=undone_pairs([r for r in ix.records if r.seq <= as_of],
                                          None if args_of is None else args_value))
        kept_flags = []
        for f in sorted(flags, key=lambda f: (f[1] or "", f[0])):
            reason, obj, act = f
            if reason != "write_write_conflict" or obj is None:
                kept_flags.append(f)
                continue
            if obj in no_resolve:
                refused[obj] = "sim_clean"
                kept_flags.append(f)
                continue
            el = eligible(ctx, obj, act)
            if not el.ok:
                refused[obj] = el.failed or "-"
                kept_flags.append(f)
                continue
            resolves.append(ResolveStep(n=0, reason="write_write_conflict", rule=RULE_ID, rule_version=RULE_VERSION,
                                        obj=obj, culprit_ver=el.culprit_ver, expect=el.expect, to=el.to,
                                        rebased=el.rebased, rebased_hash=el.expect.hash, unblocked=(),
                                        rationale=RECORD_CHECKS))
            resolve_records[el.rebased.seq] = ix.by_seq[el.rebased.seq]
            repaired_objs.add(obj)
            resolved_written.add((obj, el.expect.ver))
            covered.add(el.rebased.seq)
        flags = kept_flags

    seed_keys = {(v.obj, v.ver) for v in taint.seed}
    rerun_written: set[tuple[str, int]] = set(resolved_written)
    reruns: list[RerunStep] = []
    rerun_records: dict[int, Record] = {}
    replans: list[ReplanStep] = []
    compensates: list[CompensateStep] = []
    riders: list[Rider] = []
    c_candidates: dict[int, Record] = {}

    def repaired(o: str, v: int) -> bool:
        return ((o, v) in seed_keys and o in repaired_objs) or (o, v) in rerun_written

    # what blocks each non-re-run tainted action (for Planned.held): seq -> labels
    seed_flag = {obj: f"flag({reason} {obj})" for reason, obj, _ in flags if obj is not None}
    blockers: dict[int, tuple[str, ...]] = {}

    def block_labels(hits: Iterable[tuple[str, int]]) -> tuple[str, ...]:
        out: set[str] = set()
        for o, v in hits:
            w = ix.writer(o, v)
            if (o, v) in seed_keys and o in seed_flag:
                out.add(seed_flag[o])
            elif w is not None and w.seq in blockers:
                out.update(blockers[w.seq])
            else:
                out.add(f"unrepaired {o} v{v}")
        return tuple(sorted(out))

    for r in taint.actions:
        agent = r.attributed_agent
        if r.seq > as_of or agent == culprit or agent in SYSTEM_PRINCIPALS or r.seq in covered:
            continue
        ref = action_ref(r)
        if agent in llm:
            replans.append(ReplanStep(n=0, reason="tainted_llm", action=ref))
            blockers[r.seq] = (f"replan seq {r.seq}",)
            continue
        if r.action_class == ActionClass.I2:
            flags.append(("tainted_i2", None, ref))
            blockers[r.seq] = (f"flag(tainted_i2) seq {r.seq}",)
            continue
        if r.action_class == ActionClass.C:
            comp = comps.get(r.envelope.tool)
            if comp is None:
                flags.append(("no_compensator", None, ref))
                blockers[r.seq] = (f"flag(no_compensator) seq {r.seq}",)
                via = taint.via.get(r.seq, ())
                if not r.outbox_ids and via and all(repaired(h.obj, h.ver) for h in via):
                    c_candidates[r.seq] = r  # B3-24 narrowed A: the dry-run may prove the re-run identical
            else:
                compensates.append(CompensateStep(n=0, reason="tainted_effect", action=ref, compensator=comp))
                blockers[r.seq] = (f"compensate seq {r.seq}",)
            continue
        blocked = tuple((h.obj, h.ver) for h in taint.via.get(r.seq, ()) if not repaired(h.obj, h.ver))
        if blocked or not taint.via.get(r.seq):
            # not taint.via: sticky-only taint (no tainted read) cannot be repaired by re-running either
            riders.append(Rider(action=ref, blocked_by=blocked))
            blockers[r.seq] = block_labels(blocked) if blocked else ("sticky_taint",)
            continue
        reruns.append(RerunStep(n=0, reason="tainted_read", action=ref))
        rerun_records[r.seq] = r
        rerun_written.update((w.obj, w.after.ver) for w in r.write_set)

    creator: dict[str, Record] = {}
    for r in live:
        for oid in r.outbox_ids:
            creator.setdefault(oid, r)
    cancels: list[CancelOutboxStep] = []
    held: list[Held] = []
    for oid in sorted(taint.outbox_ids):
        c = creator.get(oid)
        status = _outbox_status(state, oid)
        if status is None:
            flags.append(("outbox_missing", f"outbox:{oid}", None if c is None else action_ref(c)))
            continue
        if status == OutboxStatus.CANCELLED:
            continue
        if status == OutboxStatus.DISPATCHED:
            flags.append(("dispatched_tainted", f"outbox:{oid}", None if c is None else action_ref(c)))
            continue
        if c is not None and c.seq in rerun_records:
            continue  # M14: the re-run updates the same outbox:<id> (v+1, back on hold)
        own = c is not None and c.attributed_agent == culprit and t0 <= c.seq <= as_of
        if own or status == OutboxStatus.RELEASED:
            cancels.append(CancelOutboxStep(n=0, reason="tainted_effect", outbox_id=oid))
            continue
        # §6.1 amended (B3-48): rider / replan / flagged / compensated item stays held, listed, no step
        why = ("no_creating_record",) if c is None else blockers.get(c.seq, (f"unrepaired seq {c.seq}",))
        held.append(Held(outbox_id=oid, status=status, action=None if c is None else action_ref(c), blocked_by=why))

    flag_steps = [FlagStep(n=0, reason=reason, obj=obj, action=act)
                  for reason, obj, act in sorted(flags, key=lambda f: (f[0], f[1] or "",
                                                                       f[2].seq if f[2] else 0))]
    ordered = [*cancels, *restores, *resolves, *reruns, *compensates, *replans, *flag_steps]
    steps = tuple(s.model_copy(update={"n": i}) for i, s in enumerate(ordered))

    # B3 lanes: kept = untainted honest heads written at/after t0 on any row the plan touches
    tainted_agents = set(taint.agents)
    kept: list[Kept] = []
    for obj, ref in heads.items():
        if row_obj_id(obj) not in touched_rows or taint.is_tainted(obj, ref.ver):
            continue
        w = ix.writer(obj, ref.ver)
        if w is None or w.seq < t0 or w is ix.seed or w.attributed_agent in (culprit, *SYSTEM_PRINCIPALS):
            continue
        kept.append(Kept(obj=obj, ver=ref.ver, hash=ref.hash, author=w.attributed_agent, seq=w.seq))
    kept.sort(key=lambda k: (k.obj, k.ver))
    kept_agents = {k.author for k in kept}
    independent = sorted({r.attributed_agent for r in live
                          if r.seq >= t0 and r.write_set and r is not ix.seed and r.attributed_agent
                          and r.attributed_agent not in SYSTEM_PRINCIPALS and r.attributed_agent != culprit
                          and r.attributed_agent not in tainted_agents and r.attributed_agent not in kept_agents})

    plan = RecoveryPlan(plan_id=plan_id or default_plan_id(as_of), alert_id=alert_id, culprit=culprit,
                        t0_seq_est=t0, t0_seq_est_literal=taint.t0_seq_est_literal, as_of_seq=as_of, taint_set=taint.taint_set(), steps=steps, diff=())
    return Planned(plan=plan, kept=tuple(kept), independent=tuple(independent), riders=tuple(riders),
                   rerun_records=rerun_records, notes=tuple(notes), c_candidates=c_candidates,
                   held=tuple(held), resolver=resolver, resolve_records=resolve_records, refused=refused,
                   ww_flags_before=ww_before, replan=again)


def with_diff(plan: RecoveryPlan, diff: Iterable[DiffEntry]) -> RecoveryPlan:
    """The same plan with its dry-run diff (re-validated, so ``diff`` is sorted and unique)."""
    return RecoveryPlan.model_validate({**plan.to_obj(), "diff": [d.to_obj() for d in diff]})
