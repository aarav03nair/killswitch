"""Dry-run (ADR-05 §7, CALL-02 B3): apply the plan's restores and simulate its re-runs in a rolled-back
savepoint, in seq order, and report a hash-only per-object diff. The live store is never changed: the state
digest is checked before and after and a difference raises.

Re-run simulation (B3-24) plugs in through :class:`Rerunner`: ``rerunner(store, step, record, seq)`` re-executes
``record``'s original tool and args inside the open ``simulate()`` block (writes through ``store`` at ``seq``) and
returns its write set, or a :class:`~ks.recovery.rerun.RerunOutcome` (writes + reads + effects), which
:class:`~ks.recovery.rerun.ToolRerunner` does. Without a rerunner the re-run lane is reported as *pending
simulation* and the diff holds only the restored objects.

Stale steps (ADR-05 §8, M8, maya 7). A restore is stale when its ``expect`` is no longer the head
(``StaleExpect``). A re-run is stale when an object it wrote (originally or in the simulation) has a version
written after the original action, before the dry-run, by something the plan does not repair (not another re-run
of this plan, not a seed version that a restore covers): re-running would overwrite that later write. With
``on_stale="raise"`` (default) the ``StaleExpect`` propagates; with ``on_stale="halt"`` the simulation **halts at
the first stale step**, :attr:`DryRun.stale` names it, the decision is ``hold/stale_plan`` and the diff covers
only the steps before it (the console must build a new plan with ``as_of_seq`` = now).

Plan refinement from the simulation (ADR-05 §6.3, M14). A re-run whose args are redacted or missing becomes
``flag(redacted_args)``, and later re-runs that read a version it wrote ride with it (no step). A dispatched
item whose simulated payload hash equals the dispatched one drops the planner's conservative
``flag(dispatched_tainted)``. Outbox items of a re-run the simulation drops (rider or redacted args) follow ADR-05
§6.1 as amended (B3-48): a released item gets ``cancel_outbox``; a queued/held item gets no step, stays held and is
listed in :attr:`DryRun.held` next to the planner's :attr:`Planned.held`. Steps are renumbered; the returned plan
(and its hash) is the one to approve.

Class C without a compensator (B3-24, maya's ruling "option A, narrowed"; ADR-05 §6.4 amendment). The planner
flags it ``no_compensator`` and lists it in ``Planned.c_candidates`` when its landed record has no outbox item and
its tainted reads are repaired. The dry-run re-runs it in a nested savepoint at its seq position: if the re-run has
no outbox request, no error, no stale write and writes equal to the landed ones by (obj, after.hash) (the class-C
analogue of ``dispatched_same``), the flag becomes ``rerun(c_rerun_identical)`` and the render says
``class C ... re-run identical, no compensation needed``; otherwise the savepoint is rolled back, the flag stays
and the render says why. Never silent: :attr:`DryRun.class_c` holds both verdicts.

Lanes (B3): restore · re-run · kept (untainted honest writes on a touched row, e.g. triage's ``risk_note``) ·
independent (agents that wrote after t0 and are untouched). The t0 report shows ``RecoveryPlan.t0_seq_est_literal``
and ``t0_delta`` (C5 1.4). Taint follows the suspect's self-reads through ``tool`` read entries (B3-45 option C);
a non-zero delta is the residual it does not follow: suspect writes reached only through **view** self-reads,
left out of the seed. The console names them so a person can widen the seed.

Resolver (D-18, ADR-05a §3, §8). After the restores and before the re-runs, each ``resolve`` step is simulated with
:func:`ks.recovery.resolver.rebase` (``sim_clean``): O set to value(``to``), H's tool and args re-run, one version
landed. Its hash becomes ``rebased_hash``; ``rationale`` becomes the full check list and ``unblocked`` the items of
the final plan's dependent re-runs. If ``sim_clean`` fails for any resolve (or there is no rerunner), the dry-run
re-plans with ``no_resolve`` = those objects, which keeps them as flags (the flag line names ``sim_clean``).

Plan file: :func:`write_plan` writes ``<run>/plans/<plan_id>.json`` through ``RunDir.write_plan`` (ADR-05 §7,
CALL-02 C4). A dry-run changes nothing else in the run dir (test).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from ks.contracts import OutboxStatus, VersionRef, WriteEntry
from ks.contracts.record import Record
from ks.contracts.recovery import (ActionRef, CancelOutboxStep, DiffEntry, FlagStep, RecoveryPlan, RerunStep,
                                   ResolveStep, RestoreStep)

from ks.state import StaleExpect

from .planner import Held, Planned, Rider, _outbox_status, action_ref, apply_restore, with_diff
from .rerun import ArgsUnavailable, RerunOutcome

__all__ = ["Rerunner", "DryRun", "ClassC", "C_IDENTICAL", "Stale", "StaleRerun", "StatePerturbed", "dry_run", "render", "write_plan"]


class Rerunner(Protocol):
    """B3-24 seam: re-execute ``record`` (original tool + args, M14) in the open simulation; return writes or a
    :class:`~ks.recovery.rerun.RerunOutcome`."""

    def __call__(self, store: Any, step: RerunStep, record: Record,
                 seq: int) -> Iterable[WriteEntry] | RerunOutcome: ...


C_IDENTICAL = "c_rerun_identical"
"""Reason code of the re-run step that replaces a cleared ``flag(no_compensator)`` (B3-24, ADR-05 §6.4)."""


@dataclass(frozen=True)
class ClassC:
    """Dry-run verdict on one tainted class-C action with no compensator (B3-24 ruling, "option A, narrowed").
    ``cleared`` only if (1) its landed record has no outbox item and (2) the simulated re-run's writes equal the
    landed ones by (obj, after.hash), with no outbox request, no error and no stale write. Otherwise the flag stays
    and ``why`` says which condition failed. Both outcomes are rendered (auditability)."""

    action: ActionRef
    tool: str
    cleared: bool
    why: str
    outcome: RerunOutcome | None = None


class _Differs(Exception):
    """Roll back a class-C re-run whose writes differ (its flag stays)."""


class StatePerturbed(RuntimeError):
    """The dry-run changed the live state digest (must never happen; savepoint guard failed)."""


class StaleRerun(StaleExpect):
    """``on_stale="raise"``: a re-run would overwrite a later write the plan does not repair (M8)."""


@dataclass(frozen=True)
class Stale:
    """The first stale step: the dry-run halted here (``hold/stale_plan``, M8)."""

    n: int
    op: str
    obj: str
    detail: str
    decision: str = "hold/stale_plan"


@dataclass(frozen=True)
class DryRun:
    plan: RecoveryPlan
    planned: Planned
    digest_before: str
    digest_after: str
    simulated_reruns: bool
    rerun_writes: dict[int, tuple[WriteEntry, ...]]
    outcomes: dict[int, RerunOutcome] = field(default_factory=dict)
    stale: Stale | None = None
    riders: tuple[Rider, ...] = ()
    """Re-runs the simulation could not do and that ride with a ``flag(redacted_args)`` (added to the planner's)."""
    class_c: dict[int, ClassC] = field(default_factory=dict)
    """Verdicts on the planner's class-C candidates by seq: cleared (now ``rerun(c_rerun_identical)``) or flag kept."""
    held_extra: tuple[Held, ...] = ()
    """Queued/held items of re-runs the simulation dropped (rider, redacted args): no step, stay held (B3-48)."""
    resolve_failed: dict[str, str] = field(default_factory=dict)
    """obj -> why ``sim_clean`` failed in the first pass (those objects were re-planned as flags, ADR-05a §8)."""

    @property
    def held(self) -> tuple[Held, ...]:
        """Every tainted outbox item that stays held with no step (planner + dry-run), by outbox id (ADR-05 §6.1)."""
        return tuple(sorted((*self.planned.held, *self.held_extra), key=lambda h: h.outbox_id))

    @property
    def plan_hash(self) -> str:
        return self.plan.content_hash()

    @property
    def reemitted(self) -> int:
        """Effects a re-run would create under a **new** outbox id (not deduped onto the original): 0 on the hero."""
        return sum(1 for o in self.outcomes.values() for e in o.effects if e.disposition == "new")

    @property
    def reheld(self) -> tuple[str, ...]:
        """Outbox ids put back on hold (v+1 of the same ``outbox:<id>``)."""
        return tuple(sorted(e.outbox_id for o in self.outcomes.values() for e in o.effects
                            if e.disposition in ("reheld", "reheld_same") and e.outbox_id))


def _stale_rerun(store: Any, objs: Iterable[str], after_seq: int, before_seq: int, allowed_seqs: set[int],
                 seed: set[tuple[str, int]]) -> tuple[str, str] | None:
    for obj in sorted(set(objs)):
        if obj.startswith("outbox:"):
            continue  # outbox status moves are the dispatcher's; dispositions handle them (M14)
        for e in store.history(obj):
            if after_seq < e.seq < before_seq and e.seq not in allowed_seqs and (obj, e.ver) not in seed:
                return obj, f"{obj} v{e.ver} written at seq {e.seq} by {e.author} after seq {after_seq}"
    return None


def _try_class_c(store: Any, rerunner: Rerunner, step: RerunStep, rec: Record, seq: int,
                 dropped: set[tuple[str, int]], sim_start: int, rerun_seqs: set[int],
                 seed: set[tuple[str, int]]) -> ClassC:
    """Simulate a class-C candidate in a nested savepoint; keep its writes only if they equal the landed ones."""
    act = step.action
    tool = rec.envelope.tool if rec.envelope is not None else "-"

    def keep(why: str, out: RerunOutcome | None = None) -> ClassC:
        return ClassC(action=act, tool=tool, cleared=False, why=why, outcome=out)

    if rec.outbox_ids:  # condition (1); the planner already checks, fail closed if a caller did not
        return keep("landed action has an outbox item (external effect)")
    hit = sorted((e.obj, e.ver) for e in rec.read_set if (e.obj, e.ver) in dropped)
    if hit:
        return keep("reads a version no step repairs: " + ", ".join(f"{o} v{v}" for o, v in hit))
    bad = _stale_rerun(store, (w.obj for w in rec.write_set), rec.seq, sim_start, rerun_seqs, seed)
    if bad:
        return keep(f"stale: {bad[1]}")
    result: list[RerunOutcome | None] = [None]
    try:
        with store.savepoint():
            out = rerunner(store, step, rec, seq)
            if not isinstance(out, RerunOutcome):
                raise _Differs("rerunner gave no outcome (writes cannot be compared)")
            result[0] = out
            if out.error is not None:
                raise _Differs(f"re-run error {out.error}")
            if out.effects or out.outbox_writes:
                raise _Differs("re-run makes an outbox request (external effect)")
            if out.changed:
                raise _Differs("re-run writes differ: " + ", ".join(out.changed))
            bad = _stale_rerun(store, (w.obj for w in out.tool_writes), rec.seq, sim_start, rerun_seqs, seed)
            if bad:
                raise _Differs(f"stale: {bad[1]}")
    except ArgsUnavailable as e:
        return keep(f"args unavailable ({e})")
    except _Differs as e:
        return keep(str(e), result[0])
    return ClassC(action=act, tool=tool, cleared=True, outcome=result[0],
                  why="re-run identical, no compensation needed (no outbox request; writes equal landed by obj+hash)")


def dry_run(store: Any, planned: Planned, *, rerunner: Rerunner | None = None,
            on_stale: Literal["raise", "halt"] = "raise", _failed: dict[str, str] | None = None) -> DryRun:
    """Simulate ``planned`` on ``store`` (a :class:`~ks.state.Store`) and return the plan with its diff.
    Restores run first (step order), then re-runs in seq order. See the module doc for stale steps."""
    if on_stale not in ("raise", "halt"):
        raise ValueError("on_stale is 'raise' or 'halt'")
    plan = planned.plan
    before_digest = store.state_digest()
    before = store.heads()
    seq = max(plan.as_of_seq, store.last_seq()) + 1
    sim_start = seq
    rerun_writes: dict[int, tuple[WriteEntry, ...]] = {}
    outcomes: dict[int, RerunOutcome] = {}
    rerun_seqs = set(planned.rerun_records)
    seed = {(v.obj, v.ver) for v in plan.taint_set.versions}
    dropped_versions: set[tuple[str, int]] = set()
    redacted: list[RerunStep] = []
    riders: list[Rider] = []
    class_c: dict[int, ClassC] = {}
    stale: Stale | None = None
    failed: dict[str, str] = {}
    rebased_hash: dict[int, str] = {}

    def halt(n: int, op: str, obj: str, detail: str, exc: Exception | None = None) -> None:
        nonlocal stale
        if on_stale == "raise":
            if exc is not None:
                raise exc
            raise StaleRerun(detail)
        stale = Stale(n=n, op=op, obj=obj, detail=detail)

    with store.simulate():
        for s in plan.steps:
            if isinstance(s, RestoreStep):
                try:
                    apply_restore(store, s, seq=seq, action_id=f"{plan.plan_id}.{s.n}")
                except StaleExpect as e:
                    halt(s.n, "restore", s.obj, str(e), e)
                    break
                seq += 1
        if stale is None:
            from .resolver import rebase
            tv = frozenset((v.obj, v.ver) for v in plan.taint_set.versions)
            for s in plan.steps:
                if not isinstance(s, ResolveStep):
                    continue
                head = store.get(s.obj)
                if head is None or head.ver != s.expect.ver or head.hash != s.expect.hash:
                    halt(s.n, "resolve", s.obj, f"{s.obj}: head is {None if head is None else head.ver}, plan "
                                                f"expected v{s.expect.ver}")
                    break
                if rerunner is None:
                    failed[s.obj] = "no rerunner: cannot simulate"
                    continue
                rb = rebase(store, s, planned.resolve_records[s.rebased.seq], rerunner, seq,
                            f"{plan.plan_id}.{s.n}", tv)
                if not rb.ok:
                    failed[s.obj] = rb.why
                    continue
                rebased_hash[s.n] = rb.value_hash
                seq += 1
        if failed:
            pass  # re-planned below, outside the simulation
        elif rerunner is not None and stale is None:
            work: list[tuple[int, RerunStep, bool]] = [(s.action.seq, s, False) for s in plan.steps
                                                       if isinstance(s, RerunStep)]
            work += [(q, RerunStep(n=0, reason=C_IDENTICAL, action=action_ref(r)), True)
                     for q, r in planned.c_candidates.items()]
            work.sort(key=lambda t: t[0])
            for _, s, is_c in work:
                if is_c:
                    rec = planned.c_candidates[s.action.seq]
                    verdict = _try_class_c(store, rerunner, s, rec, seq, dropped_versions, sim_start, rerun_seqs,
                                           seed)
                    class_c[s.action.seq] = verdict
                    if verdict.cleared:
                        outcomes[s.action.seq] = verdict.outcome
                        rerun_writes[s.action.seq] = verdict.outcome.writes
                        seq += 1
                    continue
                rec = planned.rerun_records[s.action.seq]
                hit = tuple((e.obj, e.ver) for e in rec.read_set if (e.obj, e.ver) in dropped_versions)
                if hit:
                    riders.append(Rider(action=s.action, blocked_by=hit))
                    dropped_versions.update((w.obj, w.after.ver) for w in rec.write_set)
                    continue
                bad = _stale_rerun(store, (w.obj for w in rec.write_set), rec.seq, sim_start, rerun_seqs, seed)
                if bad:
                    halt(s.n, "rerun", *bad)
                    break
                try:
                    out = rerunner(store, s, rec, seq)
                except ArgsUnavailable:
                    redacted.append(s)
                    dropped_versions.update((w.obj, w.after.ver) for w in rec.write_set)
                    continue
                if isinstance(out, RerunOutcome):
                    outcomes[s.action.seq] = out
                    writes = out.writes
                    new_objs = [w.obj for w in out.tool_writes if w.obj not in {x.obj for x in rec.write_set}]
                else:
                    writes = tuple(out)
                    new_objs = [w.obj for w in writes if w.obj not in {x.obj for x in rec.write_set}]
                bad = _stale_rerun(store, new_objs, rec.seq, sim_start, rerun_seqs, seed)
                if bad:
                    halt(s.n, "rerun", *bad)
                    break
                rerun_writes[s.action.seq] = writes
                seq += 1
        after = store.heads()
    after_digest = store.state_digest()
    if after_digest != before_digest:
        raise StatePerturbed(f"dry-run changed the state digest {before_digest} -> {after_digest}")
    if failed:  # ADR-05a §8: re-plan with those objects kept as flags (monotone: terminates)
        if planned.replan is None:
            raise RuntimeError(f"resolve sim_clean failed and the plan cannot be rebuilt: {failed}")
        return dry_run(store, planned.replan(frozenset(failed)), rerunner=rerunner, on_stale=on_stale,
                       _failed={**(_failed or {}), **failed})
    diff = [DiffEntry(obj=o, current=before.get(o), planned_hash=ref.hash)
            for o, ref in sorted(after.items()) if before.get(o) != ref]
    cleared = {q: v for q, v in class_c.items() if v.cleared}
    # §6.1 amended (B3-48): items of dropped re-runs: released -> cancel_outbox, queued/held -> stay held, listed
    why = {r.action.seq: ("rides: blocked by " + ", ".join(f"{o} v{v}" for o, v in r.blocked_by),) for r in riders}
    why.update({s.action.seq: (f"flag(redacted_args) seq {s.action.seq}",) for s in redacted})
    cancels: list[str] = []
    held_extra: list[Held] = []
    for q in sorted(why):
        rec = planned.rerun_records[q]
        for oid in rec.outbox_ids:
            st = _outbox_status(store, oid)
            if st == OutboxStatus.RELEASED:
                cancels.append(oid)
            elif st in (OutboxStatus.QUEUED, OutboxStatus.HELD):
                held_extra.append(Held(outbox_id=oid, status=st, action=action_ref(rec), blocked_by=why[q]))
    refined = _refine(plan, outcomes, redacted, {r.action.seq for r in riders}, cleared, cancels)
    refined = _finalize_resolves(refined, planned, rebased_hash)
    return DryRun(plan=with_diff(refined, diff), planned=planned, digest_before=before_digest,
                  digest_after=after_digest, simulated_reruns=rerunner is not None, rerun_writes=rerun_writes,
                  outcomes=outcomes, stale=stale, riders=tuple(riders), class_c=class_c,
                  held_extra=tuple(held_extra), resolve_failed=dict(_failed or {}))


def _finalize_resolves(plan: RecoveryPlan, planned: Planned, rebased_hash: dict[int, str]) -> RecoveryPlan:
    """ADR-05a §3: fill each resolve's ``rebased_hash`` (from ``sim_clean``), ``rationale`` (every check) and
    ``unblocked`` (items of the final plan's dependent re-runs). Steps keep their numbers."""
    if not any(isinstance(s, ResolveStep) for s in plan.steps):
        return plan
    from .resolver import CHECKS, unblocked_for
    # map the (possibly renumbered) resolve steps back to the simulated ones by obj
    by_obj = {s.obj: rebased_hash.get(s.n) for s in planned.plan.steps if isinstance(s, ResolveStep)}
    recs = {**planned.rerun_records, **planned.c_candidates}
    reruns = [recs[s.action.seq] for s in plan.steps if isinstance(s, RerunStep) and s.action.seq in recs]
    steps = []
    for s in plan.steps:
        if isinstance(s, ResolveStep):
            h = by_obj.get(s.obj)
            if h is None:  # not simulated (halted before it): leave the planner's placeholder, never applied
                steps.append(s)
                continue
            s = s.model_copy(update={"rebased_hash": h, "rationale": CHECKS,
                                     "unblocked": unblocked_for(s.obj, s.culprit_ver.ver, s.expect.ver, reruns, plan)})
        steps.append(s)
    return RecoveryPlan.model_validate({**plan.to_obj(), "steps": [s.to_obj() for s in steps]})


def _refine(plan: RecoveryPlan, outcomes: dict[int, RerunOutcome], redacted: list[RerunStep],
            rides: set[int], cleared: dict[int, ClassC] | None = None,
            cancels: Iterable[str] = ()) -> RecoveryPlan:
    same = {f"outbox:{e.outbox_id}" for o in outcomes.values() for e in o.effects
            if e.disposition == "dispatched_same"}
    gone = rides | {s.action.seq for s in redacted}
    cleared = cleared or {}
    have = {s.outbox_id for s in plan.steps if s.op == "cancel_outbox"}
    new_cancels = [CancelOutboxStep(n=0, reason="tainted_effect", outbox_id=o) for o in sorted(set(cancels) - have)]
    if not same and not gone and not cleared and not new_cancels:
        return plan
    keep = [s for s in plan.steps
            if not (isinstance(s, RerunStep) and s.action.seq in gone)
            and not (isinstance(s, FlagStep) and s.reason == "dispatched_tainted" and s.obj in same)
            and not (isinstance(s, FlagStep) and s.reason == "no_compensator" and s.action is not None
                     and s.action.seq in cleared)]
    flags = [s for s in keep if isinstance(s, FlagStep)]
    flags += [FlagStep(n=0, reason="redacted_args", obj=None, action=s.action) for s in redacted]
    flags.sort(key=lambda f: (f.reason, f.obj or "", f.action.seq if f.action else 0))
    reruns = sorted([s for s in keep if isinstance(s, RerunStep)]
                    + [RerunStep(n=0, reason=C_IDENTICAL, action=v.action) for v in cleared.values()],
                    key=lambda s: s.action.seq)
    rest = [s for s in keep if not isinstance(s, (FlagStep, RerunStep))]
    co = sorted([s for s in rest if s.op == "cancel_outbox"] + new_cancels, key=lambda s: s.outbox_id)
    before = co + [s for s in rest if s.op == "restore"] + [s for s in rest if s.op == "resolve"]
    after = [s for s in rest if s.op not in ("cancel_outbox", "restore", "resolve")]
    ordered = before + reruns + after + flags
    steps = tuple(s.model_copy(update={"n": i}) for i, s in enumerate(ordered))
    return RecoveryPlan.model_validate({**plan.to_obj(), "steps": [s.to_obj() for s in steps]})


def _v(ref: VersionRef | None) -> str:
    return "absent" if ref is None else f"v{ref.ver} {ref.hash[:12]}"


def render(d: DryRun) -> str:
    """Console text of the dry-run, one line per entry, grouped by lane. Hashes only."""
    p, pl = d.plan, d.planned
    diff = {e.obj: e for e in p.diff}
    from .resolver import label
    out = [f"plan {p.plan_id}  hash {d.plan_hash[:16]}  alert {p.alert_id}  culprit {p.culprit}  "
           f"as_of_seq {p.as_of_seq}  {label(pl.resolver)}"]
    lit = p.t0_seq_est_literal
    out.append(f"t0_seq_est {p.t0_seq_est}  literal walk {lit if lit is not None else '-'}  "
               f"t0_delta {p.t0_delta if p.t0_delta is not None else '-'}"
               + ("  (view-only self-reads not followed: suspect writes from the literal t0 are outside the "
                  "seed, review them)" if p.t0_delta else ""))
    for s in p.steps:
        if s.op == "restore":
            e = diff.get(s.obj)
            out.append(f"restore      {s.obj}  expect {_v(s.expect)} -> "
                       f"{'absent (tombstone)' if s.to is None or s.reason == 'tainted_create' else _v(s.to)}"
                       f"  planned {e.planned_hash[:12] if e else '-'}")
    for s in p.steps:
        if s.op == "resolve":
            out.append(f"resolve      {s.obj} ({s.rule}/{s.rule_version}): {p.culprit} v{s.culprit_ver.ver} reverted, "
                       f"{s.rebased.agent_id} edit rebased on v{s.to.ver} -> {s.rebased_hash[:8]}; unblocked "
                       f"{', '.join(s.unblocked) or '-'}; checks {','.join(s.rationale)}; undo: ks recover RUN "
                       f"--unresolve {p.plan_id}.{s.n}")
        elif s.op == "unresolve":
            from .resolver import revert_text
            r0 = s.reverts[0]
            out.append(f"unresolve    {s.resolution.action_id}: {r0.obj} back to v{r0.to.ver}, flag raised again; "
                       f"re-held {', '.join(s.reheld) or '-'}"
                       + "".join(f"; {revert_text(e)}" for e in s.reverts[1:]))
    for s in p.steps:
        if s.op == "rerun":
            ws = d.rerun_writes.get(s.action.seq)
            o = d.outcomes.get(s.action.seq)
            if not d.simulated_reruns:
                tail = "pending simulation"
            elif ws is None:
                tail = "not simulated (halted)"
            else:
                tail = ", ".join(f"{w.obj} -> {w.after.hash[:12]}" for w in ws) or "no writes"
                if o is not None:
                    tail += f"  changed {len(o.changed)}" + (f"  error {o.error}" if o.error else "")
                    tail += "".join(f"  effect outbox:{e.outbox_id or 'NEW'} {e.disposition}" for e in o.effects)
            if s.reason == C_IDENTICAL:
                tail += "  (class C, cleared: see below)"
            out.append(f"rerun        {s.action.agent_id} seq {s.action.seq} {s.action.action_id}  {tail}")
    for s in p.steps:
        if s.op == "cancel_outbox":
            out.append(f"cancel       outbox:{s.outbox_id}")
        elif s.op in ("replan", "compensate"):
            out.append(f"{s.op:<12} {s.action.agent_id} seq {s.action.seq}")
        elif s.op == "flag":
            who = f" {s.action.agent_id} seq {s.action.seq}" if s.action else ""
            why = ""
            if s.reason == "write_write_conflict" and pl.resolver != "off" and s.obj in pl.refused:
                why = f" (resolver: {pl.refused[s.obj]} failed"
                why += f": {d.resolve_failed[s.obj]})" if s.obj in d.resolve_failed else ")"
            out.append(f"flag         {s.reason} {s.obj or '-'}{who}{why}")
    for q in sorted(d.class_c):
        v = d.class_c[q]
        out.append(f"class C      {v.action.action_id} seq {q} {v.tool}: "
                   + (v.why if v.cleared else f"flag(no_compensator) kept: {v.why}"))
    for h in d.held:
        who = f"{h.action.agent_id} seq {h.action.seq}" if h.action else "no creating record"
        out.append(f"held         outbox:{h.outbox_id} {h.status.value} {who}  no step, waits for "
                   + "; ".join(h.blocked_by))
    for k in pl.kept:
        out.append(f"kept         {k.obj} v{k.ver} by {k.author} (seq {k.seq})  no step")
    for r in (*pl.riders, *d.riders):
        out.append(f"rides        {r.action.agent_id} seq {r.action.seq}  blocked by "
                   + (", ".join(f"{o} v{v}" for o, v in r.blocked_by) or "policy"))
    out.append(f"independent  {', '.join(pl.independent) or '-'}")
    for o, e in diff.items():
        out.append(f"diff         {o}  {_v(e.current)} -> {e.planned_hash[:12]}")
    if d.stale is not None:
        out.append(f"{d.stale.decision}  halted at step {d.stale.n} ({d.stale.op} {d.stale.obj}): {d.stale.detail}; "
                   f"build a new plan with as_of_seq = now")
    if d.simulated_reruns:
        out.append(f"reheld {len(d.reheld)}  reemitted {d.reemitted}")
    out.append(f"flags {sum(1 for s in p.steps if s.op == 'flag')}  state digest unchanged {d.digest_after[:16]}")
    if pl.resolver != "off":
        ww = sum(1 for s in p.steps if s.op == "flag" and s.reason == "write_write_conflict")
        out.append(f"{label(pl.resolver)}  ww_flags_before {ww + sum(1 for s in p.steps if s.op == 'resolve')}  "
                   f"ww_flags_after {ww}")
    out.extend(f"note         {n}" for n in pl.notes)
    return "\n".join(out) + "\n"


def write_plan(plan: RecoveryPlan, rundir: Any) -> Path:
    """Write ``<run>/plans/<plan_id>.json`` (canonical bytes, 0600) through the run dir's own ``write_plan``
    (C6 ``RunDir.write_plan``; ADR-05 §7, CALL-02 C4: ``plans/**`` is a deterministic file). ``rundir`` is
    duck-typed so this package never imports the run-dir module (A3 guard: it would expose ``RunConfig``)."""
    return Path(rundir.write_plan(plan))
