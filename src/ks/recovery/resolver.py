"""Auditable, reversible resolver for write-write conflicts (D-18, ADR-05a; CALL-02 B5-a). Owner: vikram.

One rule, versioned: ``ww_rebase`` v1. It looks only at ``flag(write_write_conflict, O, H)`` and resolves it only
when **every** check in :data:`CHECKS` passes (ADR-05a §2 table, in table order). A resolution restores O to its
last clean version ``vT``, re-runs the honest action H's original tool and args on that state, and lands the result
as **one** new version (author ``ks.recovery``) in one gateway transaction (:func:`rebase`). Everything else stays a
flag and waits for a person.

The rule is a pure function of (records <= ``as_of_seq``, the plan's taint set, the alerts (:func:`refused_agents`)
and the side store): :func:`eligible`. The planner calls it (``resolver="ww_rebase/1"``), and ``ks.verify.recovery`` calls
the same function on the landed record to re-derive the checks (reason ``resolution_invalid``). It never reads
``fault``/``culprit``/``fault_tick`` of the config (A3; the culprit is the plan's ``Taint.suspect``).

Undo (ADR-05a §5): :func:`plan_unresolve` builds a one-step plan, either ``unresolve`` (the resolved object back to
the honest head, plus what this plan's dependent re-runs wrote, each back to the version it replaced; their items
re-held ``resolution_reverted``) or ``flag(unresolve_blocked)`` when anything outside the resolving plan has touched
those objects since, or an item has been released or dispatched. Undoing an undo is a person's job: the rule never
resolves that (O, H) again (``not_undone``).

Definitions used by both planner and verify (so they agree by construction):

* **seed version**: a version in the taint set written by the plan's culprit (= the A8 seed: the culprit writes
  nothing after its suspension, and nothing before t0 is tainted);
* ``unblocked``: outbox items of the plan's ``rerun`` steps that depend on the resolution, i.e. whose landed record
  read (O, vC) or (O, vH), or a version written by an earlier such re-run (seq order), minus items the plan flags
  ``dispatched_tainted``. They are re-held by their re-run (``rerun_reheld``); the resolution never releases.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ks.contracts import OutboxStatus, ReadEntry, VersionRef, WriteEntry, split_obj_id
from ks.contracts.ids import SYSTEM_PRINCIPALS
from ks.contracts.record import Decision, Record
from ks.contracts.recovery import (ActionRef, DiffEntry, FlagStep, RecoverArgs, RecoveryPlan, RerunStep, ResolveStep,
                                   RevertEntry, UnresolveStep)
from ks.taint import RecordIndex
from ks.taint.closure import suspend_seq_of

__all__ = ["RULE_ID", "RULE_VERSION", "RULE", "RULES", "RESOLVER_OFF", "RESOLVER_ON", "RESOLVERS", "CHECKS",
           "RECORD_CHECKS", "RESOLVE_TOOL", "UNRESOLVE_TOOL", "UNRESOLVE_REASON", "UNRESOLVE_CHECKS", "Context",
           "Eligibility", "eligible", "refused_agents", "undone_pairs", "unblocked_for", "Rebased", "rebase", "rule_known",
           "plan_unresolve", "unresolve_problems", "dependents", "resolving_plan_id", "label",
           "expected_reverts"]

RULE_ID = "ww_rebase"
RULE_VERSION = 1
RULE = (RULE_ID, RULE_VERSION)
RULES = frozenset({RULE})
"""Every (rule, version) verify accepts."""
RESOLVER_OFF = "off"
RESOLVER_ON = "ww_rebase/1"
RESOLVERS = (RESOLVER_OFF, RESOLVER_ON)
CHECKS = ("row_object", "single_honest_write", "honest_deterministic", "single_object", "no_tainted_view_reads",
          "seed_reads_only", "clean_base", "not_undone", "sim_clean")
"""ADR-05a §2, table order. The resolution's ``rationale`` is exactly this tuple."""
RECORD_CHECKS = CHECKS[:-1]
"""Plan-time, record-only checks (``sim_clean`` is the dry-run's, proven on the landed record by verify)."""
RESOLVE_TOOL = "ks.recover.resolve"
UNRESOLVE_TOOL = "ks.recover.unresolve"
UNRESOLVE_REASON = "resolution_reverted"
"""``UnresolveStep.reason`` and the hold reason of the items an undo re-holds."""
UNRESOLVE_CHECKS = ("resolution_executed", "not_undone_before", "no_foreign_touch", "reheld_not_released")
RECOVERY = "ks.recovery"


def label(resolver: str) -> str:
    """ADR-05a §7 label: ``resolver: off`` or ``resolver: ww_rebase/1 (on)``."""
    return "resolver: off" if resolver == RESOLVER_OFF else f"resolver: {resolver} (on)"


def rule_known(step: ResolveStep) -> bool:
    return (step.rule, step.rule_version) in RULES


@dataclass(frozen=True)
class Context:
    """Inputs of :func:`eligible`. ``taint`` = the plan's taint set versions; ``restored`` = objects the plan restores.
    ``args_ok(record)`` checks H's args are in the side store and not redacted (``None``: not checked here; the
    dry-run's ``sim_clean`` fails on missing args). ``redacted(obj, ver)`` (``None``: not checked). ``undone`` from
    :func:`undone_pairs`."""

    ix: RecordIndex
    as_of: int
    suspect: str
    taint: frozenset
    restored: frozenset = frozenset()
    alerts: tuple = ()
    llm_agents: frozenset = frozenset()
    args_ok: Callable[[Record], bool] | None = None
    redacted: Callable[[str, int], bool] | None = None
    undone: frozenset = frozenset()


@dataclass(frozen=True)
class Eligibility:
    ok: bool
    passed: tuple[str, ...]
    failed: str | None
    detail: str = ""
    culprit_ver: VersionRef | None = None
    expect: VersionRef | None = None
    to: VersionRef | None = None
    rebased: ActionRef | None = None
    seed_objs: tuple[str, ...] = ()
    """Objects (other than O) whose seed versions H read through the tool: the plan must restore them first."""


def _ref(r: Record) -> ActionRef:
    return ActionRef(seq=r.seq, agent_id=r.envelope.agent_id, action_id=r.envelope.action_id)


def refused_agents(ix: RecordIndex, as_of: int, suspect: str, taint: frozenset, alerts: Iterable[Any]) -> frozenset:
    """ADR-05a §2 ``honest_deterministic`` (rev 3, maya S4-13 ruling): the agents whose write the rule never rebases
    because they may be the rogue. The planner and ``ks.verify.recovery`` both call this, so they agree by
    construction. Record-only (never ``fault``/``culprit`` of the config):

    * the plan's suspect;
    * every alert's ``root_candidates[0]`` (the sole writer of its evidence, H1), even when a person chose another
      suspect;
    * every writer of any alert's ``evidence_versions`` (covers alerts with no sole writer, ``root_candidates=()``);
    * every author of a **taint origin**: a tainted version (seq <= ``as_of``) whose writing record read no tainted
      version, i.e. a write that is in the taint set without being derived from it (the A8 seed, or a sticky agent).

    ``root_candidates[1..]`` are hypotheses reached only through reads (ADR-05 §5, H2: never auto-suspended); they
    are not refused for that alone. LLM, system and suspended agents are refused in :func:`eligible`."""
    out = {suspect}
    for a in alerts:
        if a.root_candidates:
            out.add(a.root_candidates[0])
        for e in a.evidence_versions:
            w = ix.writer(e.obj, e.ver)
            if w is not None and w.attributed_agent:
                out.add(w.attributed_agent)
    for r in ix.records:
        if r.seq > as_of or r.decision != Decision.EXEC or not r.attributed_agent or r.attributed_agent in out:
            continue
        if any((w.obj, w.after.ver) in taint for w in r.write_set) \
                and not any((e.obj, e.ver) in taint for e in r.read_set):
            out.add(r.attributed_agent)
    return frozenset(out)


def eligible(ctx: Context, obj: str, action: ActionRef | None) -> Eligibility:
    """The record-only checks (:data:`RECORD_CHECKS`) for ``flag(write_write_conflict, obj, action)``, in order;
    stops at the first failure (``failed`` = its id)."""
    passed: list[str] = []

    def fail(check: str, detail: str) -> Eligibility:
        return Eligibility(False, tuple(passed), check, detail)

    ix, as_of = ctx.ix, ctx.as_of
    hist: dict[int, tuple[str, Record]] = {}
    for r in ix.records:
        if r.seq > as_of or r.decision != Decision.EXEC:
            continue
        for w in r.write_set:
            if w.obj == obj:
                hist[w.after.ver] = (w.after.hash, r)
    try:
        _, _, fld = split_obj_id(obj)
    except ValueError:
        return fail("row_object", f"{obj}: not an object id")
    if fld is not None:
        return fail("row_object", f"{obj} is a field object (sensitive field): a person decides")
    passed.append("row_object")

    seed = [v for v, (_, w) in hist.items() if (obj, v) in ctx.taint and w.attributed_agent == ctx.suspect]
    if not seed or not hist:
        return fail("single_honest_write", f"{obj}: no seed version of {ctx.suspect}")
    vc = max(seed)
    vh = max(hist)
    hrec = hist[vh][1]
    if vh != vc + 1 or action is None or hrec.seq != action.seq:
        return fail("single_honest_write", f"{obj}: head v{vh}, seed v{vc}: not exactly one later write by the "
                                           f"flagged action")
    passed.append("single_honest_write")

    agent = hrec.attributed_agent
    sus = suspend_seq_of(ix, agent) if agent else None
    if not agent or agent in ctx.llm_agents or agent in SYSTEM_PRINCIPALS or (sus is not None and sus <= as_of) \
            or agent in refused_agents(ix, as_of, ctx.suspect, ctx.taint, ctx.alerts):
        return fail("honest_deterministic", f"{agent}: LLM, system, suspended, suspect, top root candidate, "
                                            f"evidence writer or taint-origin author")
    passed.append("honest_deterministic")

    if hrec.envelope is None or {w.obj for w in hrec.write_set} != {obj} or hrec.outbox_ids \
            or (ctx.args_ok is not None and not ctx.args_ok(hrec)):
        return fail("single_object", f"seq {hrec.seq}: writes {sorted(w.obj for w in hrec.write_set)}, "
                                     f"outbox {list(hrec.outbox_ids)}, or args missing/redacted")
    passed.append("single_object")

    view_hits = sorted((e.obj, e.ver) for e in hrec.read_set if e.source == "view" and (e.obj, e.ver) in ctx.taint)
    if view_hits:
        return fail("no_tainted_view_reads", "tainted view read " + ", ".join(f"{o} v{v}" for o, v in view_hits))
    passed.append("no_tainted_view_reads")

    seed_objs: set[str] = set()
    for e in hrec.read_set:
        if (e.obj, e.ver) not in ctx.taint:
            continue
        w = ix.writer(e.obj, e.ver)
        is_seed = w is not None and w.attributed_agent == ctx.suspect
        if not is_seed or not (e.obj == obj or e.obj in ctx.restored):
            return fail("seed_reads_only", f"read {e.obj} v{e.ver}: not a seed version the plan reverts")
        if e.obj != obj:
            seed_objs.add(e.obj)
    passed.append("seed_reads_only")

    prior = [v for v in range(vc - 1, 0, -1) if (obj, v) not in ctx.taint and v in hist]
    if not prior:
        return fail("clean_base", f"{obj}: no clean version before v{vc} (created by the suspect)")
    vt = prior[0]
    if ctx.redacted is not None and ctx.redacted(obj, vt):
        return fail("clean_base", f"{obj} v{vt} is redacted")
    passed.append("clean_base")

    if (obj, hrec.seq) in ctx.undone or (obj, -1) in ctx.undone or ("*", -1) in ctx.undone:
        return fail("not_undone", f"a person undid an earlier resolution of {obj} / seq {hrec.seq}")
    passed.append("not_undone")

    return Eligibility(True, tuple(passed), None, "", culprit_ver=VersionRef(ver=vc, hash=hist[vc][0]),
                       expect=VersionRef(ver=vh, hash=hist[vh][0]), to=VersionRef(ver=vt, hash=hist[vt][0]),
                       rebased=_ref(hrec), seed_objs=tuple(sorted(seed_objs)))


def _args(args_value: Callable[[Record], Any] | None, r: Record) -> RecoverArgs | None:
    if args_value is None:
        return None
    try:
        return RecoverArgs.model_validate(args_value(r))
    except Exception:
        return None


def undone_pairs(records: Iterable[Record], args_value: Callable[[Record], Any] | None,
                 *, before: int | None = None) -> frozenset:
    """(obj, H seq) of every resolution an executed ``ks.recover.unresolve`` (seq < ``before``) undid. Fails closed:
    an unreadable undo gives (obj, -1) (any H on that object) or ("*", -1) (everything)."""
    recs = list(records)
    by_seq = {r.seq: r for r in recs}
    out: set = set()
    for r in recs:
        env = r.envelope
        if env is None or r.decision != Decision.EXEC or env.tool != UNRESOLVE_TOOL or env.agent_id != RECOVERY:
            continue
        if before is not None and r.seq >= before:
            continue
        a = _args(args_value, r)
        if a is None or not isinstance(a.step, UnresolveStep):
            out.add(("*", -1))
            continue
        rr = by_seq.get(a.step.resolution.seq)
        ra = None if rr is None else _args(args_value, rr)
        if ra is None or not isinstance(ra.step, ResolveStep):
            out.add((a.step.reverts[0].obj, -1))
            continue
        out.add((ra.step.obj, ra.step.rebased.seq))
    return frozenset(out)


def unblocked_for(obj: str, vc: int, vh: int, rerun_records: Iterable[Record], plan: RecoveryPlan) -> tuple[str, ...]:
    """Module doc, ``unblocked``: items of the plan's re-runs that depend on the resolved object."""
    dirty = {(obj, vc), (obj, vh)}
    ids: set[str] = set()
    for rec in sorted(rerun_records, key=lambda r: r.seq):
        if any((e.obj, e.ver) in dirty for e in rec.read_set):
            dirty.update((w.obj, w.after.ver) for w in rec.write_set)
            ids.update(rec.outbox_ids)
    gone = {s.obj[len("outbox:"):] for s in plan.steps
            if s.op == "flag" and s.reason == "dispatched_tainted" and s.obj}
    return tuple(sorted(ids - gone))


# --- apply / simulate ------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Rebased:
    """Outcome of :func:`rebase` (hashes only)."""

    ok: bool
    why: str
    write: WriteEntry | None = None
    reads: tuple[ReadEntry, ...] = ()

    @property
    def value_hash(self) -> str | None:
        return None if self.write is None else self.write.after.hash


class _Discard(Exception):
    pass


def rebase(store: Any, step: ResolveStep, record: Record, rerunner: Any, seq: int, action_id: str,
           taint: frozenset) -> Rebased:
    """ADR-05a §4 inside the caller's transaction or simulation: in a savepoint that is rolled back, put O to
    value(``to``) and re-run H's original tool and args (``rerunner``, M14); capture the value it leaves on O; then
    write that value as **one** new version of O at ``seq`` (author ``ks.recovery``, ``action_id``). Read set = the
    re-run's tool reads with O listed at ``to``. Refuses (nothing written) unless the re-run has no error, writes
    exactly {O}, requests no outbox item and reads no tainted version (``sim_clean``). The caller compares
    ``value_hash`` with the plan's ``rebased_hash`` (apply)."""
    from .rerun import ArgsUnavailable

    obj = step.obj
    got: dict[str, Any] = {}
    try:
        with store.savepoint():
            store.restore(obj, step.to.ver, expect=step.expect.ver, seq=seq, action_id=action_id,
                          author=RECOVERY)
            out = rerunner(store, RerunStep(n=step.n, reason="ww_rebase", action=step.rebased), record, seq + 1)
            cur = store.get(obj)
            got.update(out=out, value=None if cur is None else cur.value, present=cur is not None)
            raise _Discard
    except _Discard:
        pass
    except ArgsUnavailable as e:
        return Rebased(False, f"args unavailable ({e})")
    except Exception as e:  # stale expect, redacted base, tool failure: nothing lands
        return Rebased(False, f"{type(e).__name__}: {str(e)[:160]}")
    out = got["out"]
    if getattr(out, "error", None):
        return Rebased(False, f"re-run error {out.error}")
    if {w.obj for w in out.tool_writes} != {obj}:
        return Rebased(False, f"re-run writes {sorted(w.obj for w in out.tool_writes)}, not exactly {obj}")
    if out.effects or out.outbox_writes:
        return Rebased(False, "re-run requests an outbox item")
    reads = [e for e in out.reads if e.obj != obj]
    reads.append(ReadEntry(obj=obj, ver=step.to.ver, hash=step.to.hash))
    reads.sort(key=lambda e: (e.obj, e.ver))
    hit = [f"{e.obj} v{e.ver}" for e in reads if (e.obj, e.ver) in taint]
    if hit:
        return Rebased(False, "re-run reads tainted " + ", ".join(hit))
    if not got["present"] or got["value"] is None:
        return Rebased(False, f"re-run leaves {obj} absent")
    w = store.put(obj, got["value"], author=RECOVERY, seq=seq, action_id=action_id)
    return Rebased(True, "ok", w, tuple(reads))


# --- undo ----------------------------------------------------------------------------------------------------
def resolving_plan_id(action_id: str) -> str:
    """``p-000216.3`` -> ``p-000216``."""
    return action_id.rsplit(".", 1)[0]


def dependents(records: Iterable[Record], resolve_rec: Record, plan_id: str, *,
               before: int | None = None) -> list[Record]:
    """Executed ``ks.recover.rerun`` records of ``plan_id`` after the resolution (and before ``before``) whose read
    set hits the rebased version or a version written by an earlier such re-run (seq order)."""
    w = resolve_rec.write_set[0]
    dirty = {(w.obj, w.after.ver)}
    out = []
    mine = plan_id + "."
    for r in sorted(records, key=lambda r: r.seq):
        env = r.envelope
        if r.seq <= resolve_rec.seq or (before is not None and r.seq >= before) or env is None \
                or r.decision != Decision.EXEC or env.tool != "ks.recover.rerun" or env.agent_id != RECOVERY \
                or not env.action_id.startswith(mine):
            continue
        if any((e.obj, e.ver) in dirty for e in r.read_set):
            dirty.update((x.obj, x.after.ver) for x in r.write_set)
            out.append(r)
    return out


def _heads(records: Iterable[Record], before: int | None = None) -> dict[str, VersionRef]:
    h: dict[str, VersionRef] = {}
    for r in sorted(records, key=lambda r: r.seq):
        if r.decision != Decision.EXEC or (before is not None and r.seq >= before):
            continue
        for w in r.write_set:
            h[w.obj] = w.after
    return h


def _reverts(records: list[Record], resolve_rec: Record, step: ResolveStep, plan_id: str,
             before: int | None) -> tuple[list[RevertEntry], list[str], str | None]:
    heads = _heads(records, before)
    deps = dependents(records, resolve_rec, plan_id, before=before)
    out = [RevertEntry(obj=step.obj, expect=heads[step.obj], to=step.expect)]
    seen = {step.obj}
    extra: list[RevertEntry] = []
    why = None
    for d in deps:
        for w in d.write_set:
            if w.obj.startswith("outbox:") or w.obj in seen:
                continue
            seen.add(w.obj)
            if w.before is None:
                why = why or f"{w.obj} was created by re-run seq {d.seq}: nothing to put back"
                continue
            extra.append(RevertEntry(obj=w.obj, expect=heads[w.obj], to=w.before))
    reheld = sorted({o for d in deps for o in d.outbox_ids})
    return out + sorted(extra, key=lambda e: e.obj), reheld, why


def unresolve_problems(records: Iterable[Record], resolve_rec: Record, reverts: Iterable[RevertEntry], reheld: Iterable[str],
                       status_of: Callable[[str], OutboxStatus | None], *, before: int | None = None) -> str | None:
    """Why an undo is blocked (ADR-05a §5), or ``None``: a record that is not a step of the resolving plan has read
    or written a revert object since the resolution; a revert's ``expect`` is not the head; or a re-held item is
    released or dispatched."""
    recs = list(records)
    plan_id = resolving_plan_id(resolve_rec.envelope.action_id)
    objs = {e.obj for e in reverts}
    mine = plan_id + "."
    for r in sorted(recs, key=lambda r: r.seq):
        env = r.envelope
        if r.seq <= resolve_rec.seq or (before is not None and r.seq >= before) or r.decision != Decision.EXEC:
            continue
        if env is not None and env.agent_id == RECOVERY and env.action_id.startswith(mine):
            continue
        touched = {e.obj for e in r.read_set} | {w.obj for w in r.write_set}
        if touched & objs:
            return f"seq {r.seq} ({r.attributed_agent}) touched {sorted(touched & objs)[0]} after the resolution"
    heads = _heads(recs, before)
    for e in reverts:
        if heads.get(e.obj) != e.expect:
            return f"{e.obj}: head is not v{e.expect.ver}"
    for oid in reheld:
        st = status_of(oid)
        if st in (OutboxStatus.RELEASED, OutboxStatus.DISPATCHED):
            return f"outbox:{oid} is {st.value}: its effect may have left"
    return None


def plan_unresolve(records: Iterable[Record], ref: str, *, plan_of: Callable[[str], RecoveryPlan],
                   args_value: Callable[[Record], Any], status_of: Callable[[str], OutboxStatus | None],
                   plan_id: str | None = None) -> tuple[RecoveryPlan, str | None]:
    """``ks recover RUN --unresolve <plan_id>.<n>`` -> (plan, why blocked or ``None``): a one-step plan ``p-<as_of_seq>`` with an ``unresolve`` step, or
    a ``flag(unresolve_blocked)`` (module doc). Raises ``ValueError`` when ``ref`` names no executed resolution or
    the resolution was already undone (undoing an undo is a person's job)."""
    recs = sorted(records, key=lambda r: r.seq)
    rr = next((r for r in recs if r.envelope is not None and r.decision == Decision.EXEC
               and r.envelope.tool == RESOLVE_TOOL and r.envelope.agent_id == RECOVERY
               and r.envelope.action_id == ref), None)
    if rr is None:
        raise ValueError(f"no executed ks.recover.resolve with action id {ref}")
    a = _args(args_value, rr)
    if a is None or not isinstance(a.step, ResolveStep):
        raise ValueError(f"{ref}: resolution args unreadable")
    for r in recs:
        if r.envelope is not None and r.decision == Decision.EXEC and r.envelope.tool == UNRESOLVE_TOOL:
            u = _args(args_value, r)
            if u is None or (isinstance(u.step, UnresolveStep) and u.step.resolution.seq == rr.seq):
                raise ValueError(f"{ref} was already undone at seq {r.seq}: undoing an undo is a person's job")
    p = plan_of(a.plan_id)
    if p.content_hash() != a.plan_hash:
        raise ValueError(f"plans/{a.plan_id}.json does not hash to the resolution's plan_hash")
    step = a.step
    as_of = recs[-1].seq
    reverts, reheld, why = _reverts(recs, rr, step, a.plan_id, None)
    why = why or unresolve_problems(recs, rr, reverts, reheld, status_of)
    ref_act = _ref(rr)
    if why is not None:
        s = FlagStep(n=0, reason="unresolve_blocked", obj=step.obj, action=ref_act)
        diff: list[DiffEntry] = []
    else:
        s = UnresolveStep(n=0, reason=UNRESOLVE_REASON, resolution=ref_act, resolution_plan_hash=a.plan_hash,
                          reverts=tuple(reverts), reheld=tuple(reheld), rationale=UNRESOLVE_CHECKS)
        diff = sorted((DiffEntry(obj=e.obj, current=e.expect, planned_hash=e.to.hash) for e in reverts),
                      key=lambda d: d.obj)
    from .planner import default_plan_id
    return RecoveryPlan(plan_id=plan_id or default_plan_id(as_of), alert_id=p.alert_id, culprit=p.culprit,
                        t0_seq_est=p.t0_seq_est, t0_seq_est_literal=p.t0_seq_est_literal, as_of_seq=as_of,
                        taint_set=p.taint_set, steps=(s,), diff=tuple(diff)), why


def expected_reverts(records: list[Record], resolve_rec: Record, step: ResolveStep, plan_id: str,
                     before: int) -> tuple[list[RevertEntry], list[str]]:
    """Verify (ADR-05a §6.5): the reverts and re-held items an undo landing at ``before`` must carry."""
    rv, reheld, _ = _reverts(records, resolve_rec, step, plan_id, before)
    return rv, reheld
