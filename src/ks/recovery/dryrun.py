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
``flag(dispatched_tainted)``. Steps are renumbered; the returned plan (and its hash) is the one to approve.

Lanes (B3): restore · re-run · kept (untainted honest writes on a touched row, e.g. triage's ``risk_note``) ·
independent (agents that wrote after t0 and are untouched). The t0 report shows ``RecoveryPlan.t0_seq_est_literal``
and ``t0_delta`` (C5 1.4). Taint follows the suspect's self-reads through ``tool`` read entries (B3-45 option C);
a non-zero delta is the residual it does not follow: suspect writes reached only through **view** self-reads,
left out of the seed. The console names them so a person can widen the seed.

Plan file: :func:`write_plan` writes ``<run>/plans/<plan_id>.json`` through ``RunDir.write_plan`` (ADR-05 §7,
CALL-02 C4). A dry-run changes nothing else in the run dir (test).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from ks.contracts import VersionRef, WriteEntry
from ks.contracts.record import Record
from ks.contracts.recovery import DiffEntry, FlagStep, RecoveryPlan, RerunStep, RestoreStep

from ks.state import StaleExpect

from .planner import Planned, Rider, apply_restore, with_diff
from .rerun import ArgsUnavailable, RerunOutcome

__all__ = ["Rerunner", "DryRun", "Stale", "StaleRerun", "StatePerturbed", "dry_run", "render", "write_plan"]


class Rerunner(Protocol):
    """B3-24 seam: re-execute ``record`` (original tool + args, M14) in the open simulation; return writes or a
    :class:`~ks.recovery.rerun.RerunOutcome`."""

    def __call__(self, store: Any, step: RerunStep, record: Record,
                 seq: int) -> Iterable[WriteEntry] | RerunOutcome: ...


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


def dry_run(store: Any, planned: Planned, *, rerunner: Rerunner | None = None,
            on_stale: Literal["raise", "halt"] = "raise") -> DryRun:
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
    stale: Stale | None = None

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
        if rerunner is not None and stale is None:
            for s in plan.steps:
                if not isinstance(s, RerunStep):
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
    diff = [DiffEntry(obj=o, current=before.get(o), planned_hash=ref.hash)
            for o, ref in sorted(after.items()) if before.get(o) != ref]
    refined = _refine(plan, outcomes, redacted, {r.action.seq for r in riders})
    return DryRun(plan=with_diff(refined, diff), planned=planned, digest_before=before_digest,
                  digest_after=after_digest, simulated_reruns=rerunner is not None, rerun_writes=rerun_writes,
                  outcomes=outcomes, stale=stale, riders=tuple(riders))


def _refine(plan: RecoveryPlan, outcomes: dict[int, RerunOutcome], redacted: list[RerunStep],
            rides: set[int]) -> RecoveryPlan:
    same = {f"outbox:{e.outbox_id}" for o in outcomes.values() for e in o.effects
            if e.disposition == "dispatched_same"}
    gone = rides | {s.action.seq for s in redacted}
    if not same and not gone:
        return plan
    keep = [s for s in plan.steps
            if not (isinstance(s, RerunStep) and s.action.seq in gone)
            and not (isinstance(s, FlagStep) and s.reason == "dispatched_tainted" and s.obj in same)]
    flags = [s for s in keep if isinstance(s, FlagStep)]
    flags += [FlagStep(n=0, reason="redacted_args", obj=None, action=s.action) for s in redacted]
    flags.sort(key=lambda f: (f.reason, f.obj or "", f.action.seq if f.action else 0))
    ordered = [s for s in keep if not isinstance(s, FlagStep)] + flags
    steps = tuple(s.model_copy(update={"n": i}) for i, s in enumerate(ordered))
    return RecoveryPlan.model_validate({**plan.to_obj(), "steps": [s.to_obj() for s in steps]})


def _v(ref: VersionRef | None) -> str:
    return "absent" if ref is None else f"v{ref.ver} {ref.hash[:12]}"


def render(d: DryRun) -> str:
    """Console text of the dry-run, one line per entry, grouped by lane. Hashes only."""
    p, pl = d.plan, d.planned
    diff = {e.obj: e for e in p.diff}
    out = [f"plan {p.plan_id}  hash {d.plan_hash[:16]}  alert {p.alert_id}  culprit {p.culprit}  "
           f"as_of_seq {p.as_of_seq}"]
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
            out.append(f"rerun        {s.action.agent_id} seq {s.action.seq} {s.action.action_id}  {tail}")
    for s in p.steps:
        if s.op == "cancel_outbox":
            out.append(f"cancel       outbox:{s.outbox_id}")
        elif s.op in ("replan", "compensate"):
            out.append(f"{s.op:<12} {s.action.agent_id} seq {s.action.seq}")
        elif s.op == "flag":
            who = f" {s.action.agent_id} seq {s.action.seq}" if s.action else ""
            out.append(f"flag         {s.reason} {s.obj or '-'}{who}")
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
    out.extend(f"note         {n}" for n in pl.notes)
    return "\n".join(out) + "\n"


def write_plan(plan: RecoveryPlan, rundir: Any) -> Path:
    """Write ``<run>/plans/<plan_id>.json`` (canonical bytes, 0600) through the run dir's own ``write_plan``
    (C6 ``RunDir.write_plan``; ADR-05 §7, CALL-02 C4: ``plans/**`` is a deterministic file). ``rundir`` is
    duck-typed so this package never imports the run-dir module (A3 guard: it would expose ``RunConfig``)."""
    return Path(rundir.write_plan(plan))
