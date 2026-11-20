"""Conflict rule at apply time (ADR-05 §6.2 and §8, M8; CALL-02 B5). Owner: vikram.

At plan time the planner turns a later **tainted** head on an object the suspect wrote into
``flag(write_write_conflict)`` with no restore (F2+x: triage edits S-22 after reading crm's version), and keeps a
later **untainted** head (an honest blind write). Between the dry-run and apply the state can still move: an
honest write lands on an object the approved plan restores or re-runs. The approved plan must not overwrite it.

:func:`recheck` is the same-txn re-check the gateway's ``ks.recover.<op>`` handler (B3-30) runs before it executes
step ``n`` of an approved plan. It returns ``None`` (go) or a :class:`~ks.recovery.dryrun.Stale` whose decision is
``hold/stale_plan`` (``Reason.STALE_PLAN``): the step is recorded as a hold and **apply halts there**. Applied steps
stay (append-only); the console builds a new plan from the longer record (a later ``as_of_seq``), in which the
honest write is either kept (untainted) or a ``flag(write_write_conflict)`` (tainted, it read the suspect's version).

Per step:

* ``restore``: ``expect`` (ver and hash) must still be the head of ``obj``;
* ``rerun`` (also ``c_rerun_identical``): no object the action wrote (landed write set, plus the dry-run's simulated
  tool writes) may carry a version written after the original action by something the plan does not account for.
  Accounted for: the original writes of the plan's other re-runs, seed versions, and this plan's own apply writes
  (``ks.recovery`` with action id ``<plan_id>.<n>``, or a re-run's original ``agent_id/action_id``, after
  ``as_of_seq``). ``outbox:*`` objects are the outbox's (dispositions, M14) and are skipped, as in the dry-run;
* ``cancel_outbox``: the item must still exist and not be dispatched (a cancelled item is a no-op, not stale);
* ``compensate``, ``replan``, ``flag``: no ``expect`` (``replan`` and ``flag`` create no envelope).

:func:`first_stale` runs :func:`recheck` over the steps in order (pre-flight, or the position an apply would halt).
A double apply is not detected here: the gateway binds each step to the approval once (B3-30).
"""

from __future__ import annotations

from typing import Any

from ks.contracts import OutboxStatus
from ks.contracts.recovery import CancelOutboxStep, RerunStep, RestoreStep

from .dryrun import DryRun, Stale
from .planner import RECOVERY_AUTHOR, _outbox_status

__all__ = ["recheck", "first_stale", "conflict_flags", "STALE_PLAN"]

STALE_PLAN = "hold/stale_plan"


def _head(store: Any, obj: str):
    h = store.history(obj)
    return h[-1] if h else None


def recheck(store: Any, dry: DryRun, step: Any) -> Stale | None:
    """M8 re-check of approved step ``step`` of ``dry.plan`` against the current ``store`` (see module doc)."""
    plan = dry.plan
    if isinstance(step, RestoreStep):
        head = _head(store, step.obj)
        if head is None or head.ver != step.expect.ver or head.hash != step.expect.hash:
            now = "absent" if head is None else f"v{head.ver} by {head.author} at seq {head.seq}"
            return Stale(n=step.n, op="restore", obj=step.obj,
                         detail=f"{step.obj}: head is {now}, plan expected v{step.expect.ver}")
        return None
    if isinstance(step, RerunStep):
        q = step.action.seq
        rec = dry.planned.rerun_records.get(q) or dry.planned.c_candidates.get(q)
        if rec is None:
            return Stale(n=step.n, op="rerun", obj="-", detail=f"seq {q} is not a re-run of plan {plan.plan_id}")
        objs = {w.obj for w in rec.write_set}
        out = dry.outcomes.get(q)
        if out is not None:
            objs |= {w.obj for w in out.tool_writes}
        reruns = [s for s in plan.steps if isinstance(s, RerunStep)]
        orig_seqs = {s.action.seq for s in reruns}
        own = {(s.action.agent_id, s.action.action_id) for s in reruns}
        seed = {(v.obj, v.ver) for v in plan.taint_set.versions}
        mine = plan.plan_id + "."
        for obj in sorted(objs):
            if obj.startswith("outbox:"):
                continue
            for e in store.history(obj):
                if e.seq <= rec.seq or e.seq in orig_seqs or (obj, e.ver) in seed:
                    continue
                if e.seq > plan.as_of_seq and ((e.author, e.action_id) in own
                                               or (e.author == RECOVERY_AUTHOR and e.action_id.startswith(mine))):
                    continue
                return Stale(n=step.n, op="rerun", obj=obj,
                             detail=f"{obj} v{e.ver} written at seq {e.seq} by {e.author} after seq {rec.seq}")
        return None
    if isinstance(step, CancelOutboxStep):
        st = _outbox_status(store, step.outbox_id)
        if st is None or st == OutboxStatus.DISPATCHED:
            return Stale(n=step.n, op="cancel_outbox", obj=f"outbox:{step.outbox_id}",
                         detail=f"outbox:{step.outbox_id} is {'missing' if st is None else st.value}")
        return None
    return None


def first_stale(store: Any, dry: DryRun) -> Stale | None:
    """The first step :func:`recheck` refuses, i.e. where an apply would halt with ``hold/stale_plan``."""
    for s in dry.plan.steps:
        bad = recheck(store, dry, s)
        if bad is not None:
            return bad
    return None


def conflict_flags(plan: Any) -> tuple:
    """The plan's ``flag(write_write_conflict)`` steps (B5): honest edits on suspect-written objects."""
    return tuple(s for s in plan.steps if s.op == "flag" and s.reason == "write_write_conflict")
