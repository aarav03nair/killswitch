"""Snapshot baseline (ADR-06-metrics §4). Owner: tara. Oracle-assisted (``t_inject`` given), labelled so in score.json.

Snapshot: restore every non-outbox object written at tick >= ``t_inject`` (by anyone) to its pre-image, cancel every
item still held in the outbox, re-execute nothing. Same dry-run, same apply path as the system plan; only the plan
differs. The revert-culprit-only baseline is ``ks.recovery.revert_culprit_only`` (vikram)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ks.contracts import VersionRef
from ks.contracts.record import Decision, Record
from ks.contracts.recovery import CancelOutboxStep, RecoveryPlan, RestoreStep, TaintSet
from ks.recovery.planner import Planned, default_plan_id
from ks.taint import RecordIndex

__all__ = ["snapshot_plan", "SNAPSHOT_NOTE"]

SNAPSHOT_NOTE = "baseline snapshot: oracle-assisted (t_inject given): restore to t_inject-1, cancel held items, no re-execution"


def snapshot_plan(records: RecordIndex | Iterable[Record], held_outbox: Iterable[str], *, t_inject: int,
                  alert_id: str = "a-000001", culprit: str = "crm") -> Planned:
    ix = RecordIndex.of(records)
    live = [r for r in ix.records if r.decision == Decision.EXEC]
    if not live:
        raise ValueError("empty record")
    heads: dict[str, VersionRef] = {}
    vhash: dict[tuple[str, int], str] = {}
    first: dict[str, int] = {}
    seqs = []
    for r in live:
        for w in r.write_set:
            heads[w.obj] = w.after
            vhash[(w.obj, w.after.ver)] = w.after.hash
            if r.tick >= t_inject and not w.obj.startswith("outbox:"):
                first.setdefault(w.obj, w.after.ver)
                seqs.append(r.seq)
    steps: list[Any] = []
    for obj in sorted(first):
        pre = first[obj] - 1
        to = None if pre < 1 else VersionRef(ver=pre, hash=vhash[(obj, pre)])
        steps.append(RestoreStep(n=len(steps), reason="baseline_snapshot", obj=obj, expect=heads[obj], to=to))
    for oid in sorted(held_outbox):
        steps.append(CancelOutboxStep(n=len(steps), reason="baseline_snapshot", outbox_id=oid))
    as_of = live[-1].seq
    plan = RecoveryPlan(plan_id=default_plan_id(as_of), alert_id=alert_id, culprit=culprit,
                        t0_seq_est=min(seqs) if seqs else as_of, t0_seq_est_literal=None, as_of_seq=as_of,
                        taint_set=TaintSet(versions=(), actions=(), outbox_ids=()), steps=tuple(steps), diff=())
    return Planned(plan=plan, kept=(), independent=(), riders=(), rerun_records={}, notes=(SNAPSHOT_NOTE,))
