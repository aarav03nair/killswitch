"""Revert-culprit-only baseline (ADR-06 baselines, ADR-06-metrics, CALL-02 X5; ADR-05 Consequences). Owner: vikram.

**Oracle-assisted** and labelled so: the caller passes the culprit and ``t_inject`` (the bench harness knows them;
the system planner never does, A3). This module still never reads ``RunConfig``.

Definition (ADR-06-metrics): per object, restore each object the culprit wrote at tick >= ``t_inject`` to its
pre-image; no reader repair, no conflict check, outbox untouched. "Per object" means sensitive-field objects are
their own objects (X1/B1), so on the F2+ hero the IBAN restore (``suppliers:S-17.iban``) leaves triage's edit of
the ``suppliers:S-17`` row in place (spared), while billing/payments/comms/reporter stay derived from the bad
IBAN (R > 0). "No conflict check" means a later honest write on an object the culprit wrote is overwritten: on
F2+x the baseline restores S-22 over triage's edit. :attr:`Baseline.clobbered` lists those overwrites; the system
planner turns the same situation into ``flag(write_write_conflict)``.

The output is a :class:`~ks.recovery.planner.Planned` with restore steps only, so it runs through the same
``dry_run``. ``expect`` is the current head (no conflict check); ``to`` is the pre-image version, or ``None`` when
the culprit created the object (tombstone restore).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ks.contracts import ObjVer, VersionRef
from ks.contracts.ids import SYSTEM_PRINCIPALS
from ks.contracts.record import Decision, Record
from ks.contracts.recovery import RecoveryPlan, RestoreStep, TaintSet
from ks.taint import RecordIndex

from .planner import Planned, action_ref, default_plan_id

__all__ = ["Baseline", "revert_culprit_only", "ORACLE_NOTE"]

ORACLE_NOTE = "baseline revert_culprit_only: oracle-assisted (culprit and t_inject given), per object, no reader repair, no conflict check, outbox untouched"


@dataclass(frozen=True)
class Baseline:
    planned: Planned
    clobbered: tuple[tuple[str, str, int], ...]
    """(obj, author, seq) of later writes by others that the baseline overwrites (no conflict check)."""
    oracle_assisted: bool = True
    name: str = "revert_culprit_only"


def revert_culprit_only(records: RecordIndex | Iterable[Record], *, culprit: str, t_inject: int,
                        alert_id: str = "a-000001", plan_id: str | None = None) -> Baseline:
    if culprit in SYSTEM_PRINCIPALS:
        raise ValueError("the culprit is an agent, not a system principal")
    ix = RecordIndex.of(records)
    live = [r for r in ix.records if r.decision == Decision.EXEC]
    if not live:
        raise ValueError("empty record")
    as_of = live[-1].seq
    heads: dict[str, tuple[VersionRef, Record]] = {}
    vhash: dict[tuple[str, int], str] = {}
    first: dict[str, int] = {}  # obj -> first version the culprit wrote in the window
    window: list[Record] = []
    versions: list[ObjVer] = []
    for r in live:
        mine = r.attributed_agent == culprit and r.tick >= t_inject and r.write_set
        if mine:
            window.append(r)
        for w in r.write_set:
            heads[w.obj] = (w.after, r)
            vhash[(w.obj, w.after.ver)] = w.after.hash
            if mine:
                first.setdefault(w.obj, w.after.ver)
                versions.append(ObjVer(obj=w.obj, ver=w.after.ver))
    if not window:
        raise ValueError(f"{culprit} wrote nothing at tick >= {t_inject}")
    steps: list[RestoreStep] = []
    clobbered: list[tuple[str, str, int]] = []
    for i, obj in enumerate(sorted(first)):
        head, wr = heads[obj]
        pre = first[obj] - 1
        to = None if pre < 1 else VersionRef(ver=pre, hash=vhash[(obj, pre)])
        steps.append(RestoreStep(n=i, reason="baseline_revert", obj=obj, expect=head, to=to))
        if wr.attributed_agent != culprit:
            clobbered.append((obj, wr.attributed_agent, wr.seq))
    ts = TaintSet(versions=tuple(sorted(versions, key=lambda v: (v.obj, v.ver))),
                  actions=tuple(action_ref(r) for r in window), outbox_ids=())
    plan = RecoveryPlan(plan_id=plan_id or default_plan_id(as_of), alert_id=alert_id, culprit=culprit,
                        t0_seq_est=window[0].seq, t0_seq_est_literal=None, as_of_seq=as_of, taint_set=ts,
                        steps=tuple(steps), diff=())
    planned = Planned(plan=plan, kept=(), independent=(), riders=(), rerun_records={}, notes=(ORACLE_NOTE,))
    return Baseline(planned=planned, clobbered=tuple(clobbered))
