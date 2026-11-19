"""Detect, then attribute (ADR-04 section 2-3). Detectors never name anyone; this module does, with humility.

* ``root_candidates[0]`` is the attributed writer of ``evidence_versions`` (write_set lookup, exec records).
* A bounded backward walk over *recorded* read sets (which include ``TickFrame.view`` entries) then ranks the
  agents that wrote what the writer read. Agent-declared lineage and ``act_chain`` are never used (D8).
* Read-reached agents are never auto-suspended; two or more distinct writers, or none, suspend nobody.
"""

from __future__ import annotations

from collections.abc import Sequence

from ks.contracts import (HARD_ALLOWED, Alert, AlertKind, ObjVer, Record, TargetKind, make_target)

from .model import Finding, MonitorParams, RecordIndex, agent_of

__all__ = ["writers_of", "attribute", "suspect", "containment_target"]

AUTO_SUSPEND_KINDS = frozenset({AlertKind.INVARIANT, AlertKind.SCOPE})
"""D7: SCOPE and I-class INVARIANT auto-suspend the attributed writer. RECONCILE suspends nobody, SIGNATURE only
a connection, ANOMALY/RATE alert only, TAMPER/WITNESS_STALL freeze by kind."""


def writers_of(index: RecordIndex, versions: Sequence[ObjVer]) -> list[str]:
    """Distinct attributed agents that wrote ``versions``, first seen first. A version with no exec writer record,
    or a non-agent writer (``ks.recovery``), contributes nothing."""
    out: list[str] = []
    for v in versions:
        rec = index.writer(v.obj, v.ver)
        a = agent_of(rec) if rec is not None else None
        if a is not None and a not in out:
            out.append(a)
    return out


def attribute(index: RecordIndex, finding: Finding, params: MonitorParams) -> tuple[str, ...]:
    """Ranked ``root_candidates`` for a finding."""
    if not finding.evidence_versions:
        return tuple(finding.hint_agents)
    cands = writers_of(index, finding.evidence_versions)
    frontier = [r for v in finding.evidence_versions if (r := index.writer(v.obj, v.ver)) is not None]
    seen = {r.seq for r in frontier}
    nodes = 0
    for _ in range(params.walk_depth):
        found: dict[int, Record] = {}
        for rec in frontier:
            for e in rec.read_set:
                src = index.writer(e.obj, e.ver)
                if src is None or src.seq in seen or src.seq >= rec.seq or src.seq in found:
                    continue
                nodes += 1
                if nodes > params.walk_nodes:
                    return tuple(cands[:params.max_candidates])
                found[src.seq] = src
        seen.update(found)
        nxt = sorted(found.values(), key=lambda r: -r.seq)  # within a depth the most recent writer ranks first
        for src in nxt:
            a = agent_of(src)
            if a is not None and a not in cands:
                cands.append(a)
        if not nxt or len(cands) >= params.max_candidates:
            break
        frontier = nxt
    return tuple(cands[:params.max_candidates])


def suspect(alert: Alert, index: RecordIndex) -> str | None:
    """The agent containment may auto-suspend, or ``None``. Derived on demand, never stored.

    Needs a hard alert of kind INVARIANT or SCOPE, and (re-derived from the records, not trusted from the
    alert) exactly one distinct attributed writer of the evidence who is ``root_candidates[0]``."""
    if not alert.hard or alert.kind not in HARD_ALLOWED or alert.kind not in AUTO_SUSPEND_KINDS:
        return None
    if not alert.root_candidates:
        return None
    if alert.evidence_versions:
        writers = writers_of(index, alert.evidence_versions)
    else:  # SCOPE: the evidence is the denied record itself
        writers = []
        for s in alert.evidence_seqs:
            rec = index.by_seq(s)
            a = agent_of(rec) if rec is not None else None
            if a is not None and a not in writers:
                writers.append(a)
    return writers[0] if len(writers) == 1 and writers[0] == alert.root_candidates[0] else None


def containment_target(alert: Alert, index: RecordIndex) -> str | None:
    """``agent:<id>`` for an auto-suspend, ``conn:<id>`` for a signature alert, else ``None``."""
    if alert.kind == AlertKind.SIGNATURE and alert.hard and alert.conn_id:
        return make_target(TargetKind.CONN, alert.conn_id)
    s = suspect(alert, index)
    return make_target(TargetKind.AGENT, s) if s else None
