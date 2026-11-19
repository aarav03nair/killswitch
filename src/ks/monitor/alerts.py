"""Findings -> validated C4 Alerts, and Alert -> ``ks.alert`` envelope (F6)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable

from ks.contracts import (DETECTOR_KIND, HARD_DETECTORS, MAX_EXPIRY_TICKS, Alert, AlertKind, Envelope)

from .attribute import attribute
from .detectors import DETECTORS
from .model import Context, Finding

__all__ = ["make_alert", "alert_envelope", "Monitor", "ALERT_TOOL"]

ALERT_TOOL = "ks.alert"


def make_alert(ctx: Context, finding: Finding, alert_id: str) -> Alert:
    """Build the Alert for ``finding``. ``kind`` and ``hard`` come from the C4 tables, never from here; the
    ``Alert`` validator rejects anything inconsistent."""
    kind = DETECTOR_KIND[finding.detector]
    nobody = kind in (AlertKind.RECONCILE, AlertKind.TAMPER, AlertKind.WITNESS_STALL, AlertKind.SIGNATURE) \
        or finding.detector == "barrier.deadline"
    roots = () if nobody else attribute(ctx.index, finding, ctx.params)
    return Alert(alert_id=alert_id, tick=ctx.index.last_tick, seq=ctx.index.last_seq, detector=finding.detector,
                 kind=kind, hard=finding.detector in HARD_DETECTORS, evidence_seqs=finding.evidence_seqs,
                 evidence_versions=finding.evidence_versions, root_candidates=roots, conn_id=finding.conn_id)


def alert_envelope(alert: Alert, sign: Callable[[bytes], str], *, tick: int | None = None) -> Envelope:
    """The ``ks.alert`` envelope the monitor submits on c-0: ``args = alert.to_obj()``. ``sign`` signs the
    envelope signing bytes as ``ks.monitor``. Nonce and action id derive from the alert id (deterministic)."""
    t = alert.tick if tick is None else tick
    nonce = hashlib.sha256(b"ks.monitor/alert-nonce:" + alert.alert_id.encode()).hexdigest()[:32]
    env = Envelope(agent_id="ks.monitor", action_id=f"mon-{alert.alert_id}", parent_action_id=None, act_chain=(),
                   tool=ALERT_TOOL, args=alert.to_obj(), nonce=nonce, expiry_tick=t + MAX_EXPIRY_TICKS, epoch=0,
                   claimed_ts_us=None, claimed_seq=None, sig=None)
    return env.with_sig(sign(env.signing_bytes()))


class Monitor:
    """Runs the catalogue over a context and numbers new alerts ``a-000001`` upward; a finding already
    alerted (same key) is not alerted again."""

    def __init__(self, detectors: Iterable[str] | None = None, first_id: int = 1):
        self.detectors = list(DETECTORS if detectors is None else detectors)
        self._next = first_id
        self._seen: set[tuple] = set()

    def scan(self, ctx: Context) -> list[Alert]:
        out: list[Alert] = []
        for name in self.detectors:
            for f in DETECTORS[name](ctx):
                if f.key in self._seen:
                    continue
                self._seen.add(f.key)
                out.append(make_alert(ctx, f, f"a-{self._next:06d}"))
                self._next += 1
        return out
