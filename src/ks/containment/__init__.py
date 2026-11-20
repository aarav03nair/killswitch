"""ks.containment: monitor alert -> signed, recorded suspend on c-0 (ADR-04 §3-§6, B3-19). Owner: nisha.

``Containment.respond`` takes the monitor's alerts for the tick that just ran and, still inside that tick and before
the next ``Gateway.open``, admits on c-0: one ``ks.alert`` record per alert (``ks.monitor``, chained) and, for a *hard*
alert whose containment target is decided by ``ks.monitor.containment_target`` (H1/H2: ``root_candidates[0]`` for
scope and invariant alerts, the connection for signature alerts, nobody for reconcile/tamper/stall), one
``ks.control suspend`` record (auto=True, ``alert_id`` set, fresh strictly higher epoch). From that record's seq on
the epoch fold says suspended, so the next admission by that agent is ``deny/suspended`` (RT5: the step-13 re-read).
Release and revoke are operator actions (``ks.runtime.operator``); release gives a fresh epoch above the suspend, so
an envelope presigned at the old epoch is ``stale_epoch``. Hold/unhold live in ``ks.gateway.holds``.

Everything here reads and writes records only: :func:`contain_times` recomputes time-to-contain from a run directory
with no side channel (what ``ks.score`` also does).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ks.contracts import (CONTROL_TOOL, Alert, Control, ControlOp, Decision, Record, TargetKind, parse_target,
                          sidestore_relpath)
from ks.gateway.system import system_envelope
from ks.monitor import Context, Monitor, MonitorParams, alert_envelope, containment_target

if TYPE_CHECKING:
    from ks.gateway import Admission, Gateway

__all__ = ["Containment", "MonitorLoop", "ContainTime", "contain_times", "writes_after"]


class Containment:
    """Turns alerts into c-0 records. ``sign`` signs as ``ks.monitor``."""

    def __init__(self, sign: Callable[[bytes], str]):
        self._sign = sign
        self.suspended: set[str] = set()  # targets this object already suspended (no duplicate bump)

    def respond(self, gw: Gateway, alerts: Iterable[Alert], index) -> list[Admission]:
        out = []
        for alert in alerts:
            out.append(gw.admit_system(alert_envelope(alert, self._sign, tick=gw._tick)))
            if not alert.hard:
                continue
            target = containment_target(alert, index)
            if target is None or target in self.suspended or self._already(gw, target):
                continue
            self.suspended.add(target)
            seq = gw.recorder.seq + 1
            kind, ident = parse_target(target)
            epoch = gw.control.next_epoch(ident) if kind == TargetKind.AGENT else None
            ctl = Control(control_id=f"k-{seq:06d}", op=ControlOp.SUSPEND, target=target, epoch=epoch,
                          alert_id=alert.alert_id, issued_by="ks.monitor", auto=True,
                          reason="bad_sig" if kind == TargetKind.CONN else "hard_alert")
            env = system_envelope("ks.monitor", CONTROL_TOOL, ctl.to_obj(), action_id=f"mon-{alert.alert_id}-suspend",
                                  tick=gw._tick, sign=self._sign)
            out.append(gw.admit_system(env))
        return out

    @staticmethod
    def _already(gw: Gateway, target: str) -> bool:
        kind, ident = parse_target(target)
        if kind == TargetKind.AGENT:
            return gw.control.agent_denial(ident) is not None
        return gw.control.conn_denial(ident) is not None


class MonitorLoop:
    """Between ticks: scan the records, then contain. One instance per run (the Monitor dedupes by finding)."""

    def __init__(self, gw: Gateway, sign: Callable[[bytes], str], *, state: Any, side: Any,
                 params: MonitorParams | None = None, monitor: Monitor | None = None):
        self.gw, self.state, self.side = gw, state, side
        self.params = params or MonitorParams()
        self.monitor = monitor or Monitor()
        self.containment = Containment(sign)
        self.alerts: list[Alert] = []
        self._seen_seq = 0

    def step(self) -> list[Admission]:
        rec = self.gw.recorder
        if rec.seq == self._seen_seq:
            return []
        records = list(rec.rundir.records())
        ctx = Context(records=records, state=self.state, side=self.side, params=self.params, witness=list(rec.rundir.witness()),
                      memory_head=(rec.seq, rec.head))
        alerts = self.monitor.scan(ctx)
        adms = self.containment.respond(self.gw, alerts, ctx.index) if alerts else []
        self.alerts += alerts
        self._seen_seq = self.gw.recorder.seq  # our own c-0 records are not rescanned as news
        return adms


# --- measurement from records ----------------------------------------------------------------------------------
@dataclass(frozen=True)
class ContainTime:
    target: str
    alert_id: str | None
    alert_tick: int | None
    alert_seq: int | None
    contain_tick: int
    contain_seq: int

    @property
    def ticks(self) -> int | None:
        return None if self.alert_tick is None else self.contain_tick - self.alert_tick


def contain_times(run: str | Path) -> list[ContainTime]:
    """One entry per executed ``ks.control suspend`` record: the alert it cites (the chained ``ks.alert`` record whose
    result carries that alert id) and how many ticks / records later the suspend landed. Records only."""
    run = Path(run)
    recs = [Record.from_obj(json.loads(x)) for x in (run / "record.jsonl").read_text().splitlines() if x]
    alerts: dict[str, Record] = {}
    for r in recs:
        if r.envelope and r.envelope.tool == "ks.alert" and r.decision == Decision.EXEC and r.sig_ok \
                and r.envelope.agent_id == "ks.monitor":
            body = _side(run, r.envelope.args_hash)
            if isinstance(body, dict) and "alert_id" in body:
                alerts.setdefault(body["alert_id"], r)
    out = []
    for r in recs:
        c = r.control
        if c is not None and r.decision == Decision.EXEC and c.op == ControlOp.SUSPEND:
            a = alerts.get(c.alert_id) if c.alert_id else None
            out.append(ContainTime(c.target, c.alert_id, a.tick if a else None, a.seq if a else None, r.tick, r.seq))
    return out


def writes_after(records: Iterable[Record], agent: str, seq: int) -> list[Record]:
    """Executed records of ``agent`` after ``seq`` that wrote state or queued an outbox item (must be empty once
    ``seq`` is the quarantine seq)."""
    return [r for r in records if r.seq > seq and r.decision == Decision.EXEC and r.attributed_agent == agent
            and (r.write_set or r.outbox_ids)]


def _side(run: Path, h: str) -> Any:
    p = run / sidestore_relpath(h)
    return json.loads(p.read_bytes()).get("value") if p.exists() else None
