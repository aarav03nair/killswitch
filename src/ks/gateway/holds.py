"""Control ``hold`` / ``unhold`` on c-0 (ADR-04 §5, CALL-02 F9, contracts M10). Owner: nisha (B3-19).

Served from :func:`ks.gateway.system.admit_system` once signature, expiry, nonce and scope (steps 3, 5, 6, 10) passed.

* ``hold outbox:<id>``: a QUEUED item becomes HELD by a recorded Control whose write_set is the item's status change.
* ``unhold outbox:<id>``: a HELD item returns to QUEUED (same shape). Nothing is dispatched here: the next release phase
  re-checks provenance, taint and the sensitive-field window and either dispatches or holds it again.
* ``unhold action:<hold record id>``: re-executes the held envelope once. The gateway first checks, without recording
  anything, that the re-execution would not be denied (hold record valid and not yet cited by any ``reexec_of``,
  connection and agent not denied, epoch still current, class not U, policy not a deny and not a *different* hold).
  If a check fails the Control itself is denied ``tool_error`` and the hold stays open. If they pass, the Control is
  recorded, then the held envelope runs through the normal txn (control re-read at step 13) and its record carries
  ``reexec_of`` = the hold record's seq. Nonce and expiry are not re-checked (M10). A policy hold with the same reason
  is exactly what the unhold approves; the taint of the re-executed read set is not re-checked here (the world policy
  holds by approval class, not by taint; lineage holds are outbox items).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING

from ks.contracts import (ActionClass, Control, ControlOp, Decision, Envelope, OutboxStatus, Reason, SideDomain,
                          SideEntry, TargetKind, canonical, parse_target, result_hash, sidestore_relpath)
from ks.contracts import SYSTEM_CONN

if TYPE_CHECKING:
    from .stub import Admission, Gateway

__all__ = ["serve_hold_control", "HoldRefused"]

MANUAL_UNHOLD = {"ks.operator", "ks.recovery"}


class HoldRefused(ValueError):
    """The hold/unhold cannot apply now (recorded as a ``tool_error`` deny of the Control; nothing else changes)."""


def serve_hold_control(gw: Gateway, env: Envelope, header, ehash: str,
                       deny: Callable[..., Admission]) -> Admission:
    try:
        ctl = Control.model_validate_json(canonical.dumps(env.args))
        if ctl.issued_by != env.agent_id:
            raise ValueError("issued_by")
        kind, ident = parse_target(ctl.target)
        if ctl.op == ControlOp.UNHOLD and kind == TargetKind.ACTION and ctl.auto:
            raise HoldRefused("an action is only unheld by a human (ks.operator) or ks.recovery")
        plan = _outbox_plan(gw, ctl, ident) if kind == TargetKind.OUTBOX else _reexec_plan(gw, ident)
    except Exception:
        return deny(Reason.TOOL_ERROR)
    result = {"control_id": ctl.control_id, "op": ctl.op.value, "target": ctl.target, "epoch": ctl.epoch}
    rh = result_hash(result)
    gw.recorder.put_side(SideDomain.RESULT, rh, result)
    if kind == TargetKind.OUTBOX:
        return _record_outbox(gw, env, header, ehash, ctl, plan, result, rh)
    adm = gw._done(SYSTEM_CONN, header, ehash, True, Decision.EXEC, Reason.OK, ActionClass.R, result=result,
                   result_hash=rh, rtxn=gw.recorder.begin(), control=ctl)
    hold, renv, conn_id, cls = plan
    gw._execute(conn_id, renv, renv.header(), hold.envelope_hash, cls, reexec_of=hold.seq)
    return adm


# --- outbox ---------------------------------------------------------------------------------------------------
def _outbox_plan(gw: Gateway, ctl: Control, oid: str):
    if gw.outbox is None:
        raise HoldRefused("no outbox in this gateway")
    d = gw.outbox.get(oid)
    want = OutboxStatus.QUEUED if ctl.op == ControlOp.HOLD else OutboxStatus.HELD
    if d.item.status != want:
        raise HoldRefused(f"{oid} is {d.item.status}, not {want}")
    return d


def _record_outbox(gw: Gateway, env, header, ehash, ctl: Control, d, result, rh) -> Admission:
    new = OutboxStatus.HELD if ctl.op == ControlOp.HOLD else OutboxStatus.QUEUED
    store = gw.store
    rtxn = gw.recorder.begin()
    try:
        store.conn.execute("BEGIN IMMEDIATE")
        w = gw.outbox.set_status(d, new, seq=rtxn.seq, author=env.agent_id, action_id=env.action_id)
        store.conn.execute("COMMIT")
    except BaseException:
        if store.conn.in_transaction:
            store.conn.execute("ROLLBACK")
        rtxn.rollback()
        raise
    reads = tuple(sorted((*d.item.lineage, d.read_entry()), key=lambda e: (e.obj, e.ver)))
    return gw._done(SYSTEM_CONN, header, ehash, True, Decision.EXEC, Reason.OK, ActionClass.R, result=result,
                    result_hash=rh, read_set=reads, write_set=(w,), rtxn=rtxn, control=ctl)


# --- action re-execution (F9) -----------------------------------------------------------------------------------
def _reexec_plan(gw: Gateway, record_id: str):
    seq = int(record_id[2:])
    hold = gw._record_at(seq)
    if hold is None or hold.record_id != record_id or hold.decision != Decision.HOLD or hold.envelope is None \
            or not hold.sig_ok or hold.conn_id == SYSTEM_CONN or hold.reexec_of is not None:
        raise HoldRefused(f"{record_id} is not a held agent envelope")
    if any(r.reexec_of == seq for r in gw.recorder.rundir.records()):
        raise HoldRefused(f"{record_id} was already re-executed (F9: once)")
    entry = SideEntry.from_obj(json.loads((gw.recorder.rundir.path / sidestore_relpath(hold.envelope.args_hash))
                                          .read_bytes()))
    if entry.redacted or not isinstance(entry.value, dict):
        raise HoldRefused("the held arguments are not readable")
    d = hold.envelope.to_obj()
    d.pop("args_hash")
    env = Envelope.model_validate({**d, "contract": Envelope.CONTRACT, "args": entry.value})
    if env.content_hash() != hold.envelope_hash:
        raise HoldRefused("rebuilt envelope does not match the held envelope hash")
    why = gw._control_denial(env, hold.conn_id)  # 7-9 against the CURRENT state (stale epoch after a release)
    if why is not None:
        raise HoldRefused(str(why))
    cls = gw._classify(env)
    if cls == ActionClass.U:
        raise HoldRefused("class U")
    verdict = gw.policy.decide(env, cls)
    if verdict is not None and not (verdict.decision == Decision.HOLD and verdict.reason == hold.reason):
        raise HoldRefused(f"policy now says {verdict.decision}/{verdict.reason}")
    return hold, env, hold.conn_id, cls
