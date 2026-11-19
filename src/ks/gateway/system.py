"""System envelopes on ``c-0`` (B3-13, CALL-02 E1/E3/G1, ADR-00 tick step 1). Owner: maya.

In-gateway system principals (``ks.monitor``, ``ks.operator``, ``ks.recovery``, ``ks.gateway``) submit signed
envelopes here; the gateway verifies each signature against the keyring like any other envelope and records it
on ``SYSTEM_CONN`` (rule 11: denials included). Nothing outside the gateway process reaches this path: the operator
reaches it only through the J1 peercred socket (``ks.runtime.operator``), which turns requests into
``ks.operator``-signed envelopes.

Admission order (the system subset of ADR-03 §1): agent id on c-0 is a ``SystemEnvelopeError`` (never recorded:
c-0 carries system envelopes only, a Record validator) · 3 signature on c-0 · 5 expiry · 6 nonce/(principal,
action) · 10 scope inverted (the principal must be a signer of the tool, ``system_tool_signers``) · execute
(handler ``check``) · record · handler ``apply``. Steps 4 (frame tick), 7-9 (agent control state), 11 (class) and
12 (policy) are agent-frame steps and do not apply. Served tools: ``ks.alert``, ``ks.approve`` and agent/conn
``ks.control`` (suspend, release, revoke). ``ks.seed`` and ``ks.dispatch`` keep their gateway-internal paths;
``ks.recover.<op>`` (B3-30) and Control hold/unhold (B3-19) raise ``NotImplementedError`` before anything is
recorded.

:class:`SystemQueue` is the control phase (ADR-00 step 1): queued requests are admitted at the next
``Gateway.open`` in (principal, queue) order, at most :data:`CONTROL_PHASE_CAP` per tick, surplus carried over in
order. Request envelopes are built and signed at admission time (expiry = that tick, action id and nonce derived
from the seq), so they are a pure function of the request and the tick.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ks.contracts import (APPROVE_TOOL, CONTROL_TOOL, RECOVER_TOOL_PREFIX, SEED_TOOL, SYSTEM_CONN, SYSTEM_PRINCIPALS,
                          ActionClass, Alert, Approval, Control, Decision, Envelope, Reason, SideDomain, expiry_ok,
                          canonical, result_hash, system_tool_signers)

if TYPE_CHECKING:
    from .stub import Admission, Gateway

__all__ = ["SystemEnvelopeError", "SystemRequest", "SystemQueue", "admit_system", "system_envelope",
           "CONTROL_PHASE_CAP", "ALERT_TOOL", "SERVED_TOOLS"]

CONTROL_PHASE_CAP = 32
"""ADR-00 C7: at most 32 queued system envelopes per control phase."""
ALERT_TOOL = "ks.alert"
SERVED_TOOLS = frozenset({ALERT_TOOL, APPROVE_TOOL, CONTROL_TOOL})
SUBMITTERS = SYSTEM_PRINCIPALS - {"ks.witness"}
"""The witness signs checkpoints, never envelopes."""


class SystemEnvelopeError(ValueError):
    """A frame that must never reach c-0 (an agent id, the witness, a gateway-internal tool). Not recorded."""


def system_envelope(principal: str, tool: str, args: Any, *, action_id: str, tick: int,
                    sign: Callable[[bytes], str]) -> Envelope:
    """A signed system envelope: expiry = ``tick``, epoch 0, nonce derived from (principal, action_id)."""
    nonce = hashlib.sha256(f"ks/system-nonce/{principal}/{action_id}".encode()).hexdigest()[:32]
    env = Envelope(agent_id=principal, action_id=action_id, parent_action_id=None, act_chain=(), tool=tool,
                   args=args, nonce=nonce, expiry_tick=tick, epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)
    return env.with_sig(sign(env.signing_bytes()))


def _parse(env: Envelope) -> tuple[Any, dict]:
    """Validate ``env.args`` for its tool -> (payload, result). Raises on bad args (recorded as tool_error)."""
    raw = canonical.dumps(env.args)  # JSON mode: arrays are tuples, exactly as a record reader parses them
    if env.tool == ALERT_TOOL:
        a = Alert.model_validate_json(raw)
        return a, {"alert_id": a.alert_id}
    if env.tool == APPROVE_TOOL:
        ap = Approval.model_validate_json(raw)
        return ap, {"plan_id": ap.plan_id, "plan_hash": ap.plan_hash}
    c = Control.model_validate_json(raw)
    if c.issued_by != env.agent_id:
        raise ValueError("control.issued_by must equal the signing principal (K15)")
    return c, {"control_id": c.control_id, "op": c.op.value, "target": c.target, "epoch": c.epoch}


def admit_system(gw: Gateway, env: Envelope) -> Admission:
    """Admit one system envelope on c-0 in the gateway's current tick. Returns the Admission (record + reply)."""
    from .stub import Admission  # local: stub imports this module

    if env.agent_id not in SYSTEM_PRINCIPALS:
        raise SystemEnvelopeError(f"c-0 carries system envelopes only, not {env.agent_id!r} (E1)")
    if env.agent_id not in SUBMITTERS:
        raise SystemEnvelopeError("ks.witness never submits envelopes")
    if env.tool in (SEED_TOOL, "ks.dispatch"):
        raise SystemEnvelopeError(f"{env.tool} is gateway-internal (seed record / release phase)")
    if env.tool.startswith(RECOVER_TOOL_PREFIX):
        raise NotImplementedError("ks.recover.<op> is served by recovery apply (B3-30)")
    if env.tool == CONTROL_TOOL and isinstance(env.args, dict) and env.args.get("op") in ("hold", "unhold"):
        raise NotImplementedError("Control hold/unhold is served by containment/outbox (B3-19, B3-23)")

    header = env.header()
    ehash = env.content_hash()
    gw.recorder.put_side(SideDomain.ARGS, header.args_hash, env.args)
    cls = ActionClass.R  # system records have no external effect (G1 "system" row); R as the seed record

    def deny(reason: Reason, sig_ok: bool = True, rtxn=None) -> Admission:
        return gw._done(SYSTEM_CONN, header, ehash, sig_ok, Decision.DENY, reason, cls, rtxn=rtxn)

    if not gw._sig_ok(SYSTEM_CONN, header):  # 3: verified against the keyring like every envelope
        return deny(Reason.BAD_SIG, sig_ok=False)
    if not expiry_ok(env.expiry_tick, gw._tick):  # 5
        return deny(Reason.EXPIRED)
    nk, ak = (env.agent_id, env.nonce), (env.agent_id, env.action_id)
    if nk in gw._nonces or ak in gw._actions:  # 6
        return deny(Reason.NONCE_REUSED)
    gw._nonces[nk] = gw._tick
    gw._actions.add(ak)
    if env.agent_id not in system_tool_signers(env.tool) or env.tool not in SERVED_TOOLS:  # 10
        return deny(Reason.OUT_OF_SCOPE)
    rtxn = gw.recorder.begin()
    try:
        try:
            payload, result = _parse(env)
            if isinstance(payload, Control):
                check = getattr(gw.control, "check", None)
                if check is None:
                    raise TypeError("this gateway's ControlView does not fold Controls")
                check(payload)
            rh = result_hash(result)
        except NotImplementedError:
            raise
        except Exception:
            return deny(Reason.TOOL_ERROR, rtxn=rtxn)  # rule 11; the exception text is not recorded
        gw.recorder.put_side(SideDomain.RESULT, rh, result)
    except BaseException:
        rtxn.rollback()
        raise
    adm = gw._done(SYSTEM_CONN, header, ehash, True, Decision.EXEC, Reason.OK, cls, result=result, result_hash=rh,
                   rtxn=rtxn, control=payload if isinstance(payload, Control) else None)
    if isinstance(payload, Control):
        gw.control.apply(payload)  # after the record: control state never runs ahead of the chain
    return adm


Builder = Callable[["Gateway", int, int], Any]
"""(gateway, tick, seq the record will take) -> args. Runs in the control phase, on the gateway thread."""


@dataclass
class SystemRequest:
    """One queued system submission. ``build`` makes the args at admission time; ``done`` gets the Admission
    (or the exception) once it was admitted or refused. ``envelope`` instead carries a pre-signed envelope (e.g.
    ``ks.monitor.alert_envelope``)."""

    principal: str
    tool: str
    build: Builder | None = None
    envelope: Envelope | None = None
    done: Callable[[Any], None] | None = None
    _n: int = field(default=0, repr=False)


class SystemQueue:
    """Thread-safe control-phase queue (the operator socket thread puts, the gateway thread drains)."""

    def __init__(self, signers: Mapping[str, Callable[[bytes], str]], cap: int = CONTROL_PHASE_CAP):
        bad = set(signers) - SUBMITTERS
        if bad:
            raise ValueError(f"not system submitters: {sorted(bad)}")
        self._signers = dict(signers)
        self.cap = cap
        self._lock = threading.Lock()
        self._items: list[SystemRequest] = []
        self._n = 0

    def put(self, req: SystemRequest) -> None:
        if req.principal not in self._signers:
            raise ValueError(f"no signer for {req.principal}")
        if (req.build is None) == (req.envelope is None):
            raise ValueError("pass exactly one of build and envelope")
        if req.envelope is not None and req.envelope.agent_id != req.principal:
            raise ValueError("envelope principal differs from the request")
        with self._lock:
            self._n += 1
            req._n = self._n
            self._items.append(req)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def take(self) -> list[SystemRequest]:
        """This phase's batch: up to ``cap`` items in (principal, queue) order; the rest stay queued in order."""
        with self._lock:
            order = sorted(self._items, key=lambda r: (r.principal, r._n))
            batch = order[: self.cap]
            ids = {id(r) for r in batch}
            self._items = [r for r in self._items if id(r) not in ids]
        return batch

    def control_phase(self, gw: Gateway, tick: int) -> list[Admission]:
        out = []
        for req in self.take():
            try:
                env = req.envelope
                if env is None:
                    seq = gw.recorder.seq + 1
                    args = req.build(gw, tick, seq)
                    env = system_envelope(req.principal, req.tool, args, action_id=f"{req.principal[3:]}-{seq:06d}",
                                          tick=tick, sign=self._signers[req.principal])
                adm = admit_system(gw, env)
            except Exception as e:  # refused before a record (bad request / not served): tell the requester
                if req.done is not None:
                    req.done(e)
                continue
            out.append(adm)
            if req.done is not None:
                req.done(adm)
        return out

    def fail_all(self, why: str) -> None:
        """Teardown: every still-queued request learns it was never admitted."""
        with self._lock:
            items, self._items = self._items, []
        for r in items:
            if r.done is not None:
                r.done(RuntimeError(why))
