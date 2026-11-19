"""Gateway stub (SKEL-01): admission of one frame per connection per tick, in ADR-01 §8 order, then a record.

    decode -> schema -> signature -> tick tag (late_frame) -> expiry -> nonce/(agent, action) -> epoch
           -> ks.* scope -> class -> execute (ToolDispatcher) -> Record

Seams (B3-37): the barrier (ks.runtime) calls only ``open(tick, agents)`` and ``tick(tick, frames)``; everything
between (control, view, admission, dispatch, later monitor and outbox) lives behind them. Tools are not known
here: ``ToolDispatcher`` (``ks.gateway.dispatch``) classifies and executes them; ks.world implements it. No state,
policy, monitor or outbox yet (Sprint 3, nisha/vikram). A tool the dispatcher does not know is class U and denied
(rule 6).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from ks.contracts import (SYSTEM_CONN, SYSTEM_PRINCIPALS, ActionClass, CanonicalError, Decision, EnvelopeHeader,
                          Keyring, NoopFrame, Reason, Record, ReplyFrame, RunConfig, SideDomain, SubmitFrame,
                          TickFrame, decode_frame, expiry_ok, raw_hash, result_hash)
from ks.identity import verify_hex
from ks.recorder import Recorder

from .dispatch import ToolDispatcher

__all__ = ["Admission", "Gateway", "InFrame"]


@dataclass(frozen=True)
class InFrame:
    """One raw frame the barrier collected this tick: bytes incl. LF, or an oversize prefix."""

    agent_id: str
    conn_id: str
    line: bytes


@dataclass(frozen=True)
class Admission:
    """Outcome of one frame: a record (``None`` for a no-op) and the reply owed to the connection."""

    record: Record | None
    reply: ReplyFrame | None


class Gateway:
    """Admits frames and records every envelope it receives, denials included (rule 11)."""

    def __init__(self, config: RunConfig, keyring: Keyring, recorder: Recorder,
                 epoch_of: Callable[[str], int | None], *, dispatcher: ToolDispatcher):
        self.config = config.tcb_view()  # A3: the TCB never sees fault/culprit/fault_tick
        self.keyring = keyring
        self.recorder = recorder
        self._epoch_of = epoch_of
        self.dispatcher = dispatcher
        self._nonces: set[tuple[str, str]] = set()
        self._actions: set[tuple[str, str]] = set()
        self._tick = 0
        self._slot = 0

    def begin_tick(self, tick: int) -> None:
        self._tick, self._slot = tick, 0

    # --- barrier seam (B3-37) --------------------------------------------------------------------
    def open(self, tick: int, agents: Iterable[str]) -> dict[str, TickFrame]:
        """Start ``tick`` and return the TickFrame owed to each agent (epoch from control, view later)."""
        self.begin_tick(tick)
        return {a: TickFrame(tick=tick, epoch=self._epoch_of(a), view=()) for a in agents}

    def tick(self, tick: int, frames: Sequence[InFrame]) -> list[tuple[str, ReplyFrame]]:
        """Admit this tick's frames in agent_id order (arrival order is discarded); replies as (conn_id, reply)."""
        if tick != self._tick:
            raise ValueError(f"tick {tick} was not opened (current {self._tick})")
        replies = []
        for f in sorted(frames, key=lambda f: f.agent_id):
            adm = self.admit(f.conn_id, f.line)
            if adm.reply is not None:
                replies.append((f.conn_id, adm.reply))
        return replies

    # --- admission -----------------------------------------------------------------------------
    def admit(self, conn_id: str, line: bytes) -> Admission:
        """Admit one raw frame (bytes incl. LF, or an oversize prefix) from ``conn_id`` in the current tick."""
        try:
            frame = decode_frame(line)
        except CanonicalError:
            frame = None
        if isinstance(frame, NoopFrame):
            return Admission(None, None)
        if not isinstance(frame, SubmitFrame):
            h = raw_hash(line)
            self.recorder.put_side(SideDomain.RAW, h, line.hex())
            return self._done(conn_id, None, h, False, Decision.DENY, Reason.SCHEMA, ActionClass.U)

        env = frame.envelope
        header = env.header()
        self.recorder.put_side(SideDomain.ARGS, header.args_hash, env.args)
        cls = self.dispatcher.classify(env)
        deny = lambda reason, sig_ok=True: self._done(conn_id, header, env.content_hash(), sig_ok,  # noqa: E731
                                                      Decision.DENY, reason, cls)
        if not self._sig_ok(conn_id, header):
            return deny(Reason.BAD_SIG, sig_ok=False)
        if frame.tick != self._tick:
            return deny(Reason.LATE_FRAME)
        if not expiry_ok(env.expiry_tick, self._tick):
            return deny(Reason.EXPIRED)
        nonce_key, action_key = (env.agent_id, env.nonce), (env.agent_id, env.action_id)
        if nonce_key in self._nonces or action_key in self._actions:
            return deny(Reason.NONCE_REUSED)
        self._nonces.add(nonce_key)  # consumed only after sig and expiry passed (ADR-01 §8.4)
        self._actions.add(action_key)
        epoch = self._epoch_of(env.agent_id)
        if epoch is None:
            return deny(Reason.SUSPENDED)
        if env.epoch != epoch:
            return deny(Reason.STALE_EPOCH)
        if env.tool.startswith("ks."):
            return deny(Reason.OUT_OF_SCOPE)
        if cls == ActionClass.U:
            return deny(Reason.CLASS_U)
        ex = self.dispatcher.execute(env, None)  # state txn: ks.state (vikram), not wired in the skeleton
        rh = result_hash(ex.result)
        self.recorder.put_side(SideDomain.RESULT, rh, ex.result)
        return self._done(conn_id, header, env.content_hash(), True, Decision.EXEC, Reason.OK, cls,
                          result=ex.result, result_hash=rh, read_set=ex.read_set, write_set=ex.write_set)

    def _sig_ok(self, conn_id: str, header: EnvelopeHeader) -> bool:
        if header.sig is None:
            return False
        if header.agent_id in SYSTEM_PRINCIPALS and conn_id != SYSTEM_CONN:
            return False  # a system agent_id is never verified on an agent connection (X7)
        pub = self.keyring.pub(header.agent_id)
        return pub is not None and verify_hex(pub, header.sig, header.signing_bytes())

    def _done(self, conn_id: str, header: EnvelopeHeader | None, envelope_hash: str, sig_ok: bool,
              decision: Decision, reason: Reason, cls: ActionClass, *, result: Any = None,
              result_hash: str | None = None, read_set: tuple = (), write_set: tuple = ()) -> Admission:
        c = self.config
        rec = self.recorder.append(
            tick=self._tick, ts_us=c.start_ts_us + self._tick * c.tick_us + self._slot, conn_id=conn_id,
            envelope=header, envelope_hash=envelope_hash, sig_ok=sig_ok, decision=decision, reason=reason,
            policy_rule=None, action_class=cls, read_set=read_set, write_set=write_set, outbox_ids=(),
            result_hash=result_hash, control=None, reexec_of=None)
        self._slot += 1
        reply = ReplyFrame(tick=self._tick, seq=rec.seq, record_id=rec.record_id, decision=decision, reason=reason,
                           result=result, result_hash=result_hash)
        return Admission(rec, reply)
