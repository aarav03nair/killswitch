"""Gateway: admission of one frame per connection per tick in the single canonical order of ADR-03 §1, then a record.

    1 decode  2 schema  3 signature  4 late_frame  5 expiry  6 nonce/(agent, action)  7 conn deny-list
    8 agent epoch/status  9 act_chain ancestors  10 ks.* scope  11 classify (U denied)  12 policy
    13 txn: BEGIN IMMEDIATE, take seq, re-read steps 7-9, execute (ToolDispatcher), COMMIT   14 append record

The first failing step decides the reason; every stop is a sealed record (rule 11). Steps 7-9 are a fast path:
step 13 re-reads them inside the txn (RT5), so a suspend landing in the check-to-use window gives deny/suspended.
Seams: ``Gateway.open``/``Gateway.tick`` toward ks.runtime; ``ToolDispatcher`` toward ks.world (B3-37);
``ControlView`` (B3-19), ``Policy`` (B3-14) and ``TaintView`` (containment) behind protocols; the outbox
(``ks.gateway.outbox``, B3-23) is the gateway's own. Seed record (D-SEQ1):
with a store and a ``seed`` function, the first ``open`` appends seq 1 (author ``ks.gateway``, ``c-0``).
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from ks.contracts import (MAX_EXPIRY_TICKS, Control, ControlOp, OutboxStatus, SEED_TOOL, SYSTEM_CONN, SYSTEM_PRINCIPALS, ActionClass, CanonicalError, Decision,
                          Envelope, EnvelopeHeader, Keyring, NoopFrame, Reason, Record, ReplyFrame, RunConfig,
                          SideDomain, SubmitFrame, TickFrame, decode_frame, expiry_ok, merge_read_set, raw_hash, result_hash)
from ks.identity import verify_hex
from ks.recorder import GatewayHooks, Recorder

from .control import CallableControl, ControlView
from .dispatch import Execution, GatewayTxn, StateSnapshot, StateTxn, ToolDispatcher, ViewProvider
from .outbox import OUTBOX_PREFIX, Outbox, TaintView
from .policy import AllowAll, Policy
from .system import SystemEnvelopeError, SystemQueue, admit_system
from .txn import writes_at

__all__ = ["Admission", "Gateway", "InFrame"]


class _Refused(Exception):
    """The gateway refuses an execution (lying sets, dispatcher COMMIT, an outbox request it cannot honour): a recorded deny."""


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
                 epoch_of: Callable[[str], int | None] | None = None, *, dispatcher: ToolDispatcher,
                 views: ViewProvider | None = None, hooks: GatewayHooks | None = None,
                 control: ControlView | None = None, policy: Policy | None = None, store: Any = None,
                 seed: Callable[[Any, int], None] | None = None, sign: Callable[[bytes], str] | None = None,
                 taint: TaintView | None = None, system: SystemQueue | None = None):
        if (control is None) == (epoch_of is None):
            raise ValueError("pass exactly one of epoch_of and control")
        if seed is not None and (store is None or sign is None):
            raise ValueError("a seed record needs a store and the gateway signer (it is a signed ks.gateway envelope)")
        self.config = config.tcb_view()  # A3: the TCB never sees fault/culprit/fault_tick
        self.keyring = keyring
        self.recorder = recorder
        self.hooks = hooks if hooks is not None else GatewayHooks()  # no-ops in production (RT8(g) seam)
        self.control: ControlView = control if control is not None else CallableControl(epoch_of)
        self.policy: Policy = policy if policy is not None else AllowAll()
        self.store = store  # ks.state Store (None = skeleton scenario: no state, no txn)
        self._seed, self._sign = seed, sign
        if sign is not None and keyring.pub("ks.gateway") is not None and not verify_hex(
                keyring.pub("ks.gateway"), sign(b"ks/gateway-key-probe"), b"ks/gateway-key-probe"):
            raise ValueError("the gateway signer does not match the keyring's ks.gateway key")
        self.system = system  # B3-13: control-phase queue of system envelopes (c-0), drained in open()
        self._seq_tick: dict[int, int] = {}  # record seq -> tick (for the G3 early hold: tick a version was written)
        # outbox (B3-23): needs the store (objects) and the signer (ks.dispatch / ks.control records)
        self.outbox: Outbox | None = (Outbox(store, self.config, taint=taint, tick_of_seq=self._tick_of_seq,
                                           record_at=self._record_at)
                                      if store is not None and sign is not None else None)
        self._seeded = False
        self.dispatcher = dispatcher
        # ks.world's view builder (B3-05); defaults to the dispatcher if it also implements ViewProvider
        self.views = views if views is not None else (dispatcher if isinstance(dispatcher, ViewProvider) else None)
        self.delivered: dict[str, tuple] = {}  # agent -> view sent this tick; joins its read_set (I1)
        self._conn_agent: dict[str, str] = {}  # conn_id -> the agent bound to it by the barrier (D7: 1:1)
        self._nonces: dict[tuple[str, str], int] = {}  # (agent, nonce) -> tick consumed; pruned past the window
        self._actions: set[tuple[str, str]] = set()  # (agent, action_id): kept for the whole run (ADR-03 §1.6)
        self.view_reads: tuple = ()  # last executed action: reads delivered in the view (B3-46 tags these `view`)
        self.tool_reads: tuple = ()  # ... and reads the adapter made (`tool`)
        self._tick = 0
        self._slot = 0
        self._rec_cache: dict[int, Any] = {}

    def _tick_of_seq(self, seq: int) -> int:
        """Tick a record landed in, from the durable record (cache is only a speedup; a restart rebuilds it)."""
        if seq not in self._seq_tick:
            for r in self.recorder.rundir.records():
                self._seq_tick[r.seq] = r.tick
        if seq not in self._seq_tick:
            raise LookupError(f"no record for seq {seq}: cannot derive the tick of a sensitive-field version")
        return self._seq_tick[seq]

    def _record_at(self, seq: int):
        """The landed record at ``seq`` (cache; a miss rescans the durable log)."""
        if seq not in self._rec_cache:
            for r in self.recorder.rundir.records():
                self._rec_cache[r.seq] = r
        return self._rec_cache.get(seq)

    def begin_tick(self, tick: int) -> None:
        self._tick, self._slot = tick, 0
        horizon = tick - MAX_EXPIRY_TICKS  # a nonce consumed at t had expiry <= t + 8, so it is expired after that
        for k in [k for k, t in self._nonces.items() if t < horizon]:
            del self._nonces[k]

    # --- barrier seam (B3-37) --------------------------------------------------------------------
    def open(self, tick: int, agents: Iterable[str]) -> dict[str, TickFrame]:
        """Start ``tick`` and return the TickFrame owed to each agent (epoch from control, view from ViewProvider)."""
        self.begin_tick(tick)
        if self._seed is not None and not self._seeded:
            self._seed_record()
        if self.system is not None:  # ADR-00 step 1 control phase: before the release phase and the views
            self.system.control_phase(self, tick)
        self._release_due(tick)
        # M2: views see only seqs below the tick's first seq (tick 1 -> 2 after the seed); None without a store
        state = None if self.store is None else StateSnapshot(self.store, self.recorder.seq + 1)
        self.delivered = {a: (tuple(self.views.view(a, tick, state)) if self.views is not None else ())
                          for a in agents}
        return {a: TickFrame(tick=tick, epoch=self.control.epoch_of(a), view=self.delivered[a]) for a in agents}

    def tick(self, tick: int, frames: Sequence[InFrame]) -> list[tuple[str, ReplyFrame]]:
        """Admit this tick's frames in agent_id order (arrival order is discarded); replies as (conn_id, reply)."""
        if tick != self._tick:
            raise ValueError(f"tick {tick} was not opened (current {self._tick})")
        replies = []
        for f in frames:
            self.bind(f.conn_id, f.agent_id)  # the barrier's 1:1 connection <-> agent binding (S3)
        for f in sorted(frames, key=lambda f: f.agent_id):
            adm = self.admit(f.conn_id, f.line)
            if adm.reply is not None:
                replies.append((f.conn_id, adm.reply))
        return replies

    def bind(self, conn_id: str, agent_id: str) -> None:
        """Bind a connection to its agent (D7: 1:1). A frame on a connection with no binding is bad_sig (B3-42)."""
        if conn_id == SYSTEM_CONN:
            raise SystemEnvelopeError("c-0 is never bound to an agent (E1)")
        self._conn_agent[conn_id] = agent_id

    # --- admission -----------------------------------------------------------------------------
    def admit(self, conn_id: str, line: bytes) -> Admission:
        """Admit one raw frame (bytes incl. LF, or an oversize prefix) from ``conn_id`` in the current tick."""
        if conn_id == SYSTEM_CONN:  # B3-13: c-0 has no wire; system envelopes go through admit_system only
            raise SystemEnvelopeError("no frames on c-0: use Gateway.admit_system (E1)")
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
        cls = self._classify(env)
        ehash = env.content_hash()

        def deny(reason: Reason, sig_ok: bool = True, rtxn=None) -> Admission:
            return self._done(conn_id, header, ehash, sig_ok, Decision.DENY, reason, cls, rtxn=rtxn)

        if not self._sig_ok(conn_id, header):  # 3
            return deny(Reason.BAD_SIG, sig_ok=False)
        if frame.tick != self._tick:  # 4
            return deny(Reason.LATE_FRAME)
        if not expiry_ok(env.expiry_tick, self._tick):  # 5
            return deny(Reason.EXPIRED)
        nonce_key, action_key = (env.agent_id, env.nonce), (env.agent_id, env.action_id)
        if nonce_key in self._nonces or action_key in self._actions:  # 6
            return deny(Reason.NONCE_REUSED)
        self._nonces[nonce_key] = self._tick  # consumed only after sig and expiry passed (ADR-03 §1.6)
        self._actions.add(action_key)
        why = self._control_denial(env, conn_id)  # 7, 8, 9 (fast path; step 13 re-reads)
        if why is not None:
            return deny(why)
        if env.tool.startswith("ks."):  # 10
            return deny(Reason.OUT_OF_SCOPE)
        if cls == ActionClass.U:  # 11
            return deny(Reason.CLASS_U)
        verdict = self.policy.decide(env, cls)  # 12
        if verdict is not None:
            return self._done(conn_id, header, ehash, True, verdict.decision, verdict.reason, cls,
                              policy_rule=verdict.rule)
        self.hooks.between_check_and_txn(env)  # RT8/RT5 check-to-use window; no-op by default
        return self._execute(conn_id, env, header, ehash, cls)  # 13, 14

    def admit_system(self, env: Envelope) -> Admission:
        """Admit one signed system envelope on c-0 now (``ks.gateway.system``, B3-13)."""
        return admit_system(self, env)

    def _classify(self, env: Envelope) -> ActionClass:
        """Step 11 input: class of this instance. A classifier exception or non-class answer is U (ADR-03 §2)."""
        try:
            cls = self.dispatcher.classify(env)
        except Exception:
            return ActionClass.U
        return cls if isinstance(cls, ActionClass) else ActionClass.U

    def _control_denial(self, env: Envelope, conn_id: str) -> Reason | None:
        """Steps 7-9 against the *current* control state: connection deny-list, agent epoch/status, ancestors."""
        c = self.control
        why = c.conn_denial(conn_id)
        if why is not None:
            return why
        why = c.agent_denial(env.agent_id)
        if why is not None:
            return why
        epoch = c.epoch_of(env.agent_id)
        if epoch is None:
            return Reason.SUSPENDED
        if env.epoch != epoch:
            return Reason.STALE_EPOCH
        if any(c.agent_denial(link.principal) is not None for link in env.act_chain):
            return Reason.REVOKED_ANCESTOR
        return None

    def _execute(self, conn_id: str, env: Envelope, header: EnvelopeHeader, ehash: str, cls: ActionClass, *,
                 reexec_of: int | None = None) -> Admission:
        """Steps 13-14. ``seq`` is taken first (``recorder.begin``), then ``BEGIN IMMEDIATE``, then the control
        re-read (D5), then the tool runs, then COMMIT, then the record is appended under that seq. Any failure
        before COMMIT rolls the state txn back and releases the seq, so no seq is lost and no write is orphaned."""
        rtxn = self.recorder.begin()
        store = self.store
        try:
            txn: StateTxn | None = None
            if store is not None:
                store.conn.execute("BEGIN IMMEDIATE")  # inside the try: "database is locked" releases the seq
                txn = GatewayTxn(store, rtxn.seq)
            why = self._control_denial(env, conn_id)
            if why is not None:  # the suspend committed before this txn: nothing executes (RT5)
                if store is not None:
                    store.conn.execute("ROLLBACK")
                return self._done(conn_id, header, ehash, True, Decision.DENY, why, cls, rtxn=rtxn,
                                  reexec_of=reexec_of)
            try:
                ex = self._run_tool(env, txn)
                read_set, write_set = self._sets(ex, txn, env.agent_id)
                oids: tuple[str, ...] = ()
                if ex.outbox:  # gateway-built OutboxItems: derived id/idempotency_key, lineage = the record's read set
                    if self.outbox is None or txn is None:
                        raise _Refused("outbox request without a store and a signer")
                    ow, oids = self.outbox.create(ex.outbox, env, rtxn.seq, self._tick, read_set)
                    write_set = tuple(sorted((*write_set, *ow), key=lambda w: w.obj))
                rh = result_hash(ex.result)  # before COMMIT: an unhashable result must not leave a landed write
            except Exception:
                # rule 11: a dispatcher that raises, lies about its sets, commits itself or asks for an outbox
                # effect the gateway refuses is a recorded deny; the seq is consumed by that record (no gap)
                if store is not None and store.conn.in_transaction:
                    store.conn.execute("ROLLBACK")
                return self._done(conn_id, header, ehash, True, Decision.DENY, Reason.TOOL_ERROR, cls, rtxn=rtxn,
                                  reexec_of=reexec_of)
            self.recorder.put_side(SideDomain.RESULT, rh, ex.result)
            if store is not None:
                store.conn.execute("COMMIT")
        except BaseException:
            if store is not None and store.conn.in_transaction:
                store.conn.execute("ROLLBACK")
            rtxn.rollback()
            raise
        adm = self._done(conn_id, header, ehash, True, Decision.EXEC, Reason.OK, cls, result=ex.result,
                         result_hash=rh, read_set=read_set, write_set=write_set, outbox_ids=oids, rtxn=rtxn,
                         reexec_of=reexec_of)
        for oid in oids:  # ADR-03 p.lineage_hold / ADR-04 s5: a tainted lineage at creation is a hold record
            d = self.outbox.get(oid)
            why = self.outbox.hold_reason(d) if d.item.status == OutboxStatus.QUEUED else None
            if why is not None:
                self._system_record("ks.control", f"hold-{oid}-{why}", None, d, OutboxStatus.HELD, self._tick,
                                    why=why)
        return adm

    def _run_tool(self, env: Envelope, txn: StateTxn | None) -> Execution:
        """Run the dispatcher inside the gateway's txn. A dispatcher never ends it: transaction control is denied
        by a SQLite authorizer while it runs, and a txn that is no longer open afterwards is refused (the COMMIT
        is the gateway's, step 13)."""
        store = self.store
        if store is None:
            return self.dispatcher.execute(env, txn)
        store.conn.set_authorizer(lambda action, *_: sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION
                                  else sqlite3.SQLITE_OK)
        try:
            ex = self.dispatcher.execute(env, txn)
        finally:
            store.conn.set_authorizer(None)
        if not store.conn.in_transaction:
            raise _Refused("dispatcher ended the state transaction")
        return ex

    def _sets(self, ex: Execution, txn: StateTxn | None, agent_id: str) -> tuple[tuple, tuple]:
        """Record sets are the gateway's. Without a txn a tool cannot have touched state, so it may report no
        writes. With one, ``write_set`` is what the store holds for this seq (``writes_at``) and the tool's
        report must equal it; its reads must be versions the store really has. The agent's delivered view joins
        the read set (I1), kept apart from the tool's reads internally (``self.view_reads``/``self.tool_reads``,
        tagged ``source`` view|tool by ``merge_read_set``, B3-46). If one obj appears at two versions both entries
        are kept (Panel ruling on B3-41); the same version in both is one ``tool`` entry."""
        if txn is None:
            if ex.write_set:
                raise _Refused("a tool wrote without a state txn")
            return ex.read_set, ex.write_set
        writes = writes_at(txn.store, txn.seq)
        if any(w.obj.startswith(OUTBOX_PREFIX) for w in writes) or any(w.obj.startswith(OUTBOX_PREFIX) for w in ex.write_set):
            raise _Refused("only the gateway's outbox writes outbox:* objects")
        if tuple(sorted(ex.write_set, key=lambda w: w.obj)) != writes:
            raise _Refused("write_set disagrees with the store")
        for r in ex.read_set:
            row = txn.store.conn.execute("SELECT hash FROM versions WHERE obj = ? AND ver = ?",
                                         (r.obj, r.ver)).fetchone()
            if row is None or row[0] != r.hash:
                raise _Refused("read_set names a version the store does not have")
        self.tool_reads = tuple(ex.read_set)
        self.view_reads = tuple(v.read_entry() for v in self.delivered.get(agent_id, ()))
        try:  # B3-46 / contracts 1.4: tagged view|tool; one obj at two versions keeps both (Panel, B3-41 review)
            return merge_read_set(self.view_reads, self.tool_reads), writes
        except ValueError as exc:
            raise _Refused("read_set names an object twice") from exc

    def _seed_record(self) -> None:
        """D-SEQ1: record seq 1 is the seed: a signed ``ks.gateway`` envelope on ``c-0`` whose write_set is
        exactly what the seed function wrote. Appended (after COMMIT) before the first agent action."""
        self._seeded = True
        if self.recorder.seq != 0:
            raise RuntimeError("seed record must be seq 1 (the record is not empty)")
        rtxn = self.recorder.begin()
        store = self.store
        try:
            store.conn.execute("BEGIN IMMEDIATE")  # inside the try: a db lock releases seq 1 like any txn failure
            self._seed(store, rtxn.seq)
            writes = writes_at(store, rtxn.seq)
            store.conn.execute("COMMIT")
        except BaseException:
            if store.conn.in_transaction:
                store.conn.execute("ROLLBACK")
            rtxn.rollback()
            self._seeded = False  # seq 1 is released: the next open retries the seed
            raise
        args = {"seed": self.config.scenario}
        env = Envelope(agent_id="ks.gateway", action_id="seed", parent_action_id=None, act_chain=(),
                       tool=SEED_TOOL, args=args, nonce="0" * 32, expiry_tick=0, epoch=0, claimed_ts_us=None,
                       claimed_seq=None, sig=None)
        env = env.with_sig(self._sign(env.signing_bytes()))
        header = env.header()
        self.recorder.put_side(SideDomain.ARGS, header.args_hash, args)
        rh = result_hash({"seeded": len(writes)})
        self.recorder.put_side(SideDomain.RESULT, rh, {"seeded": len(writes)})
        self._done(SYSTEM_CONN, header, env.content_hash(), True, Decision.EXEC, Reason.OK, ActionClass.R,
                   result_hash=rh, write_set=writes, rtxn=rtxn, tick=0)

    # --- outbox release phase (B3-23, F4) ------------------------------------------------------------
    def _release_due(self, tick: int) -> None:
        """At the start of ``tick``: every queued item whose ``release_tick`` has come is either dispatched
        (``ks.dispatch``) or held (``ks.control`` hold, reason lineage_hold | sensitive_field). One record each."""
        if self.outbox is None:
            return
        for d in self.outbox.due(tick):
            why = self.outbox.hold_reason(d)
            oid = d.item.outbox_id
            if why is None:
                self._system_record("ks.dispatch", f"dispatch-{oid}", {"outbox": oid}, d, OutboxStatus.DISPATCHED,
                                    tick)
            else:
                self._system_record("ks.control", f"hold-{oid}-{why}", None, d, OutboxStatus.HELD, tick, why=why)

    def _system_record(self, tool: str, action_id: str, args: dict | None, d, status: OutboxStatus, tick: int,
                       *, why: str | None = None) -> None:
        """One signed ``ks.gateway`` envelope on c-0 whose write_set is the item's status change (G4)."""
        rtxn = self.recorder.begin()
        store = self.store
        try:
            store.conn.execute("BEGIN IMMEDIATE")
            w = self.outbox.set_status(d, status, seq=rtxn.seq, author="ks.gateway", action_id=action_id)
            store.conn.execute("COMMIT")
        except BaseException:
            if store.conn.in_transaction:
                store.conn.execute("ROLLBACK")
            rtxn.rollback()
            raise
        control = None
        if why is not None:
            control = Control(control_id=f"k-{rtxn.seq:06d}", op=ControlOp.HOLD, target=f"outbox:{d.item.outbox_id}",
                              epoch=None, alert_id=None, issued_by="ks.gateway", auto=True, reason=why)
            args = control.to_obj()
        env = Envelope(agent_id="ks.gateway", action_id=action_id, parent_action_id=None, act_chain=(), tool=tool,
                       args=args, nonce=hashlib.sha256(action_id.encode()).hexdigest()[:32], expiry_tick=tick,
                       epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)
        env = env.with_sig(self._sign(env.signing_bytes()))
        header = env.header()
        self.recorder.put_side(SideDomain.ARGS, header.args_hash, args)
        res = {"outbox": d.item.outbox_id, "status": status.value}
        rh = result_hash(res)
        self.recorder.put_side(SideDomain.RESULT, rh, res)
        reads = tuple(sorted((*d.item.lineage, d.read_entry()), key=lambda e: (e.obj, e.ver)))  # outbox obj not in lineage
        self._done(SYSTEM_CONN, header, env.content_hash(), True, Decision.EXEC, Reason.OK,
                   ActionClass(d.item.action_class), result_hash=rh, read_set=reads,
                   write_set=(w,), rtxn=rtxn, tick=tick, control=control)

    def _sig_ok(self, conn_id: str, header: EnvelopeHeader) -> bool:
        if header.sig is None:
            return False
        if header.agent_id in SYSTEM_PRINCIPALS and conn_id != SYSTEM_CONN:
            return False  # a system agent_id is never verified on an agent connection (X7)
        bound = self._conn_agent.get(conn_id)
        if conn_id != SYSTEM_CONN and header.agent_id != bound:
            return False  # S3: another agent than this connection's, or no agent bound to it at all: bad_sig
        pub = self.keyring.pub(header.agent_id)
        return pub is not None and verify_hex(pub, header.sig, header.signing_bytes())

    def _done(self, conn_id: str, header: EnvelopeHeader | None, envelope_hash: str, sig_ok: bool,
              decision: Decision, reason: Reason, cls: ActionClass, *, result: Any = None,
              result_hash: str | None = None, read_set: tuple = (), write_set: tuple = (), rtxn=None,
              tick: int | None = None, policy_rule: str | None = None, outbox_ids: tuple = (),
              control: Any = None, reexec_of: int | None = None) -> Admission:
        c = self.config
        if conn_id == SYSTEM_CONN and (header is None or header.agent_id not in SYSTEM_PRINCIPALS
                                       or (sig_ok and not self._sig_ok(SYSTEM_CONN, header))):
            raise SystemEnvelopeError("a c-0 record needs a system principal and, if sig_ok, a verified signature")
        tick = self._tick if tick is None else tick
        rec = (rtxn if rtxn is not None else self.recorder.begin()).append(
            tick=tick, ts_us=c.start_ts_us + tick * c.tick_us + self._slot, conn_id=conn_id,
            envelope=header, envelope_hash=envelope_hash, sig_ok=sig_ok, decision=decision, reason=reason,
            policy_rule=policy_rule, action_class=cls, read_set=read_set, write_set=write_set, outbox_ids=outbox_ids,
            result_hash=result_hash, control=control, reexec_of=reexec_of)
        self._seq_tick[rec.seq] = tick
        self._slot += 1
        reply = ReplyFrame(tick=tick, seq=rec.seq, record_id=rec.record_id, decision=decision, reason=reason,
                           result=result, result_hash=result_hash)
        return Admission(rec, reply)
