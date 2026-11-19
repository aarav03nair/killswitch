"""C2 Record (one per envelope the gateway receives, including denials) and the witness checkpoint.

Only the gateway writes records (rule 8). Chain: ``prev_hash`` of seq 1 is GENESIS_HASH; ``hash`` is
sha256 of :meth:`Record.signing_bytes` (all fields except ``hash`` and ``gw_sig``); ``gw_sig`` is the
gateway's Ed25519 over the same bytes. The witness countersigns ``(seq, head, tick, count)`` every tick.

**Frames (C2 resolution).** One frame per connection per tick, FIFO. A frame tagged with the wrong tick is
``deny/late_frame`` in that agent's slot; surplus frames wait, so a flooder only delays itself.
**System records (E1/K4).** ``c-0`` carries in-gateway system envelopes only; a system ``agent_id`` with a
verified signature is only ever on ``c-0`` and every c-0 envelope claims a system principal. ``ks.*`` tools
execute only for the principals in ``ids.SYSTEM_TOOLS``; an agent's ``ks.*`` envelope is always denied.
**seq (G5)** is assigned at the start of the ``BEGIN IMMEDIATE`` txn and the record appended after commit.
**Determinism (C5).** :func:`determinism_view` drops the key-dependent fields, so fresh-key runs of the
same seed compare equal.

Attribution rule (Q9): use :attr:`Record.attributed_agent`. It is ``None`` when ``sig_ok`` is false,
so a forged-signature denial is never counted against the agent it claims to be.
Records hold hashes only: no raw values, args or results (rule 9).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import StringConstraints, field_validator, model_validator

from ._base import Document
from .control import CONTROL_TOOL, Control
from .envelope import MAX_EXPIRY_TICKS, EnvelopeHeader
from .hashing import Domain, GENESIS_HASH, args_hash
from .ids import (RECOVER_TOOL_PREFIX, SYSTEM_CONN, SYSTEM_PRINCIPALS, ConnId, Hash, LogicalUs, PrincipalId,
                  RecordId, SEED_TOOL, Seq, Sig, Tick, Token, record_id_for, system_tool_signers)
from .state import ReadEntry, WriteEntry, _sorted_unique, check_read_set

__all__ = ["Decision", "ActionClass", "Reason", "REASONS_FOR", "Record", "WitnessCheckpoint", "GENESIS_HASH",
           "RECORD_KEY_FIELDS", "WITNESS_KEY_FIELDS", "determinism_view", "witness_chain_problems"]


class Decision(StrEnum):
    EXEC = "exec"   # executed
    DENY = "deny"   # refused; recorded (rule 11); no effects
    HOLD = "hold"   # parked by lineage hold / sensitive field / approval; no effects yet


class ActionClass(StrEnum):
    """Action class, fixed before the action runs (RES-02). Unknown values are rejected by the schema."""

    R = "R"     # reversible: we hold the earlier version
    C = "C"     # compensable: a registered opposite action exists
    I1 = "I1"   # irreversible, containable: goes through the outbox
    I2 = "I2"   # irreversible, uncontainable: needs prior human approval
    U = "U"     # unclassified / unmediated: always denied (rule 6, fail closed)


class Reason(StrEnum):
    OK = "ok"
    # deny
    BAD_SIG = "bad_sig"
    """Missing/invalid signature; suspends the connection, never the agent. Also (K14) when ``args_hash`` !=
    hash(raw args) (spliced args), and for a system ``agent_id`` on an agent connection (never verified there)."""
    SCHEMA = "schema"                    # unparseable or unknown keys; envelope is None
    NONCE_REUSED = "nonce_reused"
    EXPIRED = "expired"                  # expiry_tick outside [tick, tick + MAX_EXPIRY_TICKS]
    LATE_FRAME = "late_frame"            # frame tagged with an earlier or a future tick (C2, K3)
    STALE_EPOCH = "stale_epoch"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    REVOKED_ANCESTOR = "revoked_ancestor"  # a principal in act_chain is revoked/suspended
    CLASS_U = "class_u"
    OUT_OF_SCOPE = "out_of_scope"
    OVER_QUOTA = "over_quota"            # per-connection budget exceeded (SEC-03 F8); never ``expired``
    RECOVERY_FROZEN = "recovery_frozen"  # recovery action while frozen (verify != OK or tamper/stall alert, M12)
    TOOL_ERROR = "tool_error"
    """v1.3 (B3-11 finding 3, rule 11): the envelope was admitted but its tool/dispatcher raised. The state txn is
    rolled back, so the record has no read/write set, outbox ids or result; ``sig_ok`` is true (admitted).
    The exception text is not recorded (records hold hashes only)."""
    # hold
    LINEAGE_HOLD = "lineage_hold"
    SENSITIVE_FIELD = "sensitive_field"
    NEEDS_APPROVAL = "needs_approval"   # I2 effects and approval-gated steps
    STALE_PLAN = "stale_plan"           # ks.recover.* step whose ``expect`` is no longer the head (M8)


REASONS_FOR = {
    Decision.EXEC: frozenset({Reason.OK}),
    Decision.DENY: frozenset({Reason.BAD_SIG, Reason.SCHEMA, Reason.NONCE_REUSED, Reason.EXPIRED,
                              Reason.LATE_FRAME, Reason.STALE_EPOCH, Reason.SUSPENDED, Reason.REVOKED,
                              Reason.REVOKED_ANCESTOR, Reason.CLASS_U, Reason.OUT_OF_SCOPE, Reason.OVER_QUOTA,
                              Reason.RECOVERY_FROZEN, Reason.TOOL_ERROR}),
    Decision.HOLD: frozenset({Reason.LINEAGE_HOLD, Reason.SENSITIVE_FIELD, Reason.NEEDS_APPROVAL,
                              Reason.STALE_PLAN}),
}
"""Which reasons each decision may carry."""

OutboxId = Annotated[str, StringConstraints(strict=True, pattern=r"^ob-[0-9]{6,16}$")]


class Record(Document):
    """C2 Record. Field docs give the OTel mapping (span name ``execute_tool {tool}``)."""

    CONTRACT: ClassVar[str] = "ks.record/1"
    DOMAIN: ClassVar[bytes] = Domain.RECORD
    UNSIGNED_FIELDS: ClassVar[frozenset[str]] = frozenset({"hash", "gw_sig"})

    contract: Literal["ks.record/1"] = "ks.record/1"
    """Contract id."""
    seq: Seq
    """Gateway sequence, 1.., no gaps (``ks.record.seq``)."""
    tick: Tick
    """Tick of execution (``ks.tick``)."""
    ts_us: LogicalUs
    """Gateway logical time from the tick, never wall clock (span start time)."""
    record_id: RecordId
    """``r-`` + seq zero-padded (``ks.record.id``)."""
    conn_id: ConnId
    """Gateway-assigned submitting connection (``ks.conn.id``); never agent-supplied."""
    envelope: EnvelopeHeader | None
    """Signed envelope header as received (claimed agent_id, act_chain, args_hash, sig). ``None`` iff unparseable."""
    envelope_hash: Hash
    """``envelope.content_hash()``; for unparseable input, ``raw_hash(bytes)`` (raw in side store)."""
    sig_ok: bool
    """Gateway verified ``envelope.sig`` against the claimed principal's key (``ks.envelope.sig_ok``)."""
    decision: Decision
    """exec | deny | hold (``ks.policy.decision``)."""
    reason: Reason
    """Why; ``ok`` for exec (``ks.policy.reason``; also ``error.type`` on deny)."""
    policy_rule: Token | None
    """Policy rule id that decided, if any (``ks.policy.rule``)."""
    action_class: ActionClass
    """R | C | I1 | I2 | U, assigned before execution (``ks.action.class``)."""
    read_set: tuple[ReadEntry, ...]
    """Versions the adapter read **plus every ``TickFrame.view`` entry delivered to the agent this tick** (I1),
    sorted by (obj, ver) (``ks.read_set``). Field objects per C3 X2. Empty on deny. v1.4 (B3-46): each entry is
    tagged ``source`` view|tool; one object may appear twice (a view version and a different tool version), see
    :func:`~ks.contracts.state.check_read_set`."""
    write_set: tuple[WriteEntry, ...]
    """Versions written, before/after ver+hash, sorted by obj (``ks.write_set``). Empty unless exec."""
    outbox_ids: tuple[OutboxId, ...]
    """Outbox items created, in creation order (``ks.outbox_ids``). Empty unless exec."""
    result_hash: Hash | None
    """Hash of the result returned to the agent (OTel ``gen_ai.tool.call.result``, hashed). Exec only."""
    control: Control | None
    """The Control in clear, iff ``envelope.tool == "ks.control"`` and executed (``ks.control.*``)."""
    reexec_of: Seq | None
    """Seq of the ``hold`` record whose envelope this record re-executes after ``unhold action:<record_id>``
    (M10); same ``envelope_hash``, nonce/expiry not re-checked. ``None`` for a normal admission."""
    prev_hash: Hash
    """``hash`` of record seq-1; GENESIS_HASH for seq 1 (``ks.record.prev_hash``)."""
    hash: Hash
    """sha256 of :meth:`signing_bytes` (``ks.record.hash``)."""
    gw_sig: Sig | None
    """Gateway Ed25519 over :meth:`signing_bytes` (``ks.record.gw_sig``). ``None`` only before signing."""

    @field_validator("read_set")
    @classmethod
    def _rs(cls, v):
        return check_read_set(v)

    @field_validator("write_set")
    @classmethod
    def _ws(cls, v):
        return _sorted_unique(v, lambda e: e.obj, "write_set obj")

    @field_validator("outbox_ids")
    @classmethod
    def _ob(cls, v):
        if len(set(v)) != len(v):
            raise ValueError("duplicate outbox id")
        return v

    @model_validator(mode="after")
    def _rules(self) -> Self:
        if self.record_id != record_id_for(self.seq):
            raise ValueError("record_id must be record_id_for(seq)")
        if self.reason not in REASONS_FOR[self.decision]:
            raise ValueError(f"reason {self.reason} not allowed with decision {self.decision}")
        if (self.envelope is None) != (self.reason == Reason.SCHEMA):
            raise ValueError("envelope is None exactly when reason == schema")
        if self.envelope is None and self.action_class != ActionClass.U:
            raise ValueError("unparseable input is class U")
        if self.sig_ok == (self.reason in (Reason.BAD_SIG, Reason.SCHEMA)):
            raise ValueError("sig_ok is false exactly for bad_sig/schema denials")
        if self.action_class == ActionClass.U and self.decision != Decision.DENY:
            raise ValueError("class U is always denied (fail closed)")
        if self.reason == Reason.CLASS_U and self.action_class != ActionClass.U:
            raise ValueError("reason class_u requires action_class U")
        if self.decision != Decision.EXEC and (self.write_set or self.outbox_ids or self.result_hash):
            raise ValueError("only executed records have writes, outbox items or a result")
        if self.decision == Decision.DENY and self.read_set:
            raise ValueError("denied records have no read set")
        is_ctl = self.envelope is not None and self.envelope.tool == CONTROL_TOOL
        if self.control is not None and not is_ctl:
            raise ValueError("control present only on ks.control envelopes")
        if is_ctl and self.decision == Decision.EXEC and self.control is None:
            raise ValueError("executed ks.control record must carry the Control")
        env = self.envelope
        if env is None:
            if self.reexec_of is not None:
                raise ValueError("reexec_of needs an envelope")
            return self
        # N1: a verified record has a signature
        if self.sig_ok and env.sig is None:
            raise ValueError("sig_ok requires envelope.sig")
        # M10: re-execution of a held envelope
        if self.reexec_of is not None and (self.reexec_of >= self.seq or not self.sig_ok):
            raise ValueError("reexec_of must be an earlier seq of a verified (held) envelope")
        # F3 / K2: an admitted envelope was within its expiry window at this tick
        if self.sig_ok and self.decision in (Decision.EXEC, Decision.HOLD) and self.reexec_of is None \
                and not (self.tick <= env.expiry_tick <= self.tick + MAX_EXPIRY_TICKS):
            raise ValueError("admitted envelope must satisfy tick <= expiry_tick <= tick + MAX_EXPIRY_TICKS")
        system = env.agent_id in SYSTEM_PRINCIPALS
        # E1/K4/X7: system agent_id <=> c-0, both directions
        if system and self.sig_ok and self.conn_id != SYSTEM_CONN:
            raise ValueError("a system agent_id is verified only on c-0 (else deny/bad_sig, unverified)")
        if self.conn_id == SYSTEM_CONN and not system:
            raise ValueError("c-0 carries system envelopes only")
        ks_tool = env.tool.startswith("ks.")
        if ks_tool and not system and self.decision != Decision.DENY:
            raise ValueError("an agent ks.* envelope is always denied (out_of_scope)")
        if self.sig_ok and self.decision == Decision.EXEC and system:
            if env.agent_id not in system_tool_signers(env.tool):
                raise ValueError(f"{env.agent_id} may not execute {env.tool}")
        if env.tool.startswith(RECOVER_TOOL_PREFIX) and self.decision != Decision.DENY \
                and env.agent_id != "ks.recovery":
            raise ValueError("ks.recover.* runs only as ks.recovery")
        if self.control is not None and self.control.issued_by != env.agent_id:
            raise ValueError("control.issued_by must equal envelope.agent_id")
        if self.reason == Reason.STALE_PLAN and not env.tool.startswith(RECOVER_TOOL_PREFIX):
            raise ValueError("stale_plan is only for ks.recover.* steps")
        return self

    def seed_problems(self) -> list[str]:
        """D-15 structural rule for an admitted ``ks.seed`` record (empty list = fine, also for non-seed records
        and for denied ``ks.seed`` envelopes). ``ks verify`` adds ``write_set == seed_state`` and reports any
        problem as ``seed_invalid``."""
        env = self.envelope
        if env is None or env.tool != SEED_TOOL or self.decision == Decision.DENY:
            return []
        p: list[str] = []
        if self.decision != Decision.EXEC:
            p.append("ks.seed is exec or deny, never hold")
        if self.seq != 1:
            p.append(f"ks.seed at seq {self.seq}, not 1")
        if self.tick != 0:
            p.append(f"ks.seed at tick {self.tick}, not 0")
        if env.agent_id != "ks.gateway" or not self.sig_ok or self.conn_id != SYSTEM_CONN:
            p.append("ks.seed must be a verified ks.gateway envelope on c-0")
        if self.read_set or self.outbox_ids:
            p.append("ks.seed has no read set and no outbox items")
        if self.reexec_of is not None:
            p.append("ks.seed is never a re-execution")
        return p

    # --- construction / integrity -------------------------------------------------------------
    @classmethod
    def seal(cls, *, prev_hash: str, **fields: Any) -> Record:
        """Build a record and compute ``hash``; ``gw_sig`` stays ``None`` until :meth:`with_gw_sig`."""
        r = cls(prev_hash=prev_hash, hash=GENESIS_HASH, gw_sig=None, **fields)
        return cls.model_validate({**r.to_obj(), "hash": r.content_hash()})

    def with_gw_sig(self, sig: str) -> Record:
        return Record.model_validate({**self.to_obj(), "gw_sig": sig})

    @property
    def attributed_agent(self) -> str | None:
        """The ONLY attribution accessor: claimed agent_id if the gateway verified the signature."""
        return self.envelope.agent_id if (self.sig_ok and self.envelope is not None) else None

    @property
    def claimed_agent(self) -> str | None:
        """What the envelope claims, verified or not. Evidence only; never use for attribution."""
        return self.envelope.agent_id if self.envelope is not None else None

    def integrity_problems(self) -> list[str]:
        """Local checks ``verify`` runs per record (signatures and chain links are checked by ks.verify)."""
        p: list[str] = []
        if self.hash != self.content_hash():
            p.append("hash mismatch")
        if self.envelope is not None and self.envelope_hash != self.envelope.content_hash():
            p.append("envelope_hash mismatch")
        if self.control is not None and self.envelope is not None \
                and self.envelope.args_hash != args_hash(self.control.to_obj()):
            p.append("control does not match envelope args_hash")
        if self.gw_sig is None:
            p.append("unsigned record")
        return p


class WitnessCheckpoint(Document):
    """Signed ``(seq, head, tick, count)`` from the separate witness process; one line per tick in ``witness.jsonl``.
    No-op ticks repeat ``(seq, head)`` with a new ``count``. Stall (F6): the gateway waits to the deadline,
    proceeds and raises a ``witness_stall`` alert; heads live in ``<run>/witness-heads/`` (0700, witness uid)."""

    CONTRACT: ClassVar[str] = "ks.witness/1"
    DOMAIN: ClassVar[bytes] = Domain.WITNESS
    UNSIGNED_FIELDS: ClassVar[frozenset[str]] = frozenset({"sig"})

    contract: Literal["ks.witness/1"] = "ks.witness/1"
    """Contract id."""
    witness_id: PrincipalId
    """Witness principal (``ks.witness``); its key is not the gateway's."""
    seq: Seq
    """Seq of the record whose hash is ``head``."""
    tick: Tick
    """Tick witnessed."""
    head: Hash
    """``Record.hash`` at ``seq``."""
    count: Seq
    """Signed line counter (B1/F2): 1 on the first line, +1 per line, strictly; the RunAnchor repeats the last."""
    sig: Sig | None
    """Witness Ed25519 over :meth:`signing_bytes`. ``None`` only before signing."""

    @model_validator(mode="after")
    def _wid(self) -> Self:
        if self.witness_id != "ks.witness":
            raise ValueError("witness_id must be ks.witness")
        return self

    def with_sig(self, sig: str) -> WitnessCheckpoint:
        return WitnessCheckpoint.model_validate({**self.to_obj(), "sig": sig})


def witness_chain_problems(checkpoints) -> list[str]:
    """Structural checks of ``witness.jsonl`` in order (signatures and heads vs records belong to ks.verify):
    ``count`` = line number from 1, ``tick`` strictly increasing, ``seq`` non-decreasing, an unchanged seq
    repeats its head. Problems are ``"<line>: <code>"`` with codes from the VerifyReport vocabulary."""
    probs: list[str] = []
    prev: WitnessCheckpoint | None = None
    for i, w in enumerate(checkpoints, start=1):
        if w.count != i:
            probs.append(f"{i}: count_mismatch")
        if prev is not None:
            if w.tick <= prev.tick or w.seq < prev.seq or (w.seq == prev.seq and w.head != prev.head):
                probs.append(f"{i}: witness_mismatch")
        prev = w
    return probs


RECORD_KEY_FIELDS = ("hash", "prev_hash", "gw_sig", "envelope.sig")
"""Record fields that depend on key material; dropped by :func:`determinism_view` (C5)."""
WITNESS_KEY_FIELDS = ("head", "sig")
"""WitnessCheckpoint fields that depend on key material; dropped by :func:`determinism_view` (C5)."""


def determinism_view(doc: Record | WitnessCheckpoint) -> dict[str, Any]:
    """C5 projection: a Record without ``{hash, prev_hash, gw_sig, envelope.sig}``, a WitnessCheckpoint without
    ``{head, sig}``. Two runs of the same seed compare equal under this view even with fresh keys (T1b,
    ``ks repro``). Any other document is returned whole (``to_obj()``)."""
    obj = doc.to_obj()
    if isinstance(doc, Record):
        for f in ("hash", "prev_hash", "gw_sig"):
            obj.pop(f)
        if obj["envelope"] is not None:
            obj["envelope"].pop("sig")
    elif isinstance(doc, WitnessCheckpoint):
        for f in WITNESS_KEY_FIELDS:
            obj.pop(f)
    return obj
