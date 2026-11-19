"""C2 Record (one per envelope the gateway receives, including denials) and the witness checkpoint.

Only the gateway writes records (rule 8). Chain: ``prev_hash`` of seq 1 is GENESIS_HASH; ``hash`` is
sha256 of :meth:`Record.signing_bytes` (all fields except ``hash`` and ``gw_sig``); ``gw_sig`` is the
gateway's Ed25519 over the same bytes. The witness countersigns ``(seq, head, tick)`` every tick.

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
from .envelope import EnvelopeHeader
from .hashing import Domain, GENESIS_HASH, args_hash
from .ids import ConnId, Hash, LogicalUs, PrincipalId, RecordId, Seq, Sig, Tick, Token, record_id_for
from .state import ReadEntry, WriteEntry, _sorted_unique

__all__ = ["Decision", "ActionClass", "Reason", "REASONS_FOR", "Record", "WitnessCheckpoint", "GENESIS_HASH"]


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
    BAD_SIG = "bad_sig"                  # missing/invalid signature; suspends the connection, never the agent
    SCHEMA = "schema"                    # unparseable or unknown keys; envelope is None
    NONCE_REUSED = "nonce_reused"
    EXPIRED = "expired"
    STALE_EPOCH = "stale_epoch"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    REVOKED_ANCESTOR = "revoked_ancestor"  # a principal in act_chain is revoked/suspended
    CLASS_U = "class_u"
    OUT_OF_SCOPE = "out_of_scope"
    OVER_QUOTA = "over_quota"
    RECOVERY_FROZEN = "recovery_frozen"  # recovery action while a tamper alert is open
    # hold
    LINEAGE_HOLD = "lineage_hold"
    SENSITIVE_FIELD = "sensitive_field"
    NEEDS_APPROVAL = "needs_approval"


REASONS_FOR = {
    Decision.EXEC: frozenset({Reason.OK}),
    Decision.DENY: frozenset({Reason.BAD_SIG, Reason.SCHEMA, Reason.NONCE_REUSED, Reason.EXPIRED,
                              Reason.STALE_EPOCH, Reason.SUSPENDED, Reason.REVOKED, Reason.REVOKED_ANCESTOR,
                              Reason.CLASS_U, Reason.OUT_OF_SCOPE, Reason.OVER_QUOTA, Reason.RECOVERY_FROZEN}),
    Decision.HOLD: frozenset({Reason.LINEAGE_HOLD, Reason.SENSITIVE_FIELD, Reason.NEEDS_APPROVAL}),
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
    """Versions the adapter read, sorted by obj (``ks.read_set``). Empty on deny."""
    write_set: tuple[WriteEntry, ...]
    """Versions written, before/after ver+hash, sorted by obj (``ks.write_set``). Empty unless exec."""
    outbox_ids: tuple[OutboxId, ...]
    """Outbox items created, in creation order (``ks.outbox_ids``). Empty unless exec."""
    result_hash: Hash | None
    """Hash of the result returned to the agent (OTel ``gen_ai.tool.call.result``, hashed). Exec only."""
    control: Control | None
    """The Control in clear, iff ``envelope.tool == "ks.control"`` and executed (``ks.control.*``)."""
    prev_hash: Hash
    """``hash`` of record seq-1; GENESIS_HASH for seq 1 (``ks.record.prev_hash``)."""
    hash: Hash
    """sha256 of :meth:`signing_bytes` (``ks.record.hash``)."""
    gw_sig: Sig | None
    """Gateway Ed25519 over :meth:`signing_bytes` (``ks.record.gw_sig``). ``None`` only before signing."""

    @field_validator("read_set")
    @classmethod
    def _rs(cls, v):
        return _sorted_unique(v, lambda e: e.obj, "read_set obj")

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
        return self

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
    """Signed ``(seq, head, tick)`` from the separate witness process; one line per tick in ``witness.jsonl``."""

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
    sig: Sig | None
    """Witness Ed25519 over :meth:`signing_bytes`. ``None`` only before signing."""

    def with_sig(self, sig: str) -> WitnessCheckpoint:
        return WitnessCheckpoint.model_validate({**self.to_obj(), "sig": sig})
