"""C1 Envelope: the signed request an agent (or system principal) submits to the gateway.

Signing scheme (commit-then-sign): the signature covers the **envelope header**, in which ``args``
is replaced by ``args_hash``. So a record can embed the header and ``verify`` can check the agent
signature without the raw args, and redacting the args from the side store never breaks it.

    header = env.header()                    # args -> args_hash
    sig    = signer.sign(header.signing_bytes())   # b"ks/envelope/v1\\x00" + canonical(header - sig)
    env    = env.with_sig(sig)

Unknown keys are rejected (gateway: ``deny/schema``). Agent-supplied time or sequence goes only in
``claimed_ts_us`` / ``claimed_seq``; the gateway never orders by them (RT6).
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal, Self

from pydantic import JsonValue, model_validator

from . import canonical
from ._base import Document, Value
from .hashing import Domain, args_hash
from .ids import ActionId, Epoch, LogicalUs, NonNeg, Nonce, PrincipalId, Sig, Tick, ToolName, Hash

__all__ = ["MAX_ACT_DEPTH", "ActLink", "EnvelopeHeader", "Envelope"]

MAX_ACT_DEPTH = 16
"""Longest act chain the gateway accepts."""


class ActLink(Value):
    """One hop of the act chain: a principal and the action of theirs that led here."""

    principal: PrincipalId
    """Who asked (agent id or ``ks.*``)."""
    action_id: ActionId
    """Their action that caused this one."""


class _EnvelopeFields(Document):
    DOMAIN: ClassVar[bytes] = Domain.ENVELOPE
    UNSIGNED_FIELDS: ClassVar[frozenset[str]] = frozenset({"sig"})

    agent_id: PrincipalId
    """Claimed signer (OTel ``gen_ai.agent.id``). Trusted only if the record's ``sig_ok`` is true."""
    action_id: ActionId
    """Agent-chosen id, unique per agent (OTel ``gen_ai.tool.call.id``)."""
    parent_action_id: ActionId | None
    """Immediate parent action; equals ``act_chain[-1].action_id`` (OTel span link, ``ks.action.parent_id``)."""
    act_chain: tuple[ActLink, ...]
    """Full act chain, root first, immediate parent last; empty = self-initiated (``ks.act_chain``).
    Agent-declared: used to deny revoked ancestors, NEVER for taint (taint uses recorded read sets)."""
    tool: ToolName
    """Tool to run (OTel ``gen_ai.tool.name``; operation ``execute_tool``)."""
    nonce: Nonce
    """Anti-replay nonce, unique per agent_id (``ks.envelope.nonce``). Not used for dedupe."""
    expiry_tick: Tick
    """Last tick at which the envelope is valid; later -> ``deny/expired`` (``ks.envelope.expiry_tick``)."""
    epoch: Epoch
    """Agent's credential epoch; stale -> ``deny/stale_epoch``, checked inside the write txn (``ks.agent.epoch``)."""
    claimed_ts_us: LogicalUs | None
    """Agent-claimed time, kept for evidence only; ordering uses gateway ``seq``/``ts_us``."""
    claimed_seq: NonNeg | None
    """Agent-claimed sequence, kept for evidence only; never becomes the record ``seq``."""
    sig: Sig | None
    """Ed25519 over :meth:`signing_bytes` (``ks.envelope.sig``). ``None`` only before signing."""

    @model_validator(mode="after")
    def _chain(self) -> Self:
        if len(self.act_chain) > MAX_ACT_DEPTH:
            raise ValueError(f"act_chain longer than {MAX_ACT_DEPTH}")
        last = self.act_chain[-1].action_id if self.act_chain else None
        if self.parent_action_id != last:
            raise ValueError("parent_action_id must equal act_chain[-1].action_id (or both empty)")
        if any(l.principal == self.agent_id and l.action_id == self.action_id for l in self.act_chain):
            raise ValueError("action appears in its own act_chain")
        return self

    def with_sig(self, sig: str) -> Self:
        """Copy with ``sig`` set (re-validated)."""
        return type(self).model_validate({**self.to_obj(), "sig": sig})


class EnvelopeHeader(_EnvelopeFields):
    """The envelope with ``args`` replaced by ``args_hash``. This is what is signed and what records embed."""

    CONTRACT: ClassVar[str] = "ks.envelope_header/1"

    contract: Literal["ks.envelope_header/1"] = "ks.envelope_header/1"
    """Contract id."""
    args_hash: Hash
    """``args_hash(args)``; args themselves in the side store (OTel ``ks.tool.call.arguments_hash``)."""


class Envelope(_EnvelopeFields):
    """What travels on the socket: the header fields plus the raw ``args``."""

    CONTRACT: ClassVar[str] = "ks.envelope/1"

    contract: Literal["ks.envelope/1"] = "ks.envelope/1"
    """Contract id."""
    args: dict[str, JsonValue]
    """Tool arguments (raw; may be sensitive). Must be canonical-serializable: no floats."""

    @model_validator(mode="after")
    def _args(self) -> Envelope:
        canonical.dumps(self.args)  # raises CanonicalError (a ValueError) on floats/bytes/huge ints
        return self

    def header(self) -> EnvelopeHeader:
        """The signed/recorded form: same fields, ``args`` -> ``args_hash``."""
        d: dict[str, Any] = self.to_obj()
        d.pop("args")
        d["contract"] = EnvelopeHeader.CONTRACT
        d["args_hash"] = args_hash(self.args)
        return EnvelopeHeader.model_validate(d)

    def signing_bytes(self) -> bytes:
        """Bytes the agent signs: those of the header."""
        return self.header().signing_bytes()

    def content_hash(self) -> str:
        """``envelope_hash``: hash of the header without ``sig``."""
        return self.header().content_hash()


