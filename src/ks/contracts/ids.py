"""Identifier and scalar types shared by all contracts (patterns are part of the frozen contract)."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, Strict, StringConstraints

from .canonical import MAX_SAFE_INT

__all__ = [
    "AGENT_ID_RE", "PRINCIPAL_RE", "SYSTEM_PRINCIPALS", "Hash", "Sig", "Nonce", "AgentId", "PrincipalId",
    "ActionId", "ConnId", "RecordId", "ToolName", "Token", "Seq", "Tick", "NonNeg", "Epoch", "LogicalUs",
    "PubKey", "record_id_for", "is_system_principal",
]

AGENT_ID_RE = r"^[a-z][a-z0-9_]{0,31}$"
PRINCIPAL_RE = r"^(ks\.)?[a-z][a-z0-9_]{0,31}$"
SYSTEM_PRINCIPALS = frozenset({"ks.console", "ks.monitor", "ks.recovery", "ks.gateway", "ks.witness"})
"""Non-agent principals. Each holds its own key; agents can never claim a ``ks.*`` id."""

_Int = Strict()
Seq = Annotated[int, _Int, Field(ge=1, le=MAX_SAFE_INT)]
"""Gateway sequence number; the first record has seq 1, no gaps."""
Tick = Annotated[int, _Int, Field(ge=0, le=MAX_SAFE_INT)]
"""Logical scheduling round assigned by the gateway's tick barrier."""
NonNeg = Annotated[int, _Int, Field(ge=0, le=MAX_SAFE_INT)]
Epoch = Annotated[int, _Int, Field(ge=0, le=MAX_SAFE_INT)]
"""Credential epoch (fencing counter); bumped by suspend/revoke/release."""
LogicalUs = Annotated[int, _Int, Field(ge=0, le=MAX_SAFE_INT)]
"""Logical microseconds derived from the tick, never wall clock (determinism)."""

Hash = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
"""SHA-256, lowercase hex."""
Sig = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{128}$")]
"""Ed25519 signature, lowercase hex (64 bytes)."""
PubKey = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
"""Ed25519 public key, lowercase hex (32 bytes)."""
Nonce = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{32}$")]
"""128-bit anti-replay nonce, lowercase hex. NOT an idempotency key."""
AgentId = Annotated[str, StringConstraints(strict=True, pattern=AGENT_ID_RE)]
PrincipalId = Annotated[str, StringConstraints(strict=True, pattern=PRINCIPAL_RE)]
"""An agent id or a ``ks.*`` system principal."""
ActionId = Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_.:-]{1,64}$")]
"""Agent-chosen action id, unique per principal (OTel ``gen_ai.tool.call.id``)."""
ConnId = Annotated[str, StringConstraints(strict=True, pattern=r"^c-[0-9]{1,6}$")]
"""Gateway-assigned connection id (never agent-supplied)."""
RecordId = Annotated[str, StringConstraints(strict=True, pattern=r"^r-[0-9]{6,16}$")]
ToolName = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")]
"""Namespaced tool, e.g. ``crm.update_supplier``. ``ks.*`` tools are reserved for system principals."""
Token = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
"""Short lowercase code (detector names, sinks, policy rule ids, compensator names)."""


def record_id_for(seq: int) -> str:
    """The one record_id format: ``r-`` + seq zero-padded to 6 digits."""
    return f"r-{seq:06d}"


def is_system_principal(p: str) -> bool:
    return p in SYSTEM_PRINCIPALS

