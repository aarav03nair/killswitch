"""Identifier and scalar types shared by all contracts (patterns are part of the frozen contract)."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, Strict, StringConstraints

from .canonical import MAX_SAFE_INT

__all__ = [
    "AGENT_ID_RE", "PRINCIPAL_RE", "SYSTEM_PRINCIPALS", "SYSTEM_CONN", "SYSTEM_TOOLS", "RECOVER_TOOL_PREFIX",
    "SEED_TOOL",
    "Hash", "Sig", "Nonce", "AgentId", "PrincipalId", "ActionId", "ConnId", "RecordId", "ToolName", "Token", "Seq",
    "Tick", "NonNeg", "Epoch", "LogicalUs", "PubKey", "record_id_for", "is_system_principal", "is_system_tool",
    "system_tool_signers",
]

SYSTEM_PRINCIPALS = frozenset({"ks.gateway", "ks.monitor", "ks.operator", "ks.recovery", "ks.witness"})
"""Non-agent principals. Each holds its own key; agents can never claim a ``ks.*`` id.
v1.1 (E2/X7): the human signer is ``ks.operator`` ("incident console" is only the read-only page).
The 1.0 console signer id is removed with no alias: it no longer even matches :data:`PRINCIPAL_RE`."""

AGENT_ID_RE = r"^[a-z][a-z0-9_]{0,31}$"
PRINCIPAL_RE = r"^(?:ks\.(?:" + "|".join(sorted(p[3:] for p in SYSTEM_PRINCIPALS)) + r")|[a-z][a-z0-9_]{0,31})$"
"""An agent id or exactly one of :data:`SYSTEM_PRINCIPALS` (any other ``ks.*`` id is rejected)."""

SYSTEM_CONN = "c-0"
"""Connection id reserved for in-gateway system envelopes (E1/K4). Agents get ``c-1``.. . A system
``agent_id`` is accepted (``sig_ok``) only on ``c-0``; on ``c-1..`` it is ``deny/bad_sig`` unverified.
Every envelope recorded on ``c-0`` claims a system principal. Both directions are Record validators.
c-0 envelopes are still signature-verified; operator frames reach c-0 only via the peercred socket (J1)."""

SEED_TOOL = "ks.seed"
"""v1.3 (D-15, amends CALL-02 G1): the seed record. Executed only as record seq 1, tick 0, by ``ks.gateway`` on
``c-0``, read_set and outbox empty, write_set == the scenario's ``seed_state`` (``Record.seed_problems`` +
``ks verify`` -> ``seed_invalid``). A denied ``ks.seed`` envelope (e.g. an agent's) is an ordinary denial."""

RECOVER_TOOL_PREFIX = "ks.recover."
"""``ks.recover.<op>``, ``<op>`` a C5 ``StepOp``; signed by ``ks.recovery`` only."""

SYSTEM_TOOLS: dict[str, frozenset[str]] = {
    "ks.control": frozenset({"ks.monitor", "ks.gateway", "ks.operator", "ks.recovery"}),
    "ks.dispatch": frozenset({"ks.gateway"}),
    "ks.alert": frozenset({"ks.monitor"}),
    "ks.approve": frozenset({"ks.operator"}),
    SEED_TOOL: frozenset({"ks.gateway"}),
}
"""Reserved ``ks.*`` tools -> principals that may execute them (K13), plus ``ks.recover.<op>`` (recovery).
Each is a recorded envelope on ``c-0``. An agent principal submitting any ``ks.*`` tool is denied
(``out_of_scope`` when its signature verified); a system principal executes only these tools."""

_Int = Strict()
Seq = Annotated[int, _Int, Field(ge=1, le=MAX_SAFE_INT)]
"""Gateway sequence number; the first record has seq 1, no gaps."""
Tick = Annotated[int, _Int, Field(ge=0, le=MAX_SAFE_INT)]
"""Logical scheduling round assigned by the gateway's tick barrier."""
NonNeg = Annotated[int, _Int, Field(ge=0, le=MAX_SAFE_INT)]
Epoch = Annotated[int, _Int, Field(ge=0, le=MAX_SAFE_INT)]
"""Credential epoch (fencing counter). Starts at 0 and is **strictly monotonic per principal** (D1):
suspend, revoke and release each set a new maximum; an old epoch is never reused (see ``EpochFold``)."""
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


def is_system_tool(tool: str) -> bool:
    """True for every ``ks.*`` tool name (reserved namespace), known or not."""
    return tool.startswith("ks.")


def system_tool_signers(tool: str) -> frozenset[str]:
    """Principals allowed to execute ``tool``; empty for unknown ``ks.*`` tools and for agent tools."""
    if tool.startswith(RECOVER_TOOL_PREFIX):
        from .recovery import StepOp  # local import: recovery imports ids
        return frozenset({"ks.recovery"}) if tool[len(RECOVER_TOOL_PREFIX):] in {o.value for o in StepOp} \
            else frozenset()
    return SYSTEM_TOOLS.get(tool, frozenset())

