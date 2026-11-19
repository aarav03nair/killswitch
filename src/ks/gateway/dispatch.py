"""The tool dispatch seam (B3-37, B3-40): the gateway decides *whether* an envelope executes; ks.world decides
*what* a tool is and *does*, and *what* each agent sees. The gateway owns no tool table and no view scope.

    classify(env) -> ActionClass                                  # before admission; unknown -> ActionClass.U (rule 6)
    execute(env, txn) -> Execution(result, read_set, write_set, outbox)   # only after every admission check passed
    view(agent_id, tick, state) -> tuple[ViewEntry, ...]          # ViewProvider: TickFrame.view at Gateway.open (I1)

Who owns read/write sets: the gateway, never the tool. ``txn`` is the gateway's state transaction (``ks.state``,
ADR-05). A dispatcher reads and writes only through it, and once it is wired the gateway takes ``read_set`` and
``write_set`` from the txn and refuses an ``Execution`` whose sets disagree (``Gateway._sets``). Until then
(``txn is None``, skeleton tools touch no state) the gateway accepts the dispatcher's sets and they must be
empty for a write. TODO(B3-41): wire StateTxn and the cross-check.

``Execution.outbox`` carries I1/I2 effect *requests*; the gateway (outbox owner) assigns ids, hashes the payload,
attaches lineage from the record's read set and creates the ``OutboxItem``s. A tool never sends an effect itself.
Implemented by ``ks.world`` (``ks.world.tools.SkeletonDispatcher`` for SKEL-01).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ks.contracts import ActionClass, Envelope, ReadEntry, ViewEntry, WriteEntry

__all__ = ["Execution", "OutboxRequest", "StateSnapshot", "StateTxn", "ToolDispatcher", "ViewProvider"]

StateTxn = Any
"""Placeholder for the ks.state execution transaction (vikram); the skeleton passes ``None``."""
StateSnapshot = Any
"""Placeholder for a read-only ks.state view at the start of a tick; the skeleton passes ``None``."""


@dataclass(frozen=True)
class OutboxRequest:
    """One irreversible effect an executed tool asks for; becomes an ``OutboxItem`` (C3) in the gateway."""

    sink: str
    """Destination token, e.g. ``payments``, ``email``."""
    action_class: ActionClass
    """``ActionClass.I1`` or ``ActionClass.I2``."""
    payload: Any
    """Raw payload (side store only; the item holds its hash)."""


@dataclass(frozen=True)
class Execution:
    """What one executed tool returned: a raw result (side store only), the sets and outbox requests."""

    result: Any
    read_set: tuple[ReadEntry, ...] = ()
    write_set: tuple[WriteEntry, ...] = ()
    outbox: tuple[OutboxRequest, ...] = ()


@runtime_checkable
class ToolDispatcher(Protocol):
    def classify(self, env: Envelope) -> ActionClass:
        """Action class of ``env.tool``; ``ActionClass.U`` for a tool the world does not know."""

    def execute(self, env: Envelope, txn: StateTxn) -> Execution:
        """Run an admitted envelope of a known tool (never class U, never ``ks.*``)."""


@runtime_checkable
class ViewProvider(Protocol):
    def view(self, agent_id: str, tick: int, state: StateSnapshot) -> tuple[ViewEntry, ...]:
        """The agent's per-tick view (sorted by obj, <= MAX_VIEW_ENTRIES); ``()`` for a suspended agent is fine."""
