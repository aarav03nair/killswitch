"""The tool dispatch seam (B3-37, B3-40): the gateway decides *whether* an envelope executes; ks.world decides
*what* a tool is and *does*, and *what* each agent sees. The gateway owns no tool table and no view scope.

    classify(env) -> ActionClass                                  # before admission; unknown -> ActionClass.U (rule 6)
    execute(env, txn) -> Execution(result, read_set, write_set, outbox)   # only after every admission check passed
    view(agent_id, tick, state) -> tuple[ViewEntry, ...]          # ViewProvider: TickFrame.view at Gateway.open (I1)

Who owns read/write sets: the gateway, never the tool. ``txn`` is the gateway's state transaction (``ks.state``,
ADR-05). A dispatcher reads and writes only through it, and once it is wired the gateway takes ``read_set`` and
``write_set`` from the txn and refuses an ``Execution`` whose sets disagree (``Gateway._sets``). Without a store
(``txn is None``, skeleton tools touch no state) the gateway accepts the dispatcher's sets and they must be
empty for a write. With a store it passes a ``GatewayTxn`` (store inside ``BEGIN IMMEDIATE`` + seq).

``Execution.outbox`` carries I1/I2 effect *requests*; the gateway (outbox owner) assigns ids, hashes the payload,
attaches lineage from the record's read set and creates the ``OutboxItem``s. A tool never sends an effect itself.
Implemented by ``ks.world`` (``ks.world.tools.SkeletonDispatcher`` for SKEL-01).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ks.contracts import ActionClass, Envelope, ReadEntry, ViewEntry, WriteEntry

__all__ = ["GatewayTxn", "Execution", "OutboxRequest", "StateSnapshot", "StateTxn", "ToolDispatcher", "ViewProvider"]

@dataclass(frozen=True)
class GatewayTxn:
    """The execution transaction (step 13): the store inside the gateway's ``BEGIN IMMEDIATE`` and the record
    ``seq`` this action's writes carry (taken at txn start, G5). ``None`` is passed when the gateway has no store
    (skeleton scenario)."""

    store: Any
    seq: int


StateTxn = GatewayTxn
"""The ks.state execution transaction (or ``None`` without a store)."""


@dataclass(frozen=True)
class StateSnapshot:
    """What ``ViewProvider.view`` gets (M2): the store and ``visible_to`` = the first seq of the tick (an int:
    the seq the tick's first record takes), so writes of this tick are invisible. ``None`` without a store."""

    store: Any
    visible_to: int


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
