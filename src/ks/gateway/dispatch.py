"""The tool dispatch seam (B3-37): the gateway decides *whether* an envelope executes; a ``ToolDispatcher``
decides *what* a tool is and *does*. The gateway owns no tool table.

    classify(env) -> ActionClass                       # before admission; unknown tool -> ActionClass.U (rule 6)
    execute(env, txn) -> Execution(result, read_set, write_set)   # only after every admission check passed

``txn`` is the gateway's state transaction (``ks.state``, ADR-05; ``None`` until the store is wired in). A
dispatcher reads and writes only through it, so read/write sets are what the store saw, never self-reported.
Implemented by ``ks.world`` (``ks.world.tools.SkeletonDispatcher`` for SKEL-01). Owner of this file: nisha.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ks.contracts import ActionClass, Envelope, ReadEntry, WriteEntry

__all__ = ["Execution", "StateTxn", "ToolDispatcher"]

StateTxn = Any
"""Placeholder for the ks.state execution transaction (vikram); the skeleton passes ``None``."""


@dataclass(frozen=True)
class Execution:
    """What one executed tool returned: a raw result (side store only) and the sets for the record."""

    result: Any
    read_set: tuple[ReadEntry, ...] = ()
    write_set: tuple[WriteEntry, ...] = ()


@runtime_checkable
class ToolDispatcher(Protocol):
    def classify(self, env: Envelope) -> ActionClass:
        """Action class of ``env.tool``; ``ActionClass.U`` for a tool the world does not know."""

    def execute(self, env: Envelope, txn: StateTxn) -> Execution:
        """Run an admitted envelope of a known tool (never class U, never ``ks.*``)."""
