"""The world's tools, behind ``ks.gateway.dispatch.ToolDispatcher`` (B3-37). SKEL-01 has two tools, neither
writes state. The scenario tools (crm, billing, comms, ...) replace this in Sprint 3 (tara).

Gateway-side only: agent processes import ``ks.world.skeleton``, never this. ks.world never imports ks.runtime.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ks.contracts import ActionClass, Envelope
from ks.gateway.dispatch import Execution, StateTxn

__all__ = ["SKELETON_TOOLS", "SkeletonDispatcher"]

SKELETON_TOOLS: dict[str, tuple[ActionClass, Callable[[dict[str, Any]], Any]]] = {
    "skel.noop": (ActionClass.R, lambda args: None),
    "skel.echo": (ActionClass.R, lambda args: {"echo": args}),
}
"""Tool -> (action class, implementation). Neither tool touches state."""


class SkeletonDispatcher:
    """``ToolDispatcher`` for the skeleton scenario."""

    def classify(self, env: Envelope) -> ActionClass:
        spec = SKELETON_TOOLS.get(env.tool)
        return spec[0] if spec is not None else ActionClass.U

    def execute(self, env: Envelope, txn: StateTxn) -> Execution:
        return Execution(SKELETON_TOOLS[env.tool][1](env.args))
