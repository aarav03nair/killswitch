"""Control-plane view the gateway reads at admission steps 7-9 and again inside the txn (step 13, D5).

The real implementation folds ``ks.control`` records (B3-19/B3-20, ks.containment). The gateway depends only on
this protocol, so tests and the runtime plug in anything that answers these three questions *at call time*
(never cached across the check-to-use window).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from ks.contracts import Reason

__all__ = ["ControlView", "CallableControl", "StaticControl"]


class ControlView(Protocol):
    def epoch_of(self, agent_id: str) -> int | None:
        """Current credential epoch; ``None`` = no live credential (suspended)."""

    def conn_denial(self, conn_id: str) -> Reason | None:
        """Connection deny-list (``conn:<id>``): ``SUSPENDED``/``REVOKED`` or ``None``."""

    def agent_denial(self, agent_id: str) -> Reason | None:
        """Agent status: ``SUSPENDED``/``REVOKED`` or ``None`` (also asked for every ``act_chain`` principal)."""


class CallableControl:
    """Adapter for the runtime's plain ``epoch_of`` callable: no deny-lists."""

    def __init__(self, epoch_of: Callable[[str], int | None]):
        self.epoch_of = epoch_of

    def conn_denial(self, conn_id: str) -> Reason | None:
        return None

    def agent_denial(self, agent_id: str) -> Reason | None:
        return None


class StaticControl:
    """Mutable in-memory control state (tests, RT5 unit): set epochs and deny-lists directly."""

    def __init__(self, epochs: dict[str, int | None]):
        self.epochs = epochs
        self.conns: dict[str, Reason] = {}
        self.agents: dict[str, Reason] = {}

    def epoch_of(self, agent_id: str) -> int | None:
        return self.epochs.get(agent_id)

    def conn_denial(self, conn_id: str) -> Reason | None:
        return self.conns.get(conn_id)

    def agent_denial(self, agent_id: str) -> Reason | None:
        return self.agents.get(agent_id)
