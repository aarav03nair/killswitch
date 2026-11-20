"""Control-plane view the gateway reads at admission steps 7-9 and again inside the txn (step 13, D5).

The real implementation folds ``ks.control`` records (B3-19/B3-20, ks.containment). The gateway depends only on
this protocol, so tests and the runtime plug in anything that answers these three questions *at call time*
(never cached across the check-to-use window).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from ks.contracts import Control, ControlOp, EpochFold, Reason, TargetKind, parse_target

__all__ = ["ControlView", "CallableControl", "StaticControl", "FoldedControl"]


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


class FoldedControl:
    """Control state as the fold of executed ``ks.control`` records (B3-13): agent epochs and status by
    :class:`EpochFold` (D1, strictly monotonic), plus the connection deny-list. The gateway's system path
    (``ks.gateway.system``) calls :meth:`check` before it records a Control and :meth:`apply` after the record
    is appended, so this state never runs ahead of the chain. ``hold``/``unhold`` belong to containment and the
    outbox (B3-19, B3-23); :meth:`check` raises ``NotImplementedError`` for them so nothing is recorded."""

    def __init__(self, agents):
        self.agents = frozenset(agents)
        self.fold = EpochFold(self.agents)
        self.conns: dict[str, str] = {}  # conn_id -> "suspended" | "revoked"

    def epoch_of(self, agent_id: str) -> int | None:
        return self.fold.epoch(agent_id) if agent_id in self.agents else None

    def conn_denial(self, conn_id: str) -> Reason | None:
        return {"suspended": Reason.SUSPENDED, "revoked": Reason.REVOKED}.get(self.conns.get(conn_id, ""))

    def agent_denial(self, agent_id: str) -> Reason | None:
        return {"suspended": Reason.SUSPENDED, "revoked": Reason.REVOKED}.get(self.fold.status(agent_id))

    def next_epoch(self, agent_id: str) -> int:
        """The fresh epoch a suspend/revoke/release of ``agent_id`` sets now (D1: above every earlier one)."""
        return self.fold.max_epoch(agent_id) + 1

    def check(self, control: Control) -> None:
        """Raise ``ValueError`` if applying ``control`` now would break D1 or a permanent revoke."""
        kind, ident = parse_target(control.target)
        if control.op in (ControlOp.HOLD, ControlOp.UNHOLD):
            raise NotImplementedError(f"{control.op} is served by ks.gateway.holds (B3-19)")
        if kind == TargetKind.AGENT:
            if ident not in self.agents:
                raise ValueError(f"{ident} is not an agent of this run")
            if control.epoch is None or control.epoch <= self.fold.max_epoch(ident):
                raise ValueError(f"epoch of {ident} not strictly monotonic")
            if self.fold.status(ident) == "revoked":
                raise ValueError(f"{ident} is revoked")
            if control.op == ControlOp.RELEASE and self.fold.status(ident) == "active":
                raise ValueError(f"{ident} is not suspended")
        else:  # conn
            st = self.conns.get(ident)
            if st == "revoked":
                raise ValueError(f"conn {ident} is revoked")
            if control.op == ControlOp.RELEASE and st is None:
                raise ValueError(f"conn {ident} is not suspended")

    def apply(self, control: Control) -> None:
        self.check(control)
        kind, ident = parse_target(control.target)
        if kind == TargetKind.AGENT:
            self.fold.apply(control)
        elif control.op == ControlOp.RELEASE:
            self.conns.pop(ident, None)
        else:
            self.conns[ident] = "revoked" if control.op == ControlOp.REVOKE else "suspended"
