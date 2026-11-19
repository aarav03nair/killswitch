"""Test and red-team seams on the gateway (ADR-02 RT8(g), ADR-03 TOCTOU). Production runs use the no-op
defaults; ``ks.bench`` / the red-team harness subclass this. Nothing here can weaken a check: a hook only
*observes or withholds* (skip a witness push) or *runs code at a named point* (e.g. mutate state to test
that the txn re-checks)."""

from __future__ import annotations

__all__ = ["GatewayHooks"]


class GatewayHooks:
    """No-op by default."""

    def skip_checkpoint(self, tick: int) -> bool:
        """``True`` = the barrier sends no witness push this tick (RT8(g): rewrite records after the last
        checkpoint; ``run.snapshot`` is taken through this)."""
        return False

    def between_check_and_txn(self, env: object) -> None:
        """Called by the gateway after admission/policy checks passed and before the state txn opens (the
        check-to-use window): a test may mutate control state here to prove the txn re-validates."""
