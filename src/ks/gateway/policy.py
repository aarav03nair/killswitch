"""Step 12 (policy) seam. B3-14 implements the classes and scopes (p.scope, p.i1_outbox, p.i2_approval,
p.lineage_hold, p.sensitive_early_hold); B3-11 only fixes where it runs and what it may answer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ks.contracts import ActionClass, Decision, Envelope, Reason

__all__ = ["Policy", "Verdict", "AllowAll"]


@dataclass(frozen=True)
class Verdict:
    """A policy stop: ``decision`` is ``DENY`` or ``HOLD``; ``rule`` is the ``policy_rule`` token."""

    decision: Decision
    reason: Reason
    rule: str


class Policy(Protocol):
    def decide(self, env: Envelope, cls: ActionClass) -> Verdict | None:
        """``None`` = admit. Runs after classification (step 12), before the txn; sees no raw state."""


class AllowAll:
    def decide(self, env: Envelope, cls: ActionClass) -> Verdict | None:
        return None
