"""C5 RecoveryPlan: taint set, ordered steps, and a hash-only dry-run diff.

A **taint-scoped revert** is the set of ``restore`` steps in a plan: each restores one object to a
pre-taint version, and only if the object is still at the culprit's after-version (write-write
conflict rule; otherwise the planner emits ``flag`` or ``rerun``). Restores append a new version;
history is never edited. Steps run as envelopes from ``ks.recovery`` (tool ``ks.recover.<op>``),
after the console approves the plan by its :meth:`~RecoveryPlan.content_hash`.
Recovery is refused (``deny/recovery_frozen``) while a tamper alert is open.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Union

from pydantic import Field, StringConstraints, field_validator, model_validator

from ._base import Document, Value
from .hashing import Domain
from .ids import ActionId, AgentId, Hash, PrincipalId, Seq, Token
from .state import ObjId, ObjVer, VersionRef, _sorted_unique

__all__ = [
    "StepOp", "RestoreStep", "RerunStep", "ReplanStep", "CancelOutboxStep", "CompensateStep", "FlagStep",
    "Step", "ActionRef", "TaintSet", "DiffEntry", "RecoveryPlan",
]

_OB = Annotated[str, StringConstraints(strict=True, pattern=r"^ob-[0-9]{6,16}$")]


class StepOp(StrEnum):
    RESTORE = "restore"
    RERUN = "rerun"
    REPLAN = "replan"
    CANCEL_OUTBOX = "cancel_outbox"
    COMPENSATE = "compensate"
    FLAG = "flag"


class ActionRef(Value):
    """A recorded action, identified by its record."""

    seq: Seq
    """Record seq."""
    agent_id: PrincipalId
    """Attributed principal of that record."""
    action_id: ActionId
    """Its action id."""


class _Step(Value):
    n: Annotated[int, Field(strict=True, ge=0)]
    """Position in ``steps`` (0-based); steps run in this order."""
    reason: Token
    """Short code, e.g. ``tainted_write``, ``tainted_read``, ``write_write_conflict``."""


class RestoreStep(_Step):
    """Taint-scoped revert of one object: write a new version equal to ``to`` (class R)."""

    op: Literal["restore"] = "restore"
    """Step kind."""
    obj: ObjId
    """Object to restore."""
    expect: VersionRef
    """Must still be current (the culprit's after-version); otherwise the step fails closed."""
    to: VersionRef
    """Pre-taint version whose value is re-written (value from the side store)."""


class RerunStep(_Step):
    """Re-execute a deterministic honest action on repaired state; outbox dedupes on idempotency_key."""

    op: Literal["rerun"] = "rerun"
    """Step kind."""
    action: ActionRef
    """Original action; the re-run derives the same idempotency keys."""


class ReplanStep(_Step):
    """An LLM step that must be thought through again; queued for console approval. We build no re-planner."""

    op: Literal["replan"] = "replan"
    """Step kind."""
    action: ActionRef
    """Action whose output is tainted."""


class CancelOutboxStep(_Step):
    """Discard a held outbox item so it never leaves."""

    op: Literal["cancel_outbox"] = "cancel_outbox"
    """Step kind."""
    outbox_id: _OB
    """Held item to cancel."""


class CompensateStep(_Step):
    """Run the registered opposite action for a class C effect."""

    op: Literal["compensate"] = "compensate"
    """Step kind."""
    action: ActionRef
    """Action being compensated."""
    compensator: Token
    """Registered compensator name, e.g. ``tickets.close``."""


class FlagStep(_Step):
    """Hand to a person: no provable safe fix (write-write conflict, dispatched I1/I2 effect)."""

    op: Literal["flag"] = "flag"
    """Step kind."""
    obj: ObjId | None
    """Object concerned, if any."""
    action: ActionRef | None
    """Action concerned, if any."""


Step = Annotated[Union[RestoreStep, RerunStep, ReplanStep, CancelOutboxStep, CompensateStep, FlagStep],
                 Field(discriminator="op")]


class TaintSet(Value):
    """Everything written by, or derived from, the culprit after t0 (conservative: over-taint)."""

    versions: tuple[ObjVer, ...]
    """Tainted object versions, sorted."""
    actions: tuple[ActionRef, ...]
    """Tainted actions (wrote or read tainted versions), sorted by seq."""
    outbox_ids: tuple[_OB, ...]
    """Outbox items whose lineage touches tainted versions, sorted."""

    @field_validator("versions")
    @classmethod
    def _v(cls, v):
        return _sorted_unique(v, lambda e: (e.obj, e.ver), "tainted version")

    @field_validator("actions")
    @classmethod
    def _a(cls, v):
        return _sorted_unique(v, lambda e: e.seq, "tainted action")

    @field_validator("outbox_ids")
    @classmethod
    def _o(cls, v):
        return _sorted_unique(v, lambda e: e, "tainted outbox id")


class DiffEntry(Value):
    """One line of the dry-run diff: object state now vs after the plan (hashes only)."""

    obj: ObjId
    """Object."""
    current: VersionRef | None
    """Current head (``None`` if absent)."""
    planned_hash: Hash
    """Value hash after the plan (TOMBSTONE_HASH = deleted)."""


class RecoveryPlan(Document):
    """C5 plan, written to ``plans/<plan_id>.json``; approved by content hash."""

    CONTRACT: ClassVar[str] = "ks.recovery_plan/1"
    DOMAIN: ClassVar[bytes] = Domain.PLAN

    contract: Literal["ks.recovery_plan/1"] = "ks.recovery_plan/1"
    """Contract id."""
    plan_id: Annotated[str, StringConstraints(strict=True, pattern=r"^p-[0-9]{6,16}$")]
    """Planner-assigned id."""
    alert_id: Annotated[str, StringConstraints(strict=True, pattern=r"^a-[0-9]{6,16}$")]
    """Alert the plan answers."""
    culprit: AgentId
    """Agent being reverted, chosen by a person from the alert's root candidates."""
    t0_seq: Seq
    """First tainted record seq (taint starts here)."""
    as_of_seq: Seq
    """Plan computed against state at this record seq; stale plans must be recomputed."""
    taint_set: TaintSet
    """What is tainted."""
    steps: tuple[Step, ...]
    """Ordered steps; ``n`` equals position."""
    diff: tuple[DiffEntry, ...]
    """Dry-run diff, sorted by obj, one entry per object the plan changes."""

    @field_validator("diff")
    @classmethod
    def _d(cls, v):
        return _sorted_unique(v, lambda e: e.obj, "diff obj")

    @model_validator(mode="after")
    def _steps(self) -> RecoveryPlan:
        if [s.n for s in self.steps] != list(range(len(self.steps))):
            raise ValueError("step n must equal its position")
        if self.t0_seq > self.as_of_seq:
            raise ValueError("t0_seq must be <= as_of_seq")
        return self

    @property
    def needs_approval(self) -> tuple[int, ...]:
        """Steps a person must approve individually (replan, compensate, flag)."""
        return tuple(s.n for s in self.steps if s.op in ("replan", "compensate", "flag"))



