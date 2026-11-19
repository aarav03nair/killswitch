"""C5 RecoveryPlan: taint set, ordered steps, and a hash-only dry-run diff.

A **taint-scoped revert** is the set of ``restore`` steps in a plan: each restores one object (row or
field object) to a pre-taint version, and only if the object is still at the culprit's after-version
(write-write conflict rule; otherwise the planner emits ``flag``). There is no restore over a tainted
head (B6; the 1.0 draft "M13" is dropped). Restores append a new version; history is never edited.

**Approval binding (G6, SEC-03 F5).** The operator approves a plan with a recorded ``ks.approve`` envelope
(signed by ``ks.operator``) whose args are :class:`Approval` ``{plan_id, plan_hash, steps}``, ``plan_hash`` =
:meth:`RecoveryPlan.content_hash`. Every step then runs as a ``ks.recover.<op>`` envelope signed by
``ks.recovery`` with args :class:`RecoverArgs` ``{plan_id, plan_hash, n, step}``; verify checks each against a
prior approval that lists ``n`` and against the plan file's hash. A step whose ``expect`` is no longer the
head is ``hold/stale_plan`` (M8); the plan must be recomputed. Plan approval blocks the tick barrier:
tick ``plan_tick + decision_latency_ticks`` does not open until the decision arrives (C1).

**Freeze (M12, F5).** ``ks recover`` (dry-run or apply) runs ``verify`` first. Exit is FROZEN if verify != OK
**or** a tamper/witness-stall alert is open in the (chained ``ks.alert``) records. A freeze lasts for the
rest of the run; v1 has no resolve action. Recovery envelopes are ``deny/recovery_frozen`` meanwhile.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Union

from pydantic import Field, StringConstraints, field_validator, model_validator

from .ids import RECOVER_TOOL_PREFIX

from ._base import Document, Value, additive
from .hashing import Domain
from .ids import ActionId, AgentId, Hash, PrincipalId, Seq, Token
from .state import ObjId, ObjVer, VersionRef, _sorted_unique

__all__ = [
    "StepOp", "RestoreStep", "RerunStep", "ReplanStep", "CancelOutboxStep", "CompensateStep", "FlagStep",
    "Step", "ActionRef", "TaintSet", "DiffEntry", "RecoveryPlan", "APPROVE_TOOL", "Approval", "RecoverArgs",
    "recover_tool",
]

APPROVE_TOOL = "ks.approve"
"""Envelope tool of a plan approval; signed by ``ks.operator`` on ``c-0``."""

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
    """The culprit's after-version (B6). Must still be the head, otherwise the step fails closed
    (``hold/stale_plan``); an honest later write makes it a ``flag`` at plan time instead."""
    to: VersionRef | None
    """Pre-taint version whose value is re-written (value from the side store). v1.4 (B3-46): ``None`` = the
    culprit **created** the object (no pre-taint version), so the restore writes a tombstone (delete, value
    ``null``, ``TOMBSTONE_HASH``) as a new version. Replaces the 1.3 planner marker
    ``to=VersionRef(ver=expect.ver, hash=TOMBSTONE_HASH)``."""

    @property
    def to_absent(self) -> bool:
        """True iff this restore deletes a culprit-created object (``to is None``)."""
        return self.to is None


class RerunStep(_Step):
    """Re-execute a deterministic honest action on repaired state; outbox dedupes on idempotency_key (M14).

    Executes the original tool and args (side store, ARGS domain) for ``action.agent_id``/``action_id``.
    Idempotency keys derive from those, not from the ``ks.recovery`` envelope, so a re-run payment updates
    the same ``outbox:<id>`` (v+1, back on hold). ``OutboxItem.author`` stays the original agent.
    Redacted args make the step a ``flag``."""

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
    t0_seq_est: Seq
    """Estimated first tainted seq (A2, X3): the earliest write by ``culprit`` in the bounded backward closure
    of the alerts' ``evidence_versions``. An estimate from the record only; the planner never reads
    ``RunConfig.fault_tick`` (scorer-only). Taint seed (A8): every culprit write in [t0_seq_est, suspend]. The walk
    follows the culprit's reads of its own versions only through ``tool`` read entries (B3-45 option C, v1.4)."""
    t0_seq_est_literal: Seq | None = additive(None)
    """v1.4 (B3-46, replaces the planner-side ``Planned.t0_delta``): t0 of the literal ADR-05 §4 walk, which also
    follows the culprit's ``view`` self-reads. ``<= t0_seq_est``; the dry-run reports the difference (suspect
    writes the seed leaves out). ``None`` = not computed."""
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
        if self.t0_seq_est > self.as_of_seq:
            raise ValueError("t0_seq_est must be <= as_of_seq")
        if self.t0_seq_est_literal is not None and self.t0_seq_est_literal > self.t0_seq_est:
            raise ValueError("t0_seq_est_literal must be <= t0_seq_est (the literal walk follows more reads)")
        return self

    @property
    def t0_delta(self) -> int | None:
        """``t0_seq_est - t0_seq_est_literal`` (>= 0), or ``None`` when the literal t0 is not set."""
        return None if self.t0_seq_est_literal is None else self.t0_seq_est - self.t0_seq_est_literal

    def approval(self, steps: tuple[int, ...] | None = None) -> Approval:
        """The ``ks.approve`` args binding this plan (all steps by default)."""
        return Approval(plan_id=self.plan_id, plan_hash=self.content_hash(),
                        steps=tuple(range(len(self.steps))) if steps is None else tuple(steps))

    def recover_args(self, n: int) -> RecoverArgs:
        """The ``ks.recover.<op>`` args for step ``n``; the envelope tool is ``recover_tool(step.op)``."""
        return RecoverArgs(plan_id=self.plan_id, plan_hash=self.content_hash(), n=n, step=self.steps[n])

    @property
    def needs_approval(self) -> tuple[int, ...]:
        """Steps a person must approve individually (replan, compensate, flag)."""
        return tuple(s.n for s in self.steps if s.op in ("replan", "compensate", "flag"))





def recover_tool(op: StepOp | str) -> str:
    """``ks.recover.<op>``."""
    return RECOVER_TOOL_PREFIX + StepOp(op).value


class Approval(Value):
    """Args of a ``ks.approve`` envelope (G6): the operator approves these steps of exactly this plan."""

    plan_id: Annotated[str, StringConstraints(strict=True, pattern=r"^p-[0-9]{6,16}$")]
    """Plan approved."""
    plan_hash: Hash
    """``RecoveryPlan.content_hash()`` of the approved plan file."""
    steps: tuple[Annotated[int, Field(strict=True, ge=0)], ...]
    """Step numbers approved, ascending, unique."""

    @field_validator("steps")
    @classmethod
    def _s(cls, v):
        return _sorted_unique(v, lambda n: n, "approved step")


class RecoverArgs(Value):
    """Args of a ``ks.recover.<op>`` envelope: one step of an approved plan (G6)."""

    plan_id: Annotated[str, StringConstraints(strict=True, pattern=r"^p-[0-9]{6,16}$")]
    """Plan the step belongs to."""
    plan_hash: Hash
    """Must equal the approved ``plan_hash``."""
    n: Annotated[int, Field(strict=True, ge=0)]
    """Step number; must be listed in the approval."""
    step: Step
    """The step itself, identical to ``plan.steps[n]``."""

    @model_validator(mode="after")
    def _n(self) -> RecoverArgs:
        if self.step.n != self.n:
            raise ValueError("step.n must equal n")
        return self
