"""C4 Alert and Control.

An **Alert** is a detector's finding with evidence (record seqs and object versions). It never names
a culprit: ``root_candidates`` is a ranked list of agents that may have started the fault.
Anti-framing (D7) is enforced here: a signature alert names only the submitting **connection**;
a tamper / witness-stall alert names nobody (it freezes recovery and suspends no agent).

A **Control** is a containment operation. It is a signed, recorded action (rule 10): a system
principal submits an envelope with ``tool == "ks.control"`` whose ``args`` are ``control.to_obj()``;
the record carries the Control in clear plus ``args_hash`` binding it.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, ClassVar, Literal

from pydantic import StringConstraints, field_validator, model_validator

from ._base import Document
from .hashing import Domain
from .ids import AgentId, ConnId, Epoch, PrincipalId, Seq, Tick, Token
from .state import ObjVer, _sorted_unique

__all__ = [
    "CONTROL_TOOL", "AlertKind", "HARD_ALLOWED", "Detector", "Alert", "ControlOp", "TargetKind",
    "TARGET_RE", "Target", "make_target", "parse_target", "Control",
]

CONTROL_TOOL = "ks.control"
"""Envelope tool name for every Control."""


class AlertKind(StrEnum):
    INVARIANT = "invariant"        # data invariant broken (e.g. IBAN checksum, beneficiary changed then paid)
    SCOPE = "scope"                # write outside the agent's scope
    RECONCILE = "reconcile"        # fold(record) != live state: unmediated write, class U
    SIGNATURE = "signature"        # bad/missing signature on a connection
    TAMPER = "tamper"              # record chain / signature / witness mismatch
    WITNESS_STALL = "witness_stall"  # witness head stopped advancing
    ANOMALY = "anomaly"            # statistical; never hard
    RATE = "rate"                  # rate/quota; never hard


HARD_ALLOWED = frozenset({AlertKind.INVARIANT, AlertKind.SCOPE, AlertKind.RECONCILE, AlertKind.SIGNATURE,
                          AlertKind.TAMPER, AlertKind.WITNESS_STALL})
"""Kinds that may be ``hard`` (auto-action). Anomalies need one click."""

_NOBODY = frozenset({AlertKind.TAMPER, AlertKind.WITNESS_STALL})


class Detector:
    """Well-known detector names (``Alert.detector``)."""

    RECONCILE = "reconcile"
    SIGNATURE = "sig"
    TAMPER = "verify"
    WITNESS_STALL = "witness_stall"


class Alert(Document):
    """C4 Alert, appended to ``alerts.jsonl`` in the run dir."""

    CONTRACT: ClassVar[str] = "ks.alert/1"
    DOMAIN: ClassVar[bytes] = Domain.ALERT

    contract: Literal["ks.alert/1"] = "ks.alert/1"
    """Contract id."""
    alert_id: Annotated[str, StringConstraints(strict=True, pattern=r"^a-[0-9]{6,16}$")]
    """Monitor-assigned, ``a-000001`` upward."""
    tick: Tick
    """Tick at which the alert was raised (TTI-detect input)."""
    seq: Seq
    """Highest record seq the detector had seen when it fired."""
    detector: Token
    """Rule id, e.g. ``inv.iban_checksum``, ``reconcile`` (``ks.alert.detector``)."""
    kind: AlertKind
    """Detector family; decides who may be named and whether ``hard`` is allowed."""
    hard: bool
    """Hard evidence: containment may act automatically (suspend, never revoke)."""
    evidence_seqs: tuple[Seq, ...]
    """Record seqs that are the evidence, ascending, non-empty."""
    evidence_versions: tuple[ObjVer, ...]
    """Object versions found bad (taint seeds), sorted by (obj, ver)."""
    root_candidates: tuple[AgentId, ...]
    """Ranked, most likely first. Not a verdict. Empty for signature/tamper/witness-stall alerts."""
    conn_id: ConnId | None
    """Submitting connection; set only for signature alerts (anti-framing: never the claimed agent)."""

    @field_validator("evidence_seqs")
    @classmethod
    def _seqs(cls, v):
        if not v:
            raise ValueError("evidence_seqs must be non-empty")
        return _sorted_unique(v, lambda s: s, "evidence seq")

    @field_validator("evidence_versions")
    @classmethod
    def _vers(cls, v):
        return _sorted_unique(v, lambda e: (e.obj, e.ver), "evidence version")

    @field_validator("root_candidates")
    @classmethod
    def _cands(cls, v):
        if len(set(v)) != len(v):
            raise ValueError("duplicate root candidate")
        return v  # order is meaningful (ranked)

    @model_validator(mode="after")
    def _rules(self) -> Alert:
        if self.hard and self.kind not in HARD_ALLOWED:
            raise ValueError(f"{self.kind} alerts cannot be hard")
        if self.kind == AlertKind.SIGNATURE:
            if self.conn_id is None or self.root_candidates:
                raise ValueError("signature alerts name the connection only, never an agent")
        elif self.conn_id is not None:
            raise ValueError("conn_id is only for signature alerts")
        if self.kind in _NOBODY and self.root_candidates:
            raise ValueError("tamper/witness alerts name nobody")
        return self


class ControlOp(StrEnum):
    SUSPEND = "suspend"   # stop an agent/connection now; bumps epoch
    REVOKE = "revoke"     # permanent; only after human confirmation
    RELEASE = "release"   # lift a suspension; restores (sets) the epoch
    HOLD = "hold"         # lineage hold on an action or outbox item
    UNHOLD = "unhold"     # lift a hold


class TargetKind(StrEnum):
    AGENT = "agent"
    CONN = "conn"
    ACTION = "action"     # id = record_id of the hold record
    OUTBOX = "outbox"     # id = outbox_id


TARGET_RE = r"^(agent:[a-z][a-z0-9_]{0,31}|conn:c-[0-9]{1,6}|action:r-[0-9]{6,16}|outbox:ob-[0-9]{6,16})$"
Target = Annotated[str, StringConstraints(strict=True, pattern=TARGET_RE)]
"""``agent:<agent_id>`` | ``conn:<conn_id>`` | ``action:<record_id>`` | ``outbox:<outbox_id>``."""

_TARGET = re.compile(TARGET_RE)
_OPS_FOR = {
    ControlOp.SUSPEND: {TargetKind.AGENT, TargetKind.CONN},
    ControlOp.REVOKE: {TargetKind.AGENT, TargetKind.CONN},
    ControlOp.RELEASE: {TargetKind.AGENT, TargetKind.CONN},
    ControlOp.HOLD: {TargetKind.ACTION, TargetKind.OUTBOX},
    ControlOp.UNHOLD: {TargetKind.ACTION, TargetKind.OUTBOX},
}


def make_target(kind: TargetKind | str, ident: str) -> str:
    t = f"{TargetKind(kind)}:{ident}"
    if not _TARGET.match(t):
        raise ValueError(f"invalid target {t!r}")
    return t


def parse_target(t: str) -> tuple[TargetKind, str]:
    if not _TARGET.match(t):
        raise ValueError(f"invalid target {t!r}")
    k, _, ident = t.partition(":")
    return TargetKind(k), ident


class Control(Document):
    """C4 Control: one containment operation, recorded in clear on its record."""

    CONTRACT: ClassVar[str] = "ks.control/1"
    DOMAIN: ClassVar[bytes] = Domain.CONTROL

    contract: Literal["ks.control/1"] = "ks.control/1"
    """Contract id."""
    control_id: Annotated[str, StringConstraints(strict=True, pattern=r"^k-[0-9]{6,16}$")]
    """Issuer-assigned id."""
    op: ControlOp
    """Operation (``ks.control.op``)."""
    target: Target
    """What it acts on: agent, connection, held action or outbox item (``ks.control.target``)."""
    epoch: Epoch | None
    """New epoch for agent targets of suspend/revoke/release; ``None`` otherwise."""
    alert_id: Annotated[str, StringConstraints(strict=True, pattern=r"^a-[0-9]{6,16}$")] | None
    """Alert that caused it, if any."""
    issued_by: PrincipalId
    """``ks.monitor``/``ks.gateway`` if auto; ``ks.console``/``ks.recovery`` if human-approved."""
    auto: bool
    """True if issued without a human click (hard alert). Revoke is never auto."""
    reason: Token
    """Short code, e.g. ``hard_alert``, ``operator``, ``bad_sig``."""

    @model_validator(mode="after")
    def _rules(self) -> Control:
        kind, _ = parse_target(self.target)
        if kind not in _OPS_FOR[self.op]:
            raise ValueError(f"{self.op} cannot target {kind}")
        needs_epoch = kind == TargetKind.AGENT and self.op in (ControlOp.SUSPEND, ControlOp.REVOKE,
                                                               ControlOp.RELEASE)
        if needs_epoch != (self.epoch is not None):
            raise ValueError("epoch is required exactly for agent suspend/revoke/release")
        if self.op == ControlOp.REVOKE and (self.auto or self.issued_by != "ks.console"):
            raise ValueError("revoke only after human confirmation (ks.console, auto=false)")
        allowed = {"ks.monitor", "ks.gateway"} if self.auto else {"ks.console", "ks.recovery"}
        if self.issued_by not in allowed:
            raise ValueError(f"{'auto' if self.auto else 'manual'} controls are issued by {sorted(allowed)}")
        return self
