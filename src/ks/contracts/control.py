"""C4 Alert and Control.

An **Alert** is a detector's finding with evidence (record seqs and object versions). It never names
a culprit: ``root_candidates`` is a ranked list of agents that may have started the fault.
Anti-framing (D7) is enforced here: a signature alert names only the submitting **connection**;
tamper, witness-stall and reconcile alerts name nobody (tamper/stall freeze recovery by kind and are
never hard; reconcile is hard but, naming nobody, suspends nobody). The monitor also submits every alert
as a ``ks.alert`` envelope (``args = alert.to_obj()``) so the chain binds it (SEC-03 F6); ``alerts.jsonl``
is a convenience copy and FROZEN/TTI are derived from the chained records.

**Hard table (H3)**, enforced as ``hard == (detector in HARD_DETECTORS)``. Hard:
``inv.beneficiary_changed_then_paid``, ``inv.ledger_balance``, ``inv.iban_checksum``, ``inv.pii_egress``,
``scope``, ``reconcile``, ``sig`` (connection only). Soft: ``anomaly.price_vs_history``, ``rate``,
``barrier.deadline`` and every unlisted detector. Never hard: ``verify`` (tamper), ``witness_stall``.

A **Control** is a containment operation. It is a signed, recorded action (rule 10): a system
principal submits an envelope with ``tool == "ks.control"`` whose ``args`` are ``control.to_obj()``;
the record carries the Control in clear plus ``args_hash`` binding it. Controls are signed by the
issuing system principal (``issued_by == envelope.agent_id``, a Record validator), never by the
gateway key on another principal's behalf (K15).

**Epochs (D1).** Per-agent epochs start at 0 and are strictly monotonic: every agent ``suspend``,
``revoke`` and ``release`` sets an epoch greater than every earlier one for that agent. ``release`` sets a
*fresh* epoch and never reuses the pre-suspend one, so envelopes presigned before a suspension stay
``stale_epoch`` forever. ``ks verify`` folds Controls with :class:`EpochFold`.
"""

from __future__ import annotations

import re
from enum import StrEnum
from collections.abc import Iterable
from typing import Annotated, ClassVar, Literal

from pydantic import StringConstraints, field_validator, model_validator

from ._base import Document
from .hashing import Domain
from .ids import AgentId, ConnId, Epoch, PrincipalId, Seq, Tick, Token
from .state import ObjVer, _sorted_unique

__all__ = [
    "CONTROL_TOOL", "AlertKind", "HARD_ALLOWED", "HARD_DETECTORS", "DETECTOR_KIND", "Detector", "Alert",
    "ControlOp", "TargetKind", "TARGET_RE", "Target", "make_target", "parse_target", "Control", "EpochFold",
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


HARD_ALLOWED = frozenset({AlertKind.INVARIANT, AlertKind.SCOPE, AlertKind.RECONCILE, AlertKind.SIGNATURE})
"""Kinds that may be ``hard`` (auto-action). v1.1 (M7/N4): tamper and witness_stall are never hard;
the recovery freeze follows from their kind, not from ``hard``. Anomalies need one click."""

_NOBODY = frozenset({AlertKind.TAMPER, AlertKind.WITNESS_STALL, AlertKind.RECONCILE})


class Detector:
    """Well-known detector names (``Alert.detector``). The canonical spelling for each H3 row."""

    BENEFICIARY_CHANGED_THEN_PAID = "inv.beneficiary_changed_then_paid"
    LEDGER_BALANCE = "inv.ledger_balance"
    IBAN_CHECKSUM = "inv.iban_checksum"
    PII_EGRESS = "inv.pii_egress"
    SCOPE = "scope"
    RECONCILE = "reconcile"
    SIGNATURE = "sig"
    PRICE_VS_HISTORY = "anomaly.price_vs_history"
    RATE = "rate"
    BARRIER_DEADLINE = "barrier.deadline"
    TAMPER = "verify"
    WITNESS_STALL = "witness_stall"


HARD_DETECTORS = frozenset({Detector.BENEFICIARY_CHANGED_THEN_PAID, Detector.LEDGER_BALANCE,
                            Detector.IBAN_CHECKSUM, Detector.PII_EGRESS, Detector.SCOPE, Detector.RECONCILE,
                            Detector.SIGNATURE})
"""H3: an alert is hard **iff** its detector is in this set."""

DETECTOR_KIND = {
    Detector.BENEFICIARY_CHANGED_THEN_PAID: AlertKind.INVARIANT, Detector.LEDGER_BALANCE: AlertKind.INVARIANT,
    Detector.IBAN_CHECKSUM: AlertKind.INVARIANT, Detector.PII_EGRESS: AlertKind.INVARIANT,
    Detector.SCOPE: AlertKind.SCOPE, Detector.RECONCILE: AlertKind.RECONCILE, Detector.SIGNATURE: AlertKind.SIGNATURE,
    Detector.PRICE_VS_HISTORY: AlertKind.ANOMALY, Detector.RATE: AlertKind.RATE,
    Detector.BARRIER_DEADLINE: AlertKind.ANOMALY, Detector.TAMPER: AlertKind.TAMPER,
    Detector.WITNESS_STALL: AlertKind.WITNESS_STALL,
}
"""Kind each well-known detector must report."""


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
    """Hard evidence: containment may act automatically (suspend, never revoke). Exactly the H3 hard table."""
    evidence_seqs: tuple[Seq, ...]
    """Record seqs that are the evidence, ascending. Non-empty, except (M3) a ``barrier.deadline`` anomaly
    (a missed barrier is a no-op and has no record) and (K6) a ``reconcile`` alert for an off-log object
    with no recorded version (a row created by a bypass)."""
    evidence_versions: tuple[ObjVer, ...]
    """Object versions found bad (taint seeds), sorted by (obj, ver). For the beneficiary alert (H4): the payee
    field object only; the payment goes in ``evidence_seqs``."""
    root_candidates: tuple[AgentId, ...]
    """Ranked, most likely first. Not a verdict (M9/H1): ``root_candidates[0]`` is the attributed agent of the
    record(s) that wrote ``evidence_versions`` (write_set lookup); further candidates come from backward taint
    (bounded walk), ranked. If the evidence versions have two or more distinct writers, or none, automatic
    containment suspends nobody. Agents reached only through reads are never auto-suspended (H2). The
    *suspect* is derived as ``root_candidates[0]`` and is never stored. Empty for signature, tamper,
    witness-stall, reconcile and ``barrier.deadline`` alerts."""
    conn_id: ConnId | None
    """Connection named by the alert: required for signature alerts (the submitting connection, never the
    claimed agent); optional for ``barrier.deadline`` (the connection that missed the barrier; PMO S5);
    ``None`` for every other alert."""

    @field_validator("evidence_seqs")
    @classmethod
    def _seqs(cls, v):
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
        if not self.evidence_seqs and not (
                self.kind == AlertKind.RECONCILE
                or (self.kind == AlertKind.ANOMALY and self.detector == Detector.BARRIER_DEADLINE)):
            raise ValueError("evidence_seqs must be non-empty (except barrier.deadline anomalies and reconcile)")
        if self.hard and self.kind not in HARD_ALLOWED:
            raise ValueError(f"{self.kind} alerts cannot be hard")
        if self.hard != (self.detector in HARD_DETECTORS):
            raise ValueError(f"detector {self.detector!r} must be {'hard' if not self.hard else 'soft'} (H3)")
        want = DETECTOR_KIND.get(self.detector)
        if want is not None and self.kind != want:
            raise ValueError(f"detector {self.detector!r} reports kind {want}")
        if self.kind == AlertKind.SIGNATURE:
            if self.conn_id is None or self.root_candidates:
                raise ValueError("signature alerts name the connection only, never an agent")
        elif self.detector == Detector.BARRIER_DEADLINE:
            if self.root_candidates:  # PMO S5: names the connection that missed the barrier, never an agent
                raise ValueError("barrier.deadline alerts name a connection (conn_id), never an agent")
        elif self.conn_id is not None:
            raise ValueError("conn_id is only for signature and barrier.deadline alerts")
        if self.kind in _NOBODY and self.root_candidates:
            raise ValueError("tamper/witness-stall/reconcile alerts name nobody")
        return self


class ControlOp(StrEnum):
    SUSPEND = "suspend"   # stop an agent/connection now; sets a new (higher) epoch
    REVOKE = "revoke"     # permanent; only after human confirmation (ks.operator); sets a new epoch
    RELEASE = "release"   # active again at a FRESH epoch (never the pre-suspend one); lifts only the holds the
    #                       suspension caused; lineage_hold / sensitive_field holds survive (D4, K15)
    HOLD = "hold"         # hold on a queued action or outbox item (reason e.g. lineage_hold, sensitive_field)
    UNHOLD = "unhold"     # lift a hold; for action:<record_id> re-executes the held envelope (M10)


class TargetKind(StrEnum):
    AGENT = "agent"
    CONN = "conn"
    ACTION = "action"
    """id = record_id of the hold record. ``unhold action:<record_id>`` re-executes the held envelope (same
    ``envelope_hash``) through epoch/deny-list, classification, policy and taint in the current tick; nonce
    and expiry are not re-checked (they passed at admission). The new record sets ``reexec_of`` = the hold
    record's seq (M10). A policy-time hold is the ``hold/lineage_hold`` record itself; ``Control{hold}`` is only
    for items already queued when an alert lands. I2 approval = ``unhold action:<record_id>`` by ks.operator."""
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
    """``ks.monitor``/``ks.gateway`` if auto; ``ks.operator``/``ks.recovery`` if human-approved. Must equal the
    signing envelope's ``agent_id`` (Record validator)."""
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
        if self.op == ControlOp.REVOKE and (self.auto or self.issued_by != "ks.operator"):
            raise ValueError("revoke only after human confirmation (ks.operator, auto=false)")
        allowed = {"ks.monitor", "ks.gateway"} if self.auto else {"ks.operator", "ks.recovery"}
        if self.issued_by not in allowed:
            raise ValueError(f"{'auto' if self.auto else 'manual'} controls are issued by {sorted(allowed)}")
        return self


class EpochFold:
    """Fold of agent Controls in record order: current epoch and status per agent (D1, D3).

    Every agent starts ``active`` at epoch 0. ``apply`` raises ``ValueError`` when a suspend, revoke or
    release does not set an epoch strictly greater than every earlier epoch of that agent, or when a
    revoked agent is released (revoke is permanent). ``epoch(agent)`` is what ``TickFrame.epoch`` carries:
    the current epoch while active, ``None`` while suspended or revoked."""

    def __init__(self, agents: Iterable[str] = ()):
        self._max: dict[str, int] = {a: 0 for a in agents}
        self._status: dict[str, str] = {a: "active" for a in self._max}

    def apply(self, control: Control) -> None:
        kind, ident = parse_target(control.target)
        if kind != TargetKind.AGENT or control.op not in (ControlOp.SUSPEND, ControlOp.REVOKE, ControlOp.RELEASE):
            return
        assert control.epoch is not None  # Control validator guarantees it
        prev = self._max.get(ident, 0)
        if control.epoch <= prev:
            raise ValueError(f"epoch of {ident} not strictly monotonic: {control.epoch} <= {prev}")
        if self._status.get(ident) == "revoked":
            raise ValueError(f"{ident} is revoked; {control.op} after revoke")
        self._max[ident] = control.epoch
        self._status[ident] = {ControlOp.SUSPEND: "suspended", ControlOp.REVOKE: "revoked",
                               ControlOp.RELEASE: "active"}[control.op]

    def feed(self, controls: Iterable[Control]) -> EpochFold:
        for c in controls:
            self.apply(c)
        return self

    def status(self, agent: str) -> str:
        return self._status.get(agent, "active")

    def max_epoch(self, agent: str) -> int:
        return self._max.get(agent, 0)

    def epoch(self, agent: str) -> int | None:
        return self._max.get(agent, 0) if self.status(agent) == "active" else None
