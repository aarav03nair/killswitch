"""ks.monitor: the ADR-04 detector catalogue, attribution and C4 alert construction (B3-07).

Pure functions over C2 records, a read-only :class:`~ks.contracts.StateView` and the side store. It never reads
``RunConfig`` (scorer-only ground truth) and never names a culprit from a detector: detect, then attribute.
"""

from .alerts import ALERT_TOOL, Monitor, alert_envelope, make_alert
from .attribute import attribute, containment_target, suspect, writers_of
from .detectors import (DETECTORS, barrier_deadline, beneficiary_changed_then_paid, find_pii, iban_checksum,
                        ledger_balance, pii_egress, price_vs_history, rate, reconcile, scope_breach, signature,
                        tamper, witness_stall)
from .ibanlib import iban_ok, iban_problem
from .model import BarrierMiss, Context, Finding, MonitorParams, RecordIndex, agent_of

__all__ = [
    "ALERT_TOOL", "Monitor", "alert_envelope", "make_alert", "attribute", "containment_target", "suspect",
    "writers_of", "DETECTORS", "barrier_deadline", "beneficiary_changed_then_paid", "find_pii", "iban_checksum",
    "ledger_balance", "pii_egress", "price_vs_history", "rate", "tamper", "reconcile", "scope_breach", "signature", "witness_stall",
    "iban_ok", "iban_problem", "BarrierMiss", "Context", "Finding", "MonitorParams", "RecordIndex", "agent_of",
]
