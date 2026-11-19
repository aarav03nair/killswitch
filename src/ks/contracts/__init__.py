"""ks.contracts: frozen contracts C1-C6 (CON-01). Import from here, not from submodules.

C1 Envelope · C2 Record + WitnessCheckpoint · C3 State API + values + side store ·
C4 Alert + Control · C5 RecoveryPlan · C6 RunConfig + Keyring + RunDir + verify Exit · transport frames.
The single canonical serializer is :mod:`ks.contracts.canonical` (``canonical.dumps`` / ``canonical.loads``).
"""

from . import canonical
from .canonical import CanonicalError, NonCanonicalError
from .control import (CONTROL_TOOL, HARD_ALLOWED, Alert, AlertKind, Control, ControlOp, Detector, TargetKind,
                      make_target, parse_target)
from .envelope import MAX_ACT_DEPTH, ActLink, Envelope, EnvelopeHeader
from .hashing import (GENESIS_HASH, TOMBSTONE_HASH, Domain, args_hash, raw_hash, result_hash, sha256_hex,
                      tagged_hash, value_hash)
from .ids import SYSTEM_PRINCIPALS, record_id_for
from .record import REASONS_FOR, ActionClass, Decision, Reason, Record, WitnessCheckpoint
from .recovery import (ActionRef, CancelOutboxStep, CompensateStep, DiffEntry, FlagStep, RecoveryPlan,
                       ReplanStep, RerunStep, RestoreStep, StepOp, TaintSet)
from .rundir import DETERMINISTIC_FILES, Exit, KeyEntry, Keyring, RunConfig, RunDir, VerifyReport, sidestore_relpath
from .state import (HistoryEntry, ObjVer, OutboxItem, OutboxStatus, ReadEntry, SideDomain, SideEntry, SideStore,
                    StateRead, StateView, StateWriter, VersionRef, WriteEntry, idempotency_key, make_obj_id,
                    split_obj_id, state_digest)
from .transport import (MAX_FRAME_BYTES, NoopFrame, ReplyFrame, SignReply, SignRequest, SubmitFrame, TickFrame,
                        decode_frame, encode_frame)

CONTRACTS_VERSION = "1.0.0"
"""Bump the major on any change to fields, patterns, canonical rules or domain tags."""

DOCUMENTS = {
    "c1.envelope": Envelope, "c1.envelope_header": EnvelopeHeader,
    "c2.record": Record, "c2.witness_checkpoint": WitnessCheckpoint,
    "c3.outbox_item": OutboxItem, "c3.side_entry": SideEntry, "c3.history_entry": HistoryEntry,
    "c3.state_read": StateRead,
    "c4.alert": Alert, "c4.control": Control,
    "c5.recovery_plan": RecoveryPlan,
    "c6.run_config": RunConfig, "c6.keyring": Keyring, "c6.verify_report": VerifyReport,
}
"""Schema name -> type; one JSON Schema file per entry in ``schema/``."""

__all__ = [
    "CONTRACTS_VERSION", "DOCUMENTS", "canonical", "CanonicalError", "NonCanonicalError",
    # hashing
    "Domain", "GENESIS_HASH", "TOMBSTONE_HASH", "sha256_hex", "tagged_hash", "value_hash", "args_hash",
    "result_hash", "raw_hash", "record_id_for", "SYSTEM_PRINCIPALS",
    # C1
    "Envelope", "EnvelopeHeader", "ActLink", "MAX_ACT_DEPTH",
    # C2
    "Record", "WitnessCheckpoint", "Decision", "Reason", "REASONS_FOR", "ActionClass",
    # C3
    "ObjVer", "VersionRef", "ReadEntry", "WriteEntry", "StateRead", "HistoryEntry", "OutboxItem", "OutboxStatus",
    "SideEntry", "SideDomain", "StateView", "StateWriter", "SideStore", "make_obj_id", "split_obj_id",
    "state_digest", "idempotency_key",
    # C4
    "Alert", "AlertKind", "HARD_ALLOWED", "Detector", "Control", "ControlOp", "TargetKind", "make_target",
    "parse_target", "CONTROL_TOOL",
    # C5
    "RecoveryPlan", "TaintSet", "ActionRef", "DiffEntry", "StepOp", "RestoreStep", "RerunStep", "ReplanStep",
    "CancelOutboxStep", "CompensateStep", "FlagStep",
    # C6
    "RunConfig", "Keyring", "KeyEntry", "RunDir", "Exit", "VerifyReport", "DETERMINISTIC_FILES", "sidestore_relpath",
    # transport
    "TickFrame", "SubmitFrame", "NoopFrame", "ReplyFrame", "SignRequest", "SignReply", "encode_frame",
    "decode_frame", "MAX_FRAME_BYTES",
]
