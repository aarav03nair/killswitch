"""ks.contracts: frozen contracts C1-C6 (CON-01, v1.1 CON-02, v1.2 B3-01, v1.3 B3-43, v1.4 B3-46). Import from here, not from submodules.

C1 Envelope · C2 Record + WitnessCheckpoint · C3 State API + values + side store ·
C4 Alert + Control · C5 RecoveryPlan · C6 RunConfig + Keyring + RunDir + verify Exit · transport frames.
The single canonical serializer is :mod:`ks.contracts.canonical` (``canonical.dumps`` / ``canonical.loads``).
"""

from . import canonical
from .canonical import MAX_DEPTH, CanonicalError, ContractError, NonCanonicalError
from .control import (CONTROL_TOOL, DETECTOR_KIND, HARD_ALLOWED, HARD_DETECTORS, Alert, AlertKind, Control,
                      ControlOp, Detector, EpochFold, TargetKind, make_target, parse_target)
from .envelope import MAX_ACT_DEPTH, MAX_EXPIRY_TICKS, ActLink, Envelope, EnvelopeHeader, expiry_ok
from .hashing import (GENESIS_HASH, TOMBSTONE_HASH, Domain, args_hash, raw_hash, result_hash, sha256_hex,
                      tagged_hash, value_hash)
from .ids import (RECOVER_TOOL_PREFIX, SEED_TOOL, SYSTEM_CONN, SYSTEM_PRINCIPALS, SYSTEM_TOOLS, record_id_for,
                  system_tool_signers)
from .record import (REASONS_FOR, ActionClass, Decision, Reason, Record, WitnessCheckpoint, determinism_view,
                     witness_chain_problems)
from .recovery import (APPROVE_TOOL, ActionRef, Approval, CancelOutboxStep, CompensateStep, DiffEntry, FlagStep,
                       RecoverArgs, RecoveryPlan, ReplanStep, RerunStep, RestoreStep, StepOp, TaintSet, recover_tool)
from .rundir import (BASELINES_DIR, DETERMINISTIC_FILES, NO_LINEAGE_HOLD_BANNER, PROJECTED_FILES, SCORER_ONLY_FIELDS, VERIFY_REASONS,
                     WITNESS_HEADS_DIR, Exit, Isolation, KeyEntry, Keyring, RunAnchor, RunConfig, RunDir,
                     VerifyReport, anchor_status, sidestore_relpath)
from .state import (READ_SOURCES, HistoryEntry, ObjVer, OutboxItem, OutboxStatus, ReadEntry, ReadSource, SideDomain,
                    SideEntry, SideStore, StateRead, StateView, StateWriter, VersionRef, ViewEntry, WriteEntry,
                    check_read_set, field_obj_id, idempotency_key, is_field_obj, make_obj_id, merge_read_set,
                    row_obj_id, split_obj_id, state_digest)
from .transport import (MAX_FRAME_BYTES, MAX_SIGN_PER_TICK, MAX_VIEW_ENTRIES, SIGN_REFUSAL_REASONS,
                        WITNESS_FILES_FDS, NoopFrame, ReplyFrame, SignRefusal, SignReply, SignRequest, SubmitFrame,
                        TickFrame, WitnessClose, WitnessFiles, WitnessHead, WitnessInit, WitnessPub, WitnessReady,
                        decode_frame, decode_witness_frame, encode_frame, signer_refusal)

CONTRACTS_VERSION = "1.6.0"
"""Contract version. 1.1.0 = CON-02 design freeze (CALL-02); 1.2.0 = B3-01, additive (witness link frames,
SignRefusal, RunConfig.isolation/decisions_from, VerifyReport.isolation, reexec_invalid); 1.3.0 = B3-43, additive
(``ks.seed`` system tool per D-15, deny reason ``tool_error``, verify reason ``seed_invalid``); 1.4.0 = B3-46,
additive (``ReadEntry.source`` view|tool, read_set keyed by (obj, ver), ``RestoreStep.to`` may be ``None``,
``RecoveryPlan.t0_seq_est_literal``); 1.5.0 = B3-47, additive (verify reason ``replay_mismatch``); 1.6.0 = B3-51,
additive (``RunConfig.lineage_hold``, ``VerifyReport.lineage_hold``: the D10 no-lineage-hold contrast run); see README
changelog. Any change to fields, patterns, canonical rules or domain tags bumps it, regenerates ``schema/``
and re-pins golden hashes."""

DOCUMENTS = {
    "c1.envelope": Envelope, "c1.envelope_header": EnvelopeHeader,
    "c2.record": Record, "c2.witness_checkpoint": WitnessCheckpoint,
    "c3.outbox_item": OutboxItem, "c3.side_entry": SideEntry, "c3.history_entry": HistoryEntry,
    "c3.state_read": StateRead,
    "c4.alert": Alert, "c4.control": Control,
    "c5.recovery_plan": RecoveryPlan, "c5.approval": Approval, "c5.recover_args": RecoverArgs,
    "c6.run_config": RunConfig, "c6.keyring": Keyring, "c6.verify_report": VerifyReport,
    "c6.run_anchor": RunAnchor,
}
"""Schema name -> type; one JSON Schema file per entry in ``schema/``."""

__all__ = [
    "CONTRACTS_VERSION", "DOCUMENTS", "canonical", "CanonicalError", "NonCanonicalError", "ContractError",
    "MAX_DEPTH",
    # hashing / ids
    "Domain", "GENESIS_HASH", "TOMBSTONE_HASH", "sha256_hex", "tagged_hash", "value_hash", "args_hash",
    "result_hash", "raw_hash", "record_id_for", "SYSTEM_PRINCIPALS", "SYSTEM_CONN", "SYSTEM_TOOLS", "SEED_TOOL",
    "RECOVER_TOOL_PREFIX", "system_tool_signers",
    # C1
    "Envelope", "EnvelopeHeader", "ActLink", "MAX_ACT_DEPTH", "MAX_EXPIRY_TICKS", "expiry_ok",
    # C2
    "Record", "WitnessCheckpoint", "Decision", "Reason", "REASONS_FOR", "ActionClass", "determinism_view",
    "witness_chain_problems",
    # C3
    "ObjVer", "VersionRef", "ReadEntry", "ViewEntry", "WriteEntry", "StateRead", "HistoryEntry", "OutboxItem",
    "OutboxStatus", "SideEntry", "SideDomain", "StateView", "StateWriter", "SideStore", "make_obj_id",
    "field_obj_id", "row_obj_id", "split_obj_id", "is_field_obj", "state_digest", "idempotency_key",
    "ReadSource", "READ_SOURCES", "check_read_set", "merge_read_set",
    # C4
    "Alert", "AlertKind", "HARD_ALLOWED", "HARD_DETECTORS", "DETECTOR_KIND", "Detector", "Control", "ControlOp",
    "TargetKind", "make_target", "parse_target", "CONTROL_TOOL", "EpochFold",
    # C5
    "RecoveryPlan", "TaintSet", "ActionRef", "DiffEntry", "StepOp", "RestoreStep", "RerunStep", "ReplanStep",
    "CancelOutboxStep", "CompensateStep", "FlagStep", "APPROVE_TOOL", "Approval", "RecoverArgs", "recover_tool",
    # C6
    "RunConfig", "Keyring", "KeyEntry", "RunDir", "Exit", "VerifyReport", "VERIFY_REASONS", "RunAnchor", "Isolation",
    "anchor_status", "DETERMINISTIC_FILES", "PROJECTED_FILES", "SCORER_ONLY_FIELDS", "WITNESS_HEADS_DIR",
    "NO_LINEAGE_HOLD_BANNER",
    "BASELINES_DIR", "sidestore_relpath",
    # transport
    "TickFrame", "SubmitFrame", "NoopFrame", "ReplyFrame", "SignRequest", "SignReply", "encode_frame",
    "decode_frame", "signer_refusal", "MAX_FRAME_BYTES", "MAX_VIEW_ENTRIES", "MAX_SIGN_PER_TICK",
    "SignRefusal", "SIGN_REFUSAL_REASONS",
    # transport: witness link (v1.2)
    "WitnessInit", "WitnessPub", "WitnessFiles", "WitnessReady", "WitnessHead", "WitnessClose",
    "decode_witness_frame", "WITNESS_FILES_FDS",
]
