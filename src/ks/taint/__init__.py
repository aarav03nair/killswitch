"""ks.taint: forward taint, the A8 seed rule and backward ranking from records only (ADR-05 §4-5). Owner: vikram.

Input is the chained C2 records (``read_set``/``write_set``/``outbox_ids``) and alert ``evidence_versions``.
Taint keys on ``(obj, ver)`` and never inspects a value (conservative, ADR-05 §2b). Field objects keep it
precise: a reader of ``suppliers:S-17`` that never read ``suppliers:S-17.iban`` is not tainted by an IBAN write.

A3 (TCB blind): this package never imports ``RunConfig`` and never reads ``fault``/``culprit``/``fault_tick``
(AST guard in ``tests/taint``). D-SEQ1: record seq 1 is the seed record; it is never tainted, never a root, and
the backward walk stops at its versions.
"""

from .closure import (MAX_HOPS, SEED_SEQ, RecordIndex, Taint, closure, is_seed_record, root_candidates,
                      seed_versions, suspend_seq_of, t0_seq_est, taint_from_alerts)

__all__ = ["MAX_HOPS", "SEED_SEQ", "RecordIndex", "Taint", "closure", "is_seed_record", "root_candidates",
           "seed_versions", "suspend_seq_of", "t0_seq_est", "taint_from_alerts"]
