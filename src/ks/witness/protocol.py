"""Gateway <-> witness link (ADR-00 "Witness cadence", ADR-02 §3). Since contracts 1.2 the frames are contract
types in ``ks.contracts`` (``WitnessInit/Pub/Files/Ready/Head/Close``, decoded with ``decode_witness_frame``);
the ack is the signed ``WitnessCheckpoint`` line. See ``ks.contracts.transport`` for the sequence. This
module keeps only the witness's private constants."""

from __future__ import annotations

__all__ = ["HEADS_FILE"]

HEADS_FILE = "heads.jsonl"
"""The witness's private head store inside ``witness-heads/`` (0700, witness uid)."""
