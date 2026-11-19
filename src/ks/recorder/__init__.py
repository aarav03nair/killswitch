"""ks.recorder: the hash-chained, gateway-signed ``record.jsonl`` and the side store (ADR-02 §1, §9).
Owner: arjun. Only the gateway process holds a Recorder (rule 8)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ks.contracts import GENESIS_HASH, Record, RunDir, SideDomain, SideEntry, record_id_for, sidestore_relpath

__all__ = ["Recorder"]


class Recorder:
    """Assigns ``seq``/``record_id``/``prev_hash``, seals, signs with the in-memory gateway key, appends."""

    def __init__(self, rundir: RunDir, gw_sign: Callable[[bytes], str]):
        self.rundir = rundir
        self._sign = gw_sign
        self.seq = 0
        """Seq of the last appended record (0 = none yet)."""
        self.head = GENESIS_HASH
        """Hash of the last appended record."""

    def append(self, **fields: Any) -> Record:
        """Append one record. ``fields`` are every Record field except seq, record_id, prev_hash, hash, gw_sig."""
        seq = self.seq + 1
        rec = Record.seal(prev_hash=self.head, seq=seq, record_id=record_id_for(seq), **fields)
        rec = rec.with_gw_sig(self._sign(rec.signing_bytes()))
        self.rundir.append(rec)
        self.seq, self.head = seq, rec.hash
        return rec

    def put_side(self, domain: SideDomain, h: str, value: Any) -> None:
        """Store the raw value behind a record hash (rule 9). Idempotent: same hash, same value."""
        if (self.rundir.path / sidestore_relpath(h)).exists():
            return
        self.rundir.write_side(SideEntry(hash=h, domain=domain, value=value, redacted=False))
