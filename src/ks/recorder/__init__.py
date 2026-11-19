"""ks.recorder: the hash-chained, gateway-signed ``record.jsonl`` and the side store (ADR-02 §1, §9).
Owner: arjun. Only the gateway process holds a Recorder (rule 8).

Txn semantics (ADR-02 §1, B3-09): ``seq`` is taken at the **start** of the write txn (:meth:`Recorder.begin`),
the record is appended **after** the state commit. A crash between commit and append leaves state with a write
no record explains: the process is gone (a failed append aborts the recorder for good), and ``ks verify``
reports ``RECONCILE`` (``state_digest(fold(record))`` differs from ``state.db``): never silent.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ks.contracts import GENESIS_HASH, Record, RunDir, SideDomain, SideEntry, record_id_for, sidestore_relpath

from .hooks import GatewayHooks

__all__ = ["Recorder", "RecorderAborted", "RecorderTxn", "GatewayHooks"]


class RecorderAborted(RuntimeError):
    """The recorder cannot be trusted any more (append failed after a commit, or a txn protocol error); the run
    must stop. Verify then reports RECONCILE if state was committed without its record."""


class RecorderTxn:
    """One reserved seq. ``append`` it after the state commit, or ``rollback`` if nothing was committed."""

    def __init__(self, rec: Recorder, seq: int):
        self._rec, self.seq, self._open = rec, seq, True

    def append(self, **fields: Any) -> Record:
        if not self._open:
            raise RecorderAborted(f"txn seq {self.seq} already closed")
        self._open = False
        return self._rec._append(self.seq, fields)

    def rollback(self) -> None:
        """State txn rolled back: the seq was never used, release it (no gap in the record)."""
        if self._open:
            self._open = False
            self._rec._release(self.seq)


class Recorder:
    """Assigns ``seq``/``record_id``/``prev_hash``, seals, signs with the in-memory gateway key, appends."""

    def __init__(self, rundir: RunDir, gw_sign: Callable[[bytes], str]):
        self.rundir = rundir
        self._sign = gw_sign
        self.seq = 0
        """Seq of the last appended record (0 = none yet)."""
        self.head = GENESIS_HASH
        """Hash of the last appended record."""
        self.aborted = False
        self._reserved: int | None = None

    def begin(self) -> RecorderTxn:
        """Start a write txn: reserve the next seq (the state txn writes under it). One open txn at a time."""
        if self.aborted:
            raise RecorderAborted("recorder aborted")
        if self._reserved is not None:
            raise RecorderAborted(f"seq {self._reserved} is reserved and neither appended nor rolled back")
        self._reserved = self.seq + 1
        return RecorderTxn(self, self._reserved)

    def append(self, **fields: Any) -> Record:
        """Append one record with no state txn (denials, no-ops): ``begin`` + ``append``. ``fields`` are every
        Record field except seq, record_id, prev_hash, hash, gw_sig."""
        return self.begin().append(**fields)

    def _release(self, seq: int) -> None:
        if self._reserved == seq:
            self._reserved = None

    def _append(self, seq: int, fields: dict[str, Any]) -> Record:
        if self.aborted or self._reserved != seq:
            raise RecorderAborted("append without a reserved seq")
        try:
            rec = Record.seal(prev_hash=self.head, seq=seq, record_id=record_id_for(seq), **fields)
            rec = rec.with_gw_sig(self._sign(rec.signing_bytes()))
            self.rundir.append(rec)
        except BaseException:
            # state may already be committed under `seq`: never retry, never reuse the seq. The run stops here.
            self.aborted = True
            self._reserved = None
            raise
        self.seq, self.head, self._reserved = seq, rec.hash, None
        return rec

    def put_side(self, domain: SideDomain, h: str, value: Any) -> None:
        """Store the raw value behind a record hash (rule 9). Idempotent: same hash, same value."""
        if (self.rundir.path / sidestore_relpath(h)).exists():
            return
        self.rundir.write_side(SideEntry(hash=h, domain=domain, value=value, redacted=False))
