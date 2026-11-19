"""State-transaction helpers for the gateway (steps 13-14)."""

from __future__ import annotations

from typing import Any

from ks.contracts import VersionRef, WriteEntry

__all__ = ["writes_at"]


def writes_at(store: Any, seq: int) -> tuple[WriteEntry, ...]:
    """The write set the store itself holds for record ``seq``, sorted by obj: the authority B3-41 compares a
    tool's self-reported ``write_set`` against. Call inside or after the txn that wrote ``seq``."""
    out = []
    for obj, ver, h in store.conn.execute("SELECT obj, ver, hash FROM versions WHERE seq = ? ORDER BY obj", (seq,)):
        prev = store.conn.execute("SELECT hash FROM versions WHERE obj = ? AND ver = ?", (obj, ver - 1)).fetchone()
        out.append(WriteEntry(obj=obj, before=None if prev is None else VersionRef(ver=ver - 1, hash=prev[0]),
                              after=VersionRef(ver=ver, hash=h)))
    return tuple(out)
