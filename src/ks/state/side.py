"""SQLite-backed :class:`~ks.contracts.SideStore` for state values, in the same ``state.db`` (ADR-05 §1).

``versions`` holds only ``(obj, ver, hash, author, seq, action_id)``; the value of every version lives
here, keyed by its value hash, so old values stay redactable (a redacted restore target gives ``flag``,
ADR-05 §6.2). Being a table in the store's own database, it commits and rolls back with the gateway's
``BEGIN IMMEDIATE`` transaction and with savepoints (dry-run simulation leaves nothing behind).

The run dir side store (``sidestore/xx/<hash>.json``, ADR-02, arjun) is still what records point at:
the gateway mirrors each committed ``WriteEntry.after`` value there via the recorder after commit.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from ks.contracts import SideDomain, SideEntry, canonical

__all__ = ["SqliteSideStore", "side_hash"]


def side_hash(domain: SideDomain, value: Any) -> str:
    """The hash :class:`SideEntry` expects for ``value`` in ``domain`` (one definition, in the contract)."""
    return SideEntry.model_construct(hash="", domain=SideDomain(domain), value=value, redacted=False).expected_hash()


class SqliteSideStore:
    """Rows ``side(hash PK, domain, value canonical-text | NULL, redacted)``. Idempotent puts."""

    def __init__(self, conn: sqlite3.Connection):
        self._c = conn

    def put(self, domain: SideDomain, value: Any) -> str:
        h = side_hash(domain, value)
        # Idempotent; a put of a value whose hash was redacted re-populates it (the value is live again,
        # so every version with that hash stays readable, consistent with the new head).
        self._c.execute("INSERT INTO side(hash, domain, value, redacted) VALUES (?, ?, ?, 0) "
                        "ON CONFLICT(hash) DO UPDATE SET value = excluded.value, redacted = 0 WHERE side.redacted = 1",
                        (h, SideDomain(domain).value, canonical.dumps(value).decode()))
        return h

    def get(self, h: str) -> SideEntry | None:
        row = self._c.execute("SELECT domain, value, redacted FROM side WHERE hash = ?", (h,)).fetchone()
        if row is None:
            return None
        domain, text, redacted = row
        if redacted:
            return SideEntry(hash=h, domain=SideDomain(domain), value=None, redacted=True)
        return SideEntry(hash=h, domain=SideDomain(domain), value=canonical.loads(text.encode()), redacted=False)

    def redact(self, h: str) -> None:
        """Erase the value, keep the hash. Also erases a head value with that hash (``objects.head_value``),
        so erasure is complete inside ``state.db``; the store then reports the head as redacted."""
        self._c.execute("UPDATE side SET value = NULL, redacted = 1 WHERE hash = ?", (h,))
        self._c.execute("UPDATE objects SET head_value = NULL, head_redacted = 1 WHERE head_hash = ?", (h,))
