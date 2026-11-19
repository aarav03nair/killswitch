"""ks.state: the versioned object store (ADR-05 §1-2, C3 M11). Owner: vikram.

Layout of ``workspace/state.db`` (0600, gateway uid):

* ``objects(obj PK, head_ver, head_hash, head_value, head_redacted)``: the current head of every object;
* ``versions(obj, ver, hash, author, seq, action_id)``: **append-only** (triggers abort UPDATE/DELETE),
  one row per write, PK ``(obj, ver)``;
* ``side(hash PK, domain, value, redacted)``: the value of every version, by value hash (redactable);
* ``meta(k PK, v)``: schema version.

Conventions (M11). ``ver`` starts at 1 and is ``before.ver + 1`` per write. (a) A delete writes a tombstone
(value ``None``, ``TOMBSTONE_HASH``); a re-create continues the counter. (b) A restore writes a **new**
version (author ``ks.recovery``), never rewinds. (c) A version written at seq *s* is visible only to seq > *s*
(``visible_to=``). Seq is the gateway's global record seq: writes arrive in seq order, one write per object
per action.

Transactions (ADR-03 §1.8, CALL-02 G5). The store never opens or commits a transaction around a write: the
gateway owns ``BEGIN IMMEDIATE``, takes ``seq`` first, re-checks epoch and the deny-list, then calls
:meth:`Store.put`, then commits and appends the record. ``put`` refuses to run outside a transaction, so
a write can never autocommit on its own. :meth:`Store.txn` is a convenience wrapper with the same shape.
Savepoints for dry-run simulation are B3-04.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ks.contracts import (
    TOMBSTONE_HASH,
    HistoryEntry,
    SideDomain,
    StateRead,
    VersionRef,
    WriteEntry,
    canonical,
    split_obj_id,
    value_hash,
)

from .fields import FieldSchema
from .side import SqliteSideStore

__all__ = [
    "RECOVERY_AUTHOR",
    "SCHEMA_VERSION",
    "NotInTransaction",
    "RedactedValue",
    "SeqOrderError",
    "StaleExpect",
    "StateError",
    "Store",
    "open_store",
]

SCHEMA_VERSION = "ks.state/1"
RECOVERY_AUTHOR = "ks.recovery"
DB_MODE = 0o600

_DDL = (
    """CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS objects(
        obj TEXT PRIMARY KEY,
        head_ver INTEGER NOT NULL CHECK (head_ver >= 1),
        head_hash TEXT NOT NULL,
        head_value TEXT,
        head_redacted INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS versions(
        obj TEXT NOT NULL,
        ver INTEGER NOT NULL CHECK (ver >= 1),
        hash TEXT NOT NULL,
        author TEXT NOT NULL,
        seq INTEGER NOT NULL CHECK (seq >= 1),
        action_id TEXT NOT NULL,
        PRIMARY KEY (obj, ver)) WITHOUT ROWID""",
    """CREATE INDEX IF NOT EXISTS versions_seq ON versions(seq)""",
    """CREATE TABLE IF NOT EXISTS side(
        hash TEXT PRIMARY KEY,
        domain TEXT NOT NULL,
        value TEXT,
        redacted INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID""",
    """CREATE TRIGGER IF NOT EXISTS versions_no_update BEFORE UPDATE ON versions
        BEGIN SELECT RAISE(ABORT, 'versions is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS versions_no_delete BEFORE DELETE ON versions
        BEGIN SELECT RAISE(ABORT, 'versions is append-only'); END""",
)


class StateError(Exception):
    """A write the store refuses (the gateway's adapter call fails closed)."""


class NotInTransaction(StateError):
    """``put`` outside the caller's ``BEGIN IMMEDIATE`` transaction."""


class SeqOrderError(StateError):
    """``seq`` behind the store, or a second write to one object by one action (same seq)."""


class StaleExpect(StateError):
    """Restore ``expect`` is no longer the head (B6/M8: the gateway records ``hold/stale_plan``)."""


class RedactedValue(StateError):
    """The value of that version was erased; only its hash remains."""


def _text(value: Any) -> str:
    return canonical.dumps(value).decode()


def _value(text: str) -> Any:
    return canonical.loads(text.encode())


class Store:
    """Implements C3 :class:`~ks.contracts.StateView` and :class:`~ks.contracts.StateWriter`; ``side`` is
    a C3 :class:`~ks.contracts.SideStore`. Wraps a connection opened with ``isolation_level=None``."""

    def __init__(self, conn: sqlite3.Connection, fields: FieldSchema | None = None):
        if conn.isolation_level is not None:
            raise StateError("connection must use isolation_level=None (the caller issues BEGIN IMMEDIATE)")
        self.conn = conn
        self.fields = fields if fields is not None else FieldSchema()
        self.side = SqliteSideStore(conn)
        for stmt in _DDL:
            conn.execute(stmt)
        row = conn.execute("SELECT v FROM meta WHERE k = 'schema'").fetchone()
        if row is None:
            conn.execute("INSERT INTO meta(k, v) VALUES ('schema', ?)", (SCHEMA_VERSION,))
        elif row[0] != SCHEMA_VERSION:
            raise StateError(f"state.db schema {row[0]!r}, expected {SCHEMA_VERSION!r}")

    def close(self) -> None:
        self.conn.close()

    # --- transactions ----------------------------------------------------------------------------
    @contextmanager
    def txn(self) -> Iterator[Store]:
        """``BEGIN IMMEDIATE`` ... ``COMMIT`` (``ROLLBACK`` on any exception). The gateway may instead issue
        the statements itself on ``self.conn``; the store only requires that a transaction is open."""
        if self.conn.in_transaction:
            raise StateError("transaction already open (nesting is a savepoint, B3-04)")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    # --- StateView -------------------------------------------------------------------------------
    def get(self, obj: str, *, visible_to: int | None = None) -> StateRead | None:
        """Current ``(value, ver, author)``; a tombstone has ``value=None``. ``None`` if the object never
        existed. With ``visible_to=r``: the latest version written at seq < r (M11c), or ``None``."""
        split_obj_id(obj)
        head = self.conn.execute("SELECT head_ver, head_hash, head_value, head_redacted FROM objects WHERE obj = ?",
                                 (obj,)).fetchone()
        if head is None:
            return None
        if visible_to is None:
            ver, h = head[0], head[1]
        else:
            row = self.conn.execute("SELECT ver, hash FROM versions WHERE obj = ? AND seq < ? "
                                    "ORDER BY ver DESC LIMIT 1", (obj, visible_to)).fetchone()
            if row is None:
                return None
            ver, h = row
        if ver == head[0]:
            if head[3]:
                raise RedactedValue(f"{obj} v{ver} is redacted")
            value = None if head[1] == TOMBSTONE_HASH else _value(head[2])
        else:
            value = self.value_at(obj, ver)
        author = self.conn.execute("SELECT author FROM versions WHERE obj = ? AND ver = ?", (obj, ver)).fetchone()[0]
        return StateRead(obj=obj, value=value, ver=ver, author=author, hash=h)

    def history(self, obj: str, *, visible_to: int | None = None) -> tuple[HistoryEntry, ...]:
        """Every version of ``obj``, oldest first (only those written at seq < ``visible_to`` if given)."""
        split_obj_id(obj)
        q = "SELECT ver, hash, author, seq, action_id FROM versions WHERE obj = ?"
        args: tuple = (obj,)
        if visible_to is not None:
            q, args = q + " AND seq < ?", (obj, visible_to)
        rows = self.conn.execute(q + " ORDER BY ver", args).fetchall()
        return tuple(HistoryEntry(obj=obj, ver=v, hash=h, author=a, seq=s, action_id=act) for v, h, a, s, act in rows)

    def heads(self, *, visible_to: int | None = None) -> dict[str, VersionRef]:
        """Head version of every object, tombstones included (``state_digest`` input), sorted by obj."""
        if visible_to is None:
            rows = self.conn.execute("SELECT obj, head_ver, head_hash FROM objects ORDER BY obj").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT v.obj, v.ver, v.hash FROM versions v JOIN "
                "(SELECT obj, MAX(ver) AS ver FROM versions WHERE seq < ? GROUP BY obj) m "
                "ON v.obj = m.obj AND v.ver = m.ver ORDER BY v.obj", (visible_to,)).fetchall()
        return {o: VersionRef(ver=v, hash=h) for o, v, h in rows}

    def value_at(self, obj: str, ver: int) -> Any:
        """Raw value of a specific version (restore source). ``KeyError`` if no such version,
        :class:`RedactedValue` if erased."""
        row = self.conn.execute("SELECT hash FROM versions WHERE obj = ? AND ver = ?", (obj, ver)).fetchone()
        if row is None:
            raise KeyError(f"{obj} has no version {ver}")
        if row[0] == TOMBSTONE_HASH:
            return None
        entry = self.side.get(row[0])
        if entry is None:
            raise StateError(f"{obj} v{ver}: value {row[0]} missing from the side table")
        if entry.redacted:
            raise RedactedValue(f"{obj} v{ver} is redacted")
        return entry.value

    def last_seq(self) -> int:
        """Highest seq that wrote anything (0 = empty store)."""
        return self.conn.execute("SELECT COALESCE(MAX(seq), 0) FROM versions").fetchone()[0]

    # --- StateWriter -----------------------------------------------------------------------------
    def put(self, obj: str, value: Any, *, author: str, seq: int, action_id: str) -> WriteEntry:
        """Write version ``before.ver + 1`` of ``obj`` (``value=None`` writes a tombstone) and return its
        write-set entry. Runs inside the caller's transaction. Refuses: no open transaction; a seq behind
        the store or a second write to ``obj`` at the same seq; a row value carrying a sensitive key; a field
        object that is not a configured sensitive field; deleting an absent or already deleted object."""
        if not self.conn.in_transaction:
            raise NotInTransaction("put must run inside the caller's BEGIN IMMEDIATE transaction")
        split_obj_id(obj)
        self.fields.check_obj(obj)
        self.fields.check_value(obj, value)
        text = _text(value)  # canonical rules: no floats, safe ints, depth (raises CanonicalError)
        h = value_hash(value)

        last = self.last_seq()
        if seq < last:
            raise SeqOrderError(f"seq {seq} is behind the store (last write at seq {last})")
        head = self.conn.execute("SELECT head_ver, head_hash FROM objects WHERE obj = ?", (obj,)).fetchone()
        if head is not None:
            head_seq = self.conn.execute("SELECT seq FROM versions WHERE obj = ? AND ver = ?",
                                         (obj, head[0])).fetchone()[0]
            if head_seq >= seq:
                raise SeqOrderError(f"{obj} already written at seq {head_seq} (one write per object per action)")
        if value is None and (head is None or head[1] == TOMBSTONE_HASH):
            raise StateError(f"delete of {obj}: object does not exist")

        before = None if head is None else VersionRef(ver=head[0], hash=head[1])
        ver = 1 if head is None else head[0] + 1
        # Validate every field through the contract types before touching the database.
        entry = WriteEntry(obj=obj, before=before, after=VersionRef(ver=ver, hash=h))
        HistoryEntry(obj=obj, ver=ver, hash=h, author=author, seq=seq, action_id=action_id)

        if value is not None:
            self.side.put(SideDomain.VALUE, value)
        self.conn.execute("INSERT INTO versions(obj, ver, hash, author, seq, action_id) VALUES (?, ?, ?, ?, ?, ?)",
                          (obj, ver, h, author, seq, action_id))
        self.conn.execute(
            "INSERT INTO objects(obj, head_ver, head_hash, head_value, head_redacted) VALUES (?, ?, ?, ?, 0) "
            "ON CONFLICT(obj) DO UPDATE SET head_ver = excluded.head_ver, head_hash = excluded.head_hash, "
            "head_value = excluded.head_value, head_redacted = 0",
            (obj, ver, h, None if value is None else text))
        return entry

    def restore(self, obj: str, to_ver: int, *, expect: int, seq: int, action_id: str,
                author: str = RECOVERY_AUTHOR) -> WriteEntry:
        """M11b/B6: write the value of ``to_ver`` as a **new** version, only if the head is still ``expect``
        (the culprit's after-version); otherwise :class:`StaleExpect` (gateway: ``hold/stale_plan``).
        A redacted source raises :class:`RedactedValue` (planner: ``flag``)."""
        head = self.conn.execute("SELECT head_ver FROM objects WHERE obj = ?", (obj,)).fetchone()
        if head is None or head[0] != expect:
            raise StaleExpect(f"{obj}: head is v{None if head is None else head[0]}, plan expected v{expect}")
        if not 1 <= to_ver < expect:
            raise StateError(f"{obj}: restore target v{to_ver} must be an earlier version than v{expect}")
        return self.put(obj, self.value_at(obj, to_ver), author=author, seq=seq, action_id=action_id)

    def write_row(self, row_obj: str, value: Any, *, author: str, seq: int,
                  action_id: str) -> tuple[WriteEntry, ...]:
        """Adapter helper (X2): write a full row value, splitting sensitive fields into their own objects and
        writing **only the objects that changed**. A field-only edit leaves the row's version alone; a row
        create writes its field objects; a row delete (``None``) tombstones the row and its live field
        objects; a null or absent field is a tombstone. Returns the write set, sorted by obj."""
        row_value, field_values = self.fields.split(row_obj, value)
        out: list[WriteEntry] = []
        for obj, new in sorted({row_obj: row_value, **field_values}.items()):
            head = self.conn.execute("SELECT head_hash FROM objects WHERE obj = ?", (obj,)).fetchone()
            live = head is not None and head[0] != TOMBSTONE_HASH
            if (new is None and not live) or (head is not None and head[0] == value_hash(new)):
                continue
            out.append(self.put(obj, new, author=author, seq=seq, action_id=action_id))
        return tuple(out)


def open_store(path: str | os.PathLike[str], *, fields: FieldSchema | None = None) -> Store:
    """Open (creating at mode 0600, independent of the umask) ``state.db`` with autocommit off-by-default
    semantics: no implicit transactions, the caller issues ``BEGIN IMMEDIATE``."""
    p = Path(path)
    if not p.exists():
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, DB_MODE)
        try:
            os.fchmod(fd, DB_MODE)
        finally:
            os.close(fd)
    conn = sqlite3.connect(p, isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 5000")
    return Store(conn, fields)
