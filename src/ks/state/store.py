"""ks.state: the versioned object store (ADR-05 §1-2, C3 M11). Owner: vikram.

Layout of ``workspace/state.db`` (0600, gateway uid):

* ``objects(obj PK, head_ver, head_hash, head_value, head_redacted)``: the current head of every object;
* ``versions(obj, ver, hash, author, seq, action_id)``: **append-only** (triggers abort UPDATE/DELETE),
  one row per write, PK ``(obj, ver)``;
* ``side(hash PK, domain, value, redacted)``: the value of every version, by value hash (redactable);
* ``meta(k PK, v)``: schema version and the sensitive-field list (``sensitive_fields``, canonical JSON
  array). The field list is fixed at creation: reopening with a different :class:`FieldSchema` raises,
  and ``fields=None`` on reopen adopts the persisted one, so the read rule cannot drift (B3-04 review).

Conventions (M11). ``ver`` starts at 1 and is ``before.ver + 1`` per write. (a) A delete writes a tombstone
(value ``None``, ``TOMBSTONE_HASH``); a re-create continues the counter. (b) A restore writes a **new**
version (author ``ks.recovery``), never rewinds. (c) A version written at seq *s* is visible only to seq > *s*
(``visible_to=``). Seq is the gateway's global record seq: writes arrive in seq order, one write per object
per action.

Transactions (ADR-03 §1.8, CALL-02 G5). The store never opens or commits a transaction around a write: the
gateway owns ``BEGIN IMMEDIATE``, takes ``seq`` first, re-checks epoch and the deny-list, then calls
:meth:`Store.put`, then commits and appends the record. ``put`` refuses to run outside a transaction, so
a write can never autocommit on its own. :meth:`Store.txn` is a convenience wrapper with the same shape.

Reads (B3-04, C3 X2, ADR-05 §3). :meth:`Store.read` and :meth:`Store.read_table` return the delivered value
**and** the read set the gateway records: a whole-row read lists the row and every existing field object
of that row; a projection that omits the field lists only the row; any read returning a sensitive value
lists its field object. :meth:`Store.state_digest` is the live side of reconciliation
(``state_digest(fold(record))``, see :mod:`ks.state.digest`).

Savepoints (B3-04, ADR-05 §7). :meth:`Store.savepoint` nests inside the caller's transaction and keeps its
writes unless the block raises; :meth:`Store.simulate` always rolls back (dry-run re-run simulation, B3-24).
Inside either block SQLite refuses transaction-control SQL on the connection (authorizer guard), so simulated
code cannot COMMIT its writes or ROLLBACK the caller's; if the transaction or savepoint is nevertheless gone
on exit, both raise :class:`StateError` instead of silently keeping or dropping writes.
"""

from __future__ import annotations

import itertools
import os
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ks.contracts import (
    TOMBSTONE_HASH,
    HistoryEntry,
    ReadEntry,
    SideDomain,
    StateRead,
    VersionRef,
    WriteEntry,
    canonical,
    split_obj_id,
    value_hash,
)
from ks.contracts import state_digest as _state_digest

from .fields import FieldSchema
from .side import SqliteSideStore

__all__ = [
    "RECOVERY_AUTHOR",
    "SCHEMA_VERSION",
    "NotInTransaction",
    "ReadResult",
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


@dataclass(frozen=True)
class ReadResult:
    """What a read delivered (raw ``value``: gateway-internal, never in a record) and its read set
    (``ReadEntry`` per delivered object version, sorted by obj, unique): goes into ``Record.read_set``."""

    value: Any
    read_set: tuple[ReadEntry, ...]


def _merge_read_sets(*sets: Iterable[ReadEntry]) -> tuple[ReadEntry, ...]:
    by_obj: dict[str, ReadEntry] = {}
    for rs in sets:
        for e in rs:
            prev = by_obj.setdefault(e.obj, e)
            if prev != e:
                raise StateError(f"{e.obj} read at two versions in one read set (v{prev.ver}, v{e.ver})")
    return tuple(by_obj[o] for o in sorted(by_obj))


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
        self.side = SqliteSideStore(conn)
        self._sp = itertools.count(1)
        self._depth = 0  # open savepoint blocks; >0 installs the transaction-control guard
        self._ctl = False
        for stmt in _DDL:
            conn.execute(stmt)
        row = conn.execute("SELECT v FROM meta WHERE k = 'schema'").fetchone()
        if row is None:
            conn.execute("INSERT INTO meta(k, v) VALUES ('schema', ?)", (SCHEMA_VERSION,))
        elif row[0] != SCHEMA_VERSION:
            raise StateError(f"state.db schema {row[0]!r}, expected {SCHEMA_VERSION!r}")
        self.fields = self._pin_fields(fields)

    def _pin_fields(self, fields: FieldSchema | None) -> FieldSchema:
        """The read rule depends on the field list, so it is part of the store (B3-04 review): persisted on
        first open, adopted when ``fields`` is ``None``, and a mismatch is refused."""
        row = self.conn.execute("SELECT v FROM meta WHERE k = 'sensitive_fields'").fetchone()
        if row is None:
            if self.conn.execute("SELECT 1 FROM objects LIMIT 1").fetchone() is not None:
                raise StateError("state.db has objects but no persisted sensitive_fields; cannot verify the read rule")
            pinned = fields if fields is not None else FieldSchema()
            self.conn.execute("INSERT INTO meta(k, v) VALUES ('sensitive_fields', ?)",
                              (_text(list(pinned.entries())),))
            return pinned
        stored = FieldSchema(_value(row[0]))
        if fields is not None and fields != stored:
            raise StateError(f"state.db was created with sensitive_fields {list(stored.entries())}, "
                             f"opened with {list(fields.entries())}")
        return stored

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
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        if not self.conn.in_transaction:
            raise StateError("transaction ended inside txn() (COMMIT/ROLLBACK issued by the block)")
        self.conn.execute("COMMIT")

    @contextmanager
    def savepoint(self) -> Iterator[Store]:
        """Nested ``SAVEPOINT``: its writes join the enclosing transaction unless the block raises, in which
        case only they are rolled back. Outside a transaction it opens (and commits) ``BEGIN IMMEDIATE``.
        Inside the block, transaction-control SQL on ``self.conn`` (``BEGIN``/``COMMIT``/``ROLLBACK``/
        ``SAVEPOINT``/``RELEASE``) is refused by SQLite (``sqlite3.DatabaseError: not authorized``)."""
        name, outer = self._begin_savepoint()
        try:
            yield self
        except BaseException:
            self._end_savepoint(name, outer, keep=False)
            raise
        self._end_savepoint(name, outer, keep=True)

    @contextmanager
    def simulate(self) -> Iterator[Store]:
        """Dry-run block (ADR-05 §7, B3-24 re-run simulation): reads and writes see the block's own writes,
        and everything (versions, heads, side values, redactions) is rolled back on exit, raise or not.
        Nests: an inner ``simulate``/``savepoint`` inside it is discarded with it. Transaction-control SQL
        inside the block is refused as in :meth:`savepoint`, so simulated code cannot COMMIT its writes."""
        name, outer = self._begin_savepoint()
        try:
            yield self
        finally:
            self._end_savepoint(name, outer, keep=False)

    def _authorize(self, action: int, arg1: str | None, *_: object) -> int:
        """SQLite authorizer active while any savepoint block is open: only the store's own transaction
        control passes (B3-04 review: a COMMIT inside simulate() persisted simulated writes)."""
        if action in (sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT) and not self._ctl:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def _exec_ctl(self, sql: str) -> None:
        self._ctl = True
        try:
            self.conn.execute(sql)
        finally:
            self._ctl = False

    def _begin_savepoint(self) -> tuple[str, bool]:
        name = f"ks_sp_{next(self._sp)}"
        outer = not self.conn.in_transaction
        if outer:
            self._exec_ctl("BEGIN IMMEDIATE")
        try:
            self._exec_ctl(f"SAVEPOINT {name}")
        except BaseException:
            if outer:
                self._exec_ctl("ROLLBACK")
            raise
        if self._depth == 0:
            self.conn.set_authorizer(self._authorize)
        self._depth += 1
        return name, outer

    def _end_savepoint(self, name: str, outer: bool, *, keep: bool) -> None:
        """Release (``keep``) or roll back savepoint ``name``. Backstop for the guard: if the transaction or
        the savepoint is gone (ended inside the block), raise :class:`StateError` rather than silently keep
        or drop writes."""
        self._depth -= 1
        if self._depth == 0:
            self.conn.set_authorizer(None)
        if not self.conn.in_transaction:
            raise StateError(f"transaction ended inside savepoint {name} (COMMIT/ROLLBACK issued by the block)")
        try:
            if keep:
                self._exec_ctl(f"RELEASE {name}")
            else:
                self._exec_ctl(f"ROLLBACK TO {name}")
                self._exec_ctl(f"RELEASE {name}")
        except sqlite3.OperationalError as e:  # savepoint released or rolled past inside the block
            if outer and self.conn.in_transaction:
                self._exec_ctl("ROLLBACK")
            raise StateError(f"savepoint {name} ended inside the block: {e}") from e
        if outer:
            self._exec_ctl("COMMIT" if keep else "ROLLBACK")

    # --- reads with read sets (X2) ---------------------------------------------------------------
    def read(self, obj: str, *, project: Iterable[str] | None = None,
             visible_to: int | None = None) -> ReadResult | None:
        """Read ``obj`` and return the value delivered plus its read set (C3 X2, ADR-05 §3).

        * Row, ``project=None`` (whole-row read): the row value merged with every live field value; the read
          set lists the row and **every existing field object** of that row (tombstoned ones included: the
          absence of the field was delivered too).
        * Row, ``project=[keys]``: only those keys of the merged row; the read set lists the row plus the
          existing field objects of the sensitive keys named. A projection that omits every sensitive field
          lists only the row, so a field-only edit (which does not bump the row) is invisible to it.
        * Field object: its value; the read set lists only that field object.

        ``None`` if ``obj`` does not exist (at ``visible_to``): there is no absence read in v1 (SEC-03 F7).
        A deleted row reads as ``value=None`` and still lists its tombstone version."""
        _, _, field = split_obj_id(obj)
        project = None if project is None else tuple(project)
        objs = self.fields.read_objs(obj, project)
        head = self.get(obj, visible_to=visible_to)
        if head is None:
            return None
        if field is not None:
            return ReadResult(head.value, (ReadEntry(obj=obj, ver=head.ver, hash=head.hash),))
        entries = [ReadEntry(obj=obj, ver=head.ver, hash=head.hash)]
        merged = None if head.value is None else dict(head.value) if isinstance(head.value, dict) else head.value
        for fo in objs[1:]:
            fr = self.get(fo, visible_to=visible_to)
            if fr is None:
                continue
            entries.append(ReadEntry(obj=fo, ver=fr.ver, hash=fr.hash))
            if fr.value is not None and isinstance(merged, dict):
                merged[split_obj_id(fo)[2]] = fr.value
        value = merged
        if project is not None and isinstance(merged, dict):
            keep = set(project)
            value = {k: v for k, v in merged.items() if k in keep}
        return ReadResult(value, _merge_read_sets(entries))

    def read_table(self, table: str, *, project: Iterable[str] | None = None,
                   visible_to: int | None = None) -> ReadResult:
        """Aggregate read (SEC-03 F7): enumerate every live row of ``table`` and read each by :meth:`read`
        (whole-row unless ``project`` names keys). ``value`` maps row obj -> delivered row value; the read
        set is the union of the row reads. Deleted rows are not delivered and not listed."""
        project = None if project is None else tuple(project)
        values: dict[str, Any] = {}
        sets = []
        for obj, ref in self.heads(visible_to=visible_to).items():
            t, _, f = split_obj_id(obj)
            if t != table or f is not None or ref.hash == TOMBSTONE_HASH:
                continue
            r = self.read(obj, project=project, visible_to=visible_to)
            values[obj] = r.value
            sets.append(r.read_set)
        return ReadResult(values, _merge_read_sets(*sets))

    def state_digest(self, *, visible_to: int | None = None) -> str:
        """``state_digest(heads())``: the live digest that reconciliation compares with ``fold(record)``."""
        return _state_digest(self.heads(visible_to=visible_to))

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
