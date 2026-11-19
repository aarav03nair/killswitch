"""B3-03: ks.state versioned object store (ADR-05 §1-2, C3 M11)."""

from __future__ import annotations

import os
import sqlite3
import stat

import pytest

from ks.contracts import (
    TOMBSTONE_HASH,
    CanonicalError,
    RunConfig,
    SideDomain,
    SideStore,
    StateView,
    StateWriter,
    VersionRef,
    WriteEntry,
    state_digest,
    value_hash,
)
from ks.state import (
    FieldSchema,
    NotInTransaction,
    RedactedValue,
    SensitiveKeyError,
    SeqOrderError,
    StaleExpect,
    StateError,
    Store,
    open_store,
)

S17, S22, T3 = "suppliers:S-17", "suppliers:S-22", "tickets:T-3"
IBAN = "suppliers:S-17.iban"
FIELDS = FieldSchema(["suppliers.iban"])


@pytest.fixture
def db(tmp_path):
    return tmp_path / "state.db"


@pytest.fixture
def store(db):
    s = open_store(db, fields=FIELDS)
    yield s
    s.close()


def put(store: Store, obj, value, *, author="crm", seq, action=None):
    with store.txn():
        return store.put(obj, value, author=author, seq=seq, action_id=action or f"{author}-{seq}")


def versions_rows(store: Store):
    return store.conn.execute("SELECT obj, ver, hash, author, seq, action_id FROM versions ORDER BY obj, ver").fetchall()


# --- round trip, monotonic ver, WriteEntry (C3) -----------------------------------------------------------------
def test_put_get_history_roundtrip(store):
    w1 = put(store, S17, {"name": "Acme", "terms": 30}, author="intake", seq=1)
    w2 = put(store, S17, {"name": "Acme Ltd", "terms": 30}, author="crm", seq=4)
    w3 = put(store, S17, {"name": "Acme Ltd", "terms": 45}, author="triage", seq=9)

    assert w1 == WriteEntry(obj=S17, before=None, after=VersionRef(ver=1, hash=value_hash({"name": "Acme", "terms": 30})))
    assert w2.before == w1.after and w2.after.ver == 2
    assert w3.before == w2.after and w3.after.ver == 3
    assert WriteEntry.from_canonical(w3.to_canonical()) == w3

    r = store.get(S17)
    assert (r.value, r.ver, r.author, r.hash) == ({"name": "Acme Ltd", "terms": 45}, 3, "triage", w3.after.hash)
    h = store.history(S17)
    assert [(e.ver, e.author, e.seq, e.action_id, e.hash) for e in h] == [
        (1, "intake", 1, "intake-1", w1.after.hash), (2, "crm", 4, "crm-4", w2.after.hash),
        (3, "triage", 9, "triage-9", w3.after.hash)]
    assert store.value_at(S17, 1) == {"name": "Acme", "terms": 30}
    assert store.get("suppliers:S-99") is None and store.history("suppliers:S-99") == ()


def test_version_plus_one_per_object(store):
    seq = 0
    for i in range(5):
        for obj in (S17, S22, T3):
            seq += 1
            w = put(store, obj, {"i": i}, seq=seq)
            assert w.after.ver == i + 1 and (w.before is None) == (i == 0)
    assert {o: r.ver for o, r in store.heads().items()} == {S17: 5, S22: 5, T3: 5}
    for obj in (S17, S22, T3):
        assert [e.ver for e in store.history(obj)] == [1, 2, 3, 4, 5]
    assert store.last_seq() == 15


def test_append_only(store):
    put(store, S17, {"a": 1}, seq=1)
    put(store, S17, {"a": 2}, seq=2)
    before = versions_rows(store)
    for stmt in ("UPDATE versions SET hash = 'x' WHERE obj = 'suppliers:S-17'",
                 "DELETE FROM versions WHERE ver = 1", "UPDATE versions SET author = 'crm'"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store.conn.execute(stmt)
    # Every later write only appends: earlier rows are untouched, delete and restore included.
    put(store, S17, None, seq=3)
    with store.txn():
        store.restore(S17, 2, expect=3, seq=4, action_id="rec-1")
    after = versions_rows(store)
    assert after[:len(before)] == before and len(after) == len(before) + 2


# --- tombstones and restore (M11a/b) -----------------------------------------------------------------------------
def test_tombstone_and_recreate(store):
    put(store, S22, {"name": "Beta"}, seq=1)
    w = put(store, S22, None, author="inventory", seq=2)
    assert w.after == VersionRef(ver=2, hash=TOMBSTONE_HASH) and w.before.ver == 1
    r = store.get(S22)
    assert (r.value, r.ver, r.hash, r.author) == (None, 2, TOMBSTONE_HASH, "inventory")
    assert store.heads()[S22] == VersionRef(ver=2, hash=TOMBSTONE_HASH)
    with pytest.raises(StateError, match="does not exist"):
        put(store, S22, None, seq=3)  # already deleted
    with pytest.raises(StateError, match="does not exist"):
        put(store, "suppliers:S-404", None, seq=3)  # never existed
    w = put(store, S22, {"name": "Beta 2"}, seq=3)
    assert w.before == VersionRef(ver=2, hash=TOMBSTONE_HASH) and w.after.ver == 3  # counter continues
    assert store.value_at(S22, 2) is None


def test_restore_is_new_version(store):
    honest = put(store, S17, {"name": "Acme"}, author="intake", seq=1)
    bad = put(store, S17, {"name": "Evil"}, author="crm", seq=5)
    with store.txn():
        w = store.restore(S17, 1, expect=bad.after.ver, seq=8, action_id="recover-1")
    assert w.before == bad.after and w.after == VersionRef(ver=3, hash=honest.after.hash)
    r = store.get(S17)
    assert (r.value, r.ver, r.author) == ({"name": "Acme"}, 3, "ks.recovery")
    assert [(e.ver, e.author) for e in store.history(S17)] == [(1, "intake"), (2, "crm"), (3, "ks.recovery")]


def test_restore_expect_head(store):
    put(store, S17, {"v": 1}, author="intake", seq=1)
    put(store, S17, {"v": 2}, author="crm", seq=2)
    put(store, S17, {"v": 3}, author="triage", seq=3)  # head moved since the plan
    with pytest.raises(StaleExpect), store.txn():
        store.restore(S17, 1, expect=2, seq=4, action_id="recover-1")
    with pytest.raises(StaleExpect), store.txn():
        store.restore("suppliers:S-404", 1, expect=1, seq=4, action_id="recover-1")
    assert store.get(S17).ver == 3 and len(store.history(S17)) == 3


# --- visibility after seq (M11c) ---------------------------------------------------------------------------------
def test_same_tick_visibility(store):
    put(store, T3, {"body": "hello"}, author="intake", seq=3)
    put(store, T3, {"body": "pay DE89"}, author="intake", seq=7)
    assert store.get(T3, visible_to=3) is None  # not even v1 is visible to its own seq
    assert store.get(T3, visible_to=4).ver == 1
    r = store.get(T3, visible_to=7)  # a record at seq 7 does not see the version written at seq 7
    assert (r.ver, r.value) == (1, {"body": "hello"})
    assert store.get(T3, visible_to=8).ver == 2
    assert [e.ver for e in store.history(T3, visible_to=7)] == [1]
    assert store.heads(visible_to=7) == {T3: VersionRef(ver=1, hash=value_hash({"body": "hello"}))}
    assert store.heads(visible_to=8) == store.heads()


def test_seq_order(store):
    with store.txn():
        store.put(S17, {"a": 1}, author="crm", seq=5, action_id="crm-5")
        store.put(S22, {"a": 1}, author="crm", seq=5, action_id="crm-5")  # one action, two objects
        with pytest.raises(SeqOrderError, match="one write per object"):
            store.put(S17, {"a": 2}, author="crm", seq=5, action_id="crm-5")
    with pytest.raises(SeqOrderError, match="behind"):
        put(store, T3, {"a": 1}, seq=4)
    assert store.last_seq() == 5


# --- transactions (ADR-03 §1.8, G5) ------------------------------------------------------------------------------
def test_put_requires_caller_txn(store):
    with pytest.raises(NotInTransaction):
        store.put(S17, {"a": 1}, author="crm", seq=1, action_id="crm-1")
    assert store.get(S17) is None


def test_rollback_discards_everything(store):
    put(store, S17, {"a": 1}, seq=1)
    with pytest.raises(RuntimeError), store.txn():
        store.put(S17, {"a": 2}, author="crm", seq=2, action_id="crm-2")
        store.put(S22, {"b": 1}, author="crm", seq=2, action_id="crm-2")
        raise RuntimeError("crash before commit")
    assert store.get(S17).ver == 1 and store.get(S22) is None and store.last_seq() == 1
    assert store.side.get(value_hash({"a": 2})) is None  # values roll back with the txn


def test_caller_owned_begin_immediate(db):
    """The gateway's shape: BEGIN IMMEDIATE, take seq first, re-check, put, COMMIT, then append the record."""
    gw = open_store(db, fields=FIELDS)
    other = sqlite3.connect(db, isolation_level=None, timeout=0)
    try:
        gw.conn.execute("BEGIN IMMEDIATE")
        seq = gw.last_seq() + 1  # stands in for recorder.seq + 1
        w = gw.put(S17, {"name": "Acme"}, author="crm", seq=seq, action_id="crm-1")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            other.execute("BEGIN IMMEDIATE")  # the write lock is held for the whole execution txn
        assert other.execute("SELECT COUNT(*) FROM versions").fetchone()[0] == 0  # uncommitted: invisible
        gw.conn.execute("COMMIT")
        assert other.execute("SELECT head_ver, head_hash FROM objects").fetchone() == (1, w.after.hash)
        gw.conn.execute("BEGIN IMMEDIATE")
        # nesting is a savepoint (B3-04), never a second BEGIN
        with pytest.raises(StateError, match="already open"), gw.txn():
            pass
        gw.conn.execute("ROLLBACK")
    finally:
        other.close()
        gw.close()


def test_connection_must_be_explicit_txn(db):
    with pytest.raises(StateError, match="isolation_level=None"):
        Store(sqlite3.connect(db))


# --- persistence -------------------------------------------------------------------------------------------------
def test_reopen_persistence(db):
    s = open_store(db, fields=FIELDS)
    put(s, S17, {"name": "Acme"}, author="intake", seq=1)
    put(s, S17, {"name": "Evil"}, author="crm", seq=2)
    put(s, S22, {"name": "Beta"}, author="intake", seq=3)
    put(s, S22, None, author="inventory", seq=4)
    heads, hist = s.heads(), s.history(S17)
    s.close()
    assert stat.S_IMODE(db.stat().st_mode) == 0o600

    s = open_store(db, fields=FIELDS)
    try:
        assert s.heads() == heads and s.history(S17) == hist and s.last_seq() == 4
        assert s.get(S17).value == {"name": "Evil"} and s.value_at(S17, 1) == {"name": "Acme"}
        assert s.get(S22).value is None
        w = put(s, S17, {"name": "Acme"}, author="triage", seq=5)
        assert w.after.ver == 3 and w.before == heads[S17]
        with pytest.raises(sqlite3.IntegrityError):
            s.conn.execute("DELETE FROM versions")
    finally:
        s.close()


def test_db_created_0600_under_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        open_store(tmp_path / "s.db").close()
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "s.db").stat().st_mode) == 0o600


# --- sensitive field objects, write side (B1/X1/X2) --------------------------------------------------------------
def test_sensitive_field_object(store):
    with pytest.raises(SensitiveKeyError, match="sensitive key"):
        put(store, S17, {"name": "Acme", "iban": "DE89"}, seq=1)  # each datum in exactly one object
    with pytest.raises(SensitiveKeyError, match="not a sensitive field"):
        put(store, "suppliers:S-17.name", "Acme", seq=1)
    assert store.heads() == {}

    with store.txn():  # row create writes its field objects
        ws = store.write_row(S17, {"name": "Acme", "iban": "DE89"}, author="intake", seq=1, action_id="intake-1")
    assert [(w.obj, w.after.ver) for w in ws] == [(S17, 1), (IBAN, 1)]
    assert store.get(S17).value == {"name": "Acme"} and store.get(IBAN).value == "DE89"
    assert store.get(S17).hash == value_hash({"name": "Acme"})  # row hash excludes the sensitive field

    with store.txn():  # field-level put works directly too
        w = store.put(IBAN, "GB33", author="crm", seq=2, action_id="crm-2")
    assert (w.obj, w.before.ver, w.after.ver) == (IBAN, 1, 2)

    with store.txn():  # a null field is a tombstone; the row is untouched
        ws = store.write_row(S17, {"name": "Acme", "iban": None}, author="crm", seq=3, action_id="crm-3")
    assert [(w.obj, w.after.hash) for w in ws] == [(IBAN, TOMBSTONE_HASH)]

    with store.txn():  # field re-create continues its counter
        store.write_row(S17, {"name": "Acme", "iban": "DE89"}, author="crm", seq=4, action_id="crm-4")
    with store.txn():  # row delete tombstones the row and its live field objects
        ws = store.write_row(S17, None, author="inventory", seq=5, action_id="inv-5")
    assert [(w.obj, w.after.ver, w.after.hash) for w in ws] == [(S17, 2, TOMBSTONE_HASH), (IBAN, 5, TOMBSTONE_HASH)]

    with store.txn():  # tables without sensitive fields pass through unchanged
        ws = store.write_row(T3, {"body": "x", "iban": "not sensitive here"}, author="intake", seq=6,
                             action_id="intake-6")
    assert [w.obj for w in ws] == [T3] and store.get(T3).value["iban"] == "not sensitive here"


def test_field_only_update_keeps_row_ver(store):
    with store.txn():
        store.write_row(S17, {"name": "Acme", "terms": 30, "iban": "DE89"}, author="intake", seq=1,
                        action_id="intake-1")
    with store.txn():
        ws = store.write_row(S17, {"name": "Acme", "terms": 30, "iban": "GB33"}, author="crm", seq=2,
                             action_id="crm-2")
    assert [(w.obj, w.before.ver, w.after.ver) for w in ws] == [(IBAN, 1, 2)]
    assert store.get(S17).ver == 1 and store.get(IBAN).ver == 2
    with store.txn():  # a row-only edit does not bump the field
        ws = store.write_row(S17, {"name": "Acme", "terms": 45, "iban": "GB33"}, author="triage", seq=3,
                             action_id="triage-3")
    assert [(w.obj, w.after.ver) for w in ws] == [(S17, 2)] and store.get(IBAN).ver == 2
    with store.txn():  # no change, no write
        assert store.write_row(S17, {"name": "Acme", "terms": 45, "iban": "GB33"}, author="triage", seq=4,
                               action_id="triage-4") == ()


def test_field_schema_from_config():
    cfg = RunConfig.model_construct(sensitive_fields=("employees.salary", "suppliers.iban"))
    fs = FieldSchema.from_config(cfg)
    assert fs.fields_of("suppliers") == ("iban",) and fs.fields_of("tickets") == ()
    for row in (S17, T3, "employees:E-1"):
        assert fs.field_objs_of(row) == cfg.field_objs_of(row)  # same answer as the contract helper
    with pytest.raises(ValueError):
        FieldSchema(["no_dot"])


# --- protocols, side store, canonical rules ----------------------------------------------------------------------
def test_contract_protocols(store):
    assert isinstance(store, StateView) and isinstance(store, StateWriter) and isinstance(store.side, SideStore)
    put(store, S17, {"a": 1}, seq=1)
    assert state_digest(store.heads()) == state_digest({S17: VersionRef(ver=1, hash=value_hash({"a": 1}))})


def test_side_store_and_redaction(store):
    put(store, IBAN, "DE89", author="intake", seq=1)
    put(store, IBAN, "GB33", author="crm", seq=2)
    h1 = value_hash("DE89")
    e = store.side.get(h1)
    assert (e.domain, e.value, e.redacted) == (SideDomain.VALUE, "DE89", False)
    assert store.side.put(SideDomain.VALUE, "DE89") == h1  # idempotent
    store.side.redact(h1)
    assert store.side.get(h1).redacted and store.side.get(h1).value is None
    with pytest.raises(RedactedValue):
        store.value_at(IBAN, 1)  # planner: a redacted restore target gives flag
    with pytest.raises(RedactedValue), store.txn():
        store.restore(IBAN, 1, expect=2, seq=3, action_id="recover-1")
    assert [e.hash for e in store.history(IBAN)] == [h1, value_hash("GB33")]  # the hash remains
    store.side.redact(value_hash("GB33"))  # erasing the head value erases it from objects too
    with pytest.raises(RedactedValue):
        store.get(IBAN)
    assert store.conn.execute("SELECT head_value FROM objects WHERE obj = ?", (IBAN,)).fetchone() == (None,)
    assert store.side.get("0" * 64) is None
    w = put(store, IBAN, "DE89", author="crm", seq=4)  # the erased value written again is live again
    assert store.get(IBAN).value == "DE89" and store.value_at(IBAN, w.after.ver) == "DE89"


def test_rejects_bad_values_and_ids_before_writing(store):
    with pytest.raises(CanonicalError):
        put(store, S17, {"price": 1.5}, seq=1)  # no floats
    with pytest.raises(ValueError):
        put(store, "suppliers:S.17.iban", {"a": 1}, seq=1)  # dotted pk
    with pytest.raises(ValueError):
        put(store, S17, {"a": 1}, author="Not An Agent", seq=1)
    with pytest.raises(ValueError):
        put(store, S17, {"a": 1}, seq=0)
    assert versions_rows(store) == [] and store.heads() == {}
