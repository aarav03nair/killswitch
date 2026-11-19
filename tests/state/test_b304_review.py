"""B3-04 review regressions (kabir): transaction escape inside savepoint/simulate, persisted field list,
generator projections. Cases from kabir's probe."""

from __future__ import annotations

import sqlite3

import pytest

from ks.state import FieldSchema, StateError, open_store

F = FieldSchema(["suppliers.iban"])
S = "suppliers:S-17"
IB = S + ".iban"


def mk(tmp_path, fields=F, name="s.db"):
    return open_store(tmp_path / name, fields=fields)


def seed(s):
    with s.txn():
        s.write_row(S, {"name": "a", "iban": "DE"}, author="x", seq=1, action_id="x1")


# --- (1) a block cannot end the transaction ------------------------------------------------------------
@pytest.mark.parametrize("sql", ["COMMIT", "ROLLBACK", "BEGIN", "RELEASE ks_sp_1", "ROLLBACK TO ks_sp_1",
                                 "SAVEPOINT x", "END"])
def test_commit_inside_simulate_refused_and_nothing_leaks(tmp_path, sql):
    s = mk(tmp_path)
    seed(s)
    d = s.state_digest()
    s.conn.execute("SELECT 1")  # statement cache warm; the guard must still apply
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        with s.simulate():
            s.write_row(S, {"name": "a", "iban": "EVIL"}, author="x", seq=2, action_id="x2")
            s.conn.execute(sql)
    assert s.state_digest() == d
    assert s.get(IB).value == "DE"
    assert not s.conn.in_transaction
    s.close()
    s = mk(tmp_path)  # and on disk
    assert s.state_digest() == d


def test_rollback_inside_simulate_keeps_caller_writes(tmp_path):
    s = mk(tmp_path)
    seed(s)
    with s.txn():
        s.put(S, {"name": "kept"}, author="x", seq=2, action_id="x2")
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            with s.simulate():
                s.conn.execute("ROLLBACK")
        assert s.conn.in_transaction
    assert s.get(S).value == {"name": "kept"}


def test_commit_inside_savepoint_refused(tmp_path):
    s = mk(tmp_path)
    seed(s)
    with pytest.raises(sqlite3.DatabaseError):
        with s.txn(), s.savepoint():
            s.put(S, {"name": "b"}, author="x", seq=2, action_id="x2")
            s.conn.execute("COMMIT")
    assert s.get(S).value == {"name": "a"}


def test_guard_lifted_after_blocks(tmp_path):
    s = mk(tmp_path)
    seed(s)
    with s.simulate(), s.simulate():
        pass
    s.conn.execute("BEGIN IMMEDIATE")  # the gateway's own transaction control works again
    s.put(S, {"name": "c"}, author="x", seq=2, action_id="x2")
    s.conn.execute("COMMIT")
    assert s.get(S).value == {"name": "c"}


def test_backstop_raises_if_transaction_gone(tmp_path):
    """If the guard is bypassed (authorizer replaced), exit raises instead of silently returning."""
    s = mk(tmp_path)
    seed(s)
    with pytest.raises(StateError, match="transaction ended"):
        with s.simulate():
            s.conn.set_authorizer(None)
            s.conn.execute("ROLLBACK")
    with pytest.raises(StateError, match="ended inside the block"):
        with s.txn(), s.simulate():
            s.conn.set_authorizer(None)
            s.conn.execute("RELEASE ks_sp_2")  # second savepoint block on this store
    assert not s.conn.in_transaction


def test_txn_raises_if_block_ended_it(tmp_path):
    s = mk(tmp_path)
    with pytest.raises(StateError, match="transaction ended inside txn"):
        with s.txn():
            s.conn.execute("COMMIT")
    assert not s.conn.in_transaction


# --- (2) the field list is pinned in state.db ----------------------------------------------------------
def test_config_drift_refused(tmp_path):
    s = mk(tmp_path, fields=FieldSchema())
    with s.txn():
        s.put(S, {"name": "a", "iban": "DE"}, author="x", seq=1, action_id="x1")
    s.close()
    with pytest.raises(StateError, match="sensitive_fields"):
        mk(tmp_path)


def test_fields_persisted_and_adopted(tmp_path):
    s = mk(tmp_path)
    seed(s)
    s.close()
    s = mk(tmp_path, fields=None)  # adopts the persisted list
    assert s.fields == F
    r = s.read(S)
    assert r.value["iban"] == "DE" and IB in [e.obj for e in r.read_set]
    s.close()
    with pytest.raises(StateError):
        mk(tmp_path, fields=FieldSchema(["suppliers.iban", "suppliers.email"]))
    mk(tmp_path, fields=FieldSchema(["suppliers.iban", "suppliers.iban"]))  # same set, order/dups irrelevant


def test_legacy_db_without_field_list_refused(tmp_path):
    s = mk(tmp_path)
    seed(s)
    s.conn.execute("DELETE FROM meta WHERE k = 'sensitive_fields'")
    s.close()
    with pytest.raises(StateError, match="no persisted sensitive_fields"):
        mk(tmp_path)


# --- (3) generator projection ---------------------------------------------------------------------------
def test_generator_projection(tmp_path):
    s = mk(tmp_path)
    seed(s)
    r = s.read(S, project=(k for k in ["name", "iban"]))
    assert r.value == {"name": "a", "iban": "DE"}
    assert [e.obj for e in r.read_set] == [S, IB]
    t = s.read_table("suppliers", project=(k for k in ["name"]))
    assert t.value == {S: {"name": "a"}} and [e.obj for e in t.read_set] == [S]


def test_field_live_row_deleted(tmp_path):
    s = mk(tmp_path)
    with s.txn():
        s.put(S, {"name": "a"}, author="x", seq=1, action_id="x1")
        s.put(IB, "DE", author="x", seq=1, action_id="x1")
    with s.txn():
        s.put(S, None, author="x", seq=2, action_id="x2")
    r = s.read(S)
    assert r.value is None  # a deleted row delivers nothing, even if a field object is still live
    assert S in [e.obj for e in r.read_set]
    assert s.read_table("suppliers").value == {}
