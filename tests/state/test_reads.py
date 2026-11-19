"""B3-04: read rule with field objects (C3 X2, ADR-05 §3), state_digest + fold, savepoints/simulate."""

from __future__ import annotations

import random
from types import SimpleNamespace

import pytest

from ks.contracts import (
    TOMBSTONE_HASH,
    ReadEntry,
    RunConfig,
    VersionRef,
    WriteEntry,
    state_digest,
    value_hash,
)
from ks.state import (
    FieldSchema,
    FoldError,
    ReadResult,
    SensitiveKeyError,
    StateError,
    Store,
    fold,
    fold_digest,
    open_store,
)

S17, S22, T3 = "suppliers:S-17", "suppliers:S-22", "tickets:T-3"
IBAN, IBAN22, SALARY = "suppliers:S-17.iban", "suppliers:S-22.iban", "employees:E-1.salary"
FIELDS = FieldSchema(["suppliers.iban", "suppliers.tax_id", "employees.salary"])
TAX = "suppliers:S-17.tax_id"


@pytest.fixture
def store(tmp_path):
    s = open_store(tmp_path / "state.db", fields=FIELDS)
    yield s
    s.close()


def row(store: Store, obj, value, *, author="intake", seq):
    with store.txn():
        return store.write_row(obj, value, author=author, seq=seq, action_id=f"{author}-{seq}")


def objs(r: ReadResult):
    return [e.obj for e in r.read_set]


def entry(store: Store, obj) -> ReadEntry:
    g = store.get(obj)
    return ReadEntry(obj=obj, ver=g.ver, hash=g.hash)


# --- read rule (X2) -----------------------------------------------------------------------------------------------
def test_row_read_includes_field_objects(store):
    row(store, S17, {"name": "Acme", "terms": 30, "iban": "DE89"}, seq=1)  # tax_id never written
    r = store.read(S17)
    assert r.value == {"name": "Acme", "terms": 30, "iban": "DE89"}
    assert r.read_set == (entry(store, S17), entry(store, IBAN))  # existing field objects only, sorted
    assert TAX not in objs(r)

    row(store, S22, {"name": "Beta", "iban": "GB33", "tax_id": "T-9"}, seq=2)
    agg = store.read_table("suppliers")  # aggregates enumerate rows and their field objects
    assert objs(agg) == [S17, IBAN, S22, IBAN22, "suppliers:S-22.tax_id"]
    assert agg.value == {S17: {"name": "Acme", "terms": 30, "iban": "DE89"},
                         S22: {"name": "Beta", "iban": "GB33", "tax_id": "T-9"}}


def test_row_read_lists_field_obj(store):
    """R2 store side: whole-row read lists the field object; a projection without the field does not."""
    row(store, S17, {"name": "Acme", "terms": 30, "iban": "DE89"}, seq=1)
    assert IBAN in objs(store.read(S17))
    assert IBAN in objs(store.read_table("suppliers"))

    proj = store.read(S17, project=["name", "terms"])  # triage's projection
    assert proj.value == {"name": "Acme", "terms": 30} and objs(proj) == [S17]
    assert objs(store.read_table("suppliers", project=["terms"])) == [S17]

    with_iban = store.read(S17, project=["name", "iban"])  # a read returning the sensitive value lists it
    assert with_iban.value == {"name": "Acme", "iban": "DE89"} and objs(with_iban) == [S17, IBAN]

    direct = store.read(IBAN)  # a field-object read lists only the field object
    assert direct.value == "DE89" and direct.read_set == (entry(store, IBAN),)

    # every read that returns a sensitive value lists its field object (property over all projections)
    keys = ["name", "terms", "iban", "tax_id"]
    for mask in range(1 << len(keys)):
        p = [k for i, k in enumerate(keys) if mask >> i & 1]
        r = store.read(S17, project=p)
        for k, v in r.value.items():
            if k in FIELDS.fields_of("suppliers"):
                assert f"{S17}.{k}" in objs(r) and store.get(f"{S17}.{k}").value == v


def test_triage_edit_does_not_bump_iban(store):
    """Field-only edits do not bump the row; a row-only edit does not bump the field (X2)."""
    row(store, S17, {"name": "Acme", "terms": 30, "iban": "DE89"}, seq=1)
    before = store.read(S17, project=["name", "terms"])
    row(store, S17, {"name": "Acme", "terms": 30, "iban": "XX00-CULPRIT"}, author="crm", seq=2)  # iban only
    after = store.read(S17, project=["name", "terms"])
    assert after.read_set == before.read_set  # triage's view cannot have observed the bad iban
    assert store.get(S17).ver == 1 and store.get(IBAN).ver == 2

    ws = row(store, S17, {"name": "Acme", "terms": 30, "risk_note": "check", "iban": "XX00-CULPRIT"},
             author="triage", seq=3)  # triage set_risk_note
    assert [(w.obj, w.after.ver) for w in ws] == [(S17, 2)]
    assert store.get(IBAN).ver == 2 and store.history(IBAN)[-1].author == "crm"


def test_triage_view_excludes_iban(store):
    row(store, S17, {"name": "Acme", "iban": "DE89"}, seq=1)
    assert objs(store.read(S17, project=("name", "terms", "risk_note"))) == [S17]
    assert FIELDS.read_objs(S17, project=["name"]) == (S17,)
    assert FIELDS.read_objs(S17) == (S17, IBAN, TAX)


def test_read_tombstones_and_visibility(store):
    row(store, S17, {"name": "Acme", "iban": "DE89"}, seq=1)
    row(store, S17, {"name": "Acme", "iban": None}, author="crm", seq=2)  # iban tombstoned
    r = store.read(S17)
    assert r.value == {"name": "Acme"}  # absence of the field was delivered ...
    assert [(e.obj, e.hash == TOMBSTONE_HASH) for e in r.read_set] == [(S17, False), (IBAN, True)]  # ... and listed

    old = store.read(S17, visible_to=2)  # as seen by seq 2 (M11c): before crm's write
    assert old.value == {"name": "Acme", "iban": "DE89"} and old.read_set[1].ver == 1
    assert store.read(S17, visible_to=1) is None  # nothing visible yet: no absence read
    assert store.read("suppliers:S-99") is None

    row(store, S17, None, author="inventory", seq=3)  # row delete
    gone = store.read(S17)
    assert gone.value is None and objs(gone) == [S17, IBAN]
    assert store.read_table("suppliers").read_set == ()  # deleted rows are not delivered by an aggregate


def test_read_rejects_non_sensitive_field_obj(store):
    with pytest.raises(SensitiveKeyError):
        store.read("suppliers:S-17.name")
    with pytest.raises(ValueError):
        store.read("suppliers:S.17")


def test_put_rejects_sensitive_key_in_row(store):
    with store.txn():
        for bad in ({"name": "Acme", "iban": "DE89"}, {"tax_id": None}):
            with pytest.raises(SensitiveKeyError):
                store.put(S17, bad, author="crm", seq=1, action_id="crm-1")
        with pytest.raises(SensitiveKeyError):
            store.put("employees:E-1", {"salary": 1}, author="hr", seq=1, action_id="hr-1")
    assert store.heads() == {}


def test_field_schema_read_objs_matches_config():
    cfg = RunConfig.model_construct(sensitive_fields=("employees.salary", "suppliers.iban", "suppliers.tax_id"))
    fs = FieldSchema.from_config(cfg)
    assert fs.read_objs(S17)[1:] == cfg.field_objs_of(S17)
    assert fs.read_objs(SALARY) == (SALARY,) and fs.row_of(SALARY) == "employees:E-1"


# --- state_digest + fold (reconcile) ------------------------------------------------------------------------------
def _scripted(store: Store, n: int = 30, seed: int = 7) -> list[SimpleNamespace]:
    """n writes over rows (with and without sensitive fields), deletes and re-creates; returns fake records."""
    rng = random.Random(seed)
    rows = [S17, S22, T3, "tickets:T-4", "employees:E-1"]
    records, live = [], {}
    for seq in range(1, n + 1):
        obj = rng.choice(rows)
        if obj in live and rng.random() < 0.2:
            value = None
        elif obj.startswith("suppliers"):
            value = {"name": f"n{seq}", "iban": rng.choice(["DE89", "GB33", None]), "tax_id": f"t{seq % 3}"}
        elif obj.startswith("employees"):
            value = {"name": "E", "salary": rng.choice([100, 200])}
        else:
            value = {"body": f"b{seq}"}
        ws = row(store, obj, value, author=f"a{seq % 4}", seq=seq)
        live[obj] = value
        if value is None:
            live.pop(obj)
        records.append(SimpleNamespace(seq=seq, write_set=ws))
    return records


def test_state_digest_fold_30_writes(store):
    records = _scripted(store)
    assert sum(len(r.write_set) for r in records) >= 30
    assert fold(records) == store.heads()
    assert state_digest(fold(records)) == store.state_digest() == fold_digest(records)
    flat = [w for r in records for w in r.write_set]
    assert fold_digest(flat) == store.state_digest()  # WriteEntry items fold the same
    # visible_to: folding a prefix of the record equals the store as seen by the next seq
    for k in (0, 10, 29):
        assert fold_digest(records[:k]) == store.state_digest(visible_to=k + 1)


def test_digest_stability(tmp_path):
    a = open_store(tmp_path / "a.db", fields=FIELDS)
    b = open_store(tmp_path / "b.db", fields=FIELDS)
    _scripted(a)
    _scripted(b)
    assert a.state_digest() == b.state_digest()  # same script, same digest
    d = a.state_digest()
    a.read_table("suppliers")
    a.read(S17)
    assert a.state_digest() == d  # reads never change the digest
    a.close()
    a = open_store(tmp_path / "a.db", fields=FIELDS)
    assert a.state_digest() == d  # stable across reopen
    with a.txn():
        a.put(T3, {"body": "unmediated"}, author="x", seq=a.last_seq() + 1, action_id="x-1")
    assert a.state_digest() != d  # any head change moves it
    assert open_store(tmp_path / "e.db").state_digest() == state_digest({})
    a.close()
    b.close()


def test_fold_detects_unchained_writes():
    h1, h2 = value_hash({"a": 1}), value_hash({"a": 2})
    w1 = WriteEntry(obj=T3, before=None, after=VersionRef(ver=1, hash=h1))
    w2 = WriteEntry(obj=T3, before=VersionRef(ver=1, hash=h1), after=VersionRef(ver=2, hash=h2))
    assert fold([w1, w2]) == {T3: VersionRef(ver=2, hash=h2)}
    with pytest.raises(FoldError):
        fold([w2])
    with pytest.raises(FoldError):
        fold([w1, w1])


# --- savepoints / simulate (ADR-05 §7, for B3-24) -----------------------------------------------------------------
def test_dryrun_savepoint(store):
    """A nested simulate() block leaves the store digest unchanged."""
    _scripted(store, n=10)
    d, heads, last = store.state_digest(), store.heads(), store.last_seq()
    side_n = store.conn.execute("SELECT COUNT(*) FROM side").fetchone()[0]
    with store.simulate():
        obj, expect = _restorable(store)
        store.restore(obj, 1, expect=expect, seq=last + 1, action_id="ks-rec-1")
        store.write_row(S17, {"name": "sim", "iban": "SIM0"}, author="billing", seq=last + 2, action_id="b-1")
        assert store.read(S17).value == {"name": "sim", "iban": "SIM0"}  # the block sees its own writes
        with store.simulate():  # nested
            store.write_row(T3, {"body": "inner"}, author="reporter", seq=last + 3, action_id="r-1")
            assert store.get(T3).value == {"body": "inner"}
        with store.savepoint():  # nested, kept until the outer simulate ends
            store.side.redact(store.get(S17).hash)
        assert store.state_digest() != d
    assert store.state_digest() == d and store.heads() == heads and store.last_seq() == last
    assert store.conn.execute("SELECT COUNT(*) FROM side").fetchone()[0] == side_n
    assert not store.conn.in_transaction


def _restorable(store: Store):
    for obj, ref in store.heads().items():
        if ref.ver >= 2:
            return obj, ref.ver
    raise AssertionError("script has no object with two versions")


def test_simulate_inside_caller_txn(store):
    row(store, T3, {"body": "a"}, seq=1)
    with store.txn():
        store.put(T3, {"body": "kept"}, author="x", seq=2, action_id="x-2")
        with store.simulate():
            store.put(T3, {"body": "sim"}, author="x", seq=3, action_id="x-3")
        assert store.get(T3).value == {"body": "kept"} and store.conn.in_transaction
    assert store.get(T3).ver == 2


def test_simulate_rolls_back_on_raise(store):
    row(store, T3, {"body": "a"}, seq=1)
    d = store.state_digest()
    with pytest.raises(RuntimeError), store.simulate():
        store.put(T3, {"body": "sim"}, author="x", seq=2, action_id="x-2")
        raise RuntimeError("boom")
    assert store.state_digest() == d and not store.conn.in_transaction


def test_savepoint_keeps_or_rolls_back(store):
    row(store, T3, {"body": "a"}, seq=1)
    with store.txn():
        with pytest.raises(StateError), store.savepoint():
            store.put(T3, {"body": "partial"}, author="x", seq=2, action_id="x-2")
            store.put(S17, None, author="x", seq=2, action_id="x-2")  # delete of absent: refused
        assert store.get(T3).ver == 1  # only the savepoint's writes were undone
        with store.savepoint():
            store.put(T3, {"body": "b"}, author="x", seq=3, action_id="x-3")
    assert store.get(T3).value == {"body": "b"}
    with store.savepoint():  # outside a transaction: its own BEGIN IMMEDIATE ... COMMIT
        store.put(T3, {"body": "c"}, author="x", seq=4, action_id="x-4")
    assert store.get(T3).ver == 3 and not store.conn.in_transaction


def test_read_set_merge_conflict():
    from ks.state.store import _merge_read_sets
    a = ReadEntry(obj=T3, ver=1, hash=value_hash(1))
    b = ReadEntry(obj=T3, ver=2, hash=value_hash(2))
    assert _merge_read_sets([a], [a]) == (a,)
    with pytest.raises(StateError):
        _merge_read_sets([a], [b])
