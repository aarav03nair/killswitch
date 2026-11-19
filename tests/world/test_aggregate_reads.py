"""B3-16 (Kabir F7): every aggregate/scan adapter records every row it read plus those rows' field objects.
A scan that finds nothing records no read (absence reads are deferred to 2.0; ADR-05 Amendments)."""

from __future__ import annotations

from types import SimpleNamespace

from ks.world.registry import SUPPLIER_MASTER
from ks.world.scenario import open_world_store, seed_state
from ks.world.tools import CATALOGUE, WorldDispatcher, WorldTxn

AGGREGATE = {"docs.write"}
"""Adapters that read a variable list of rows (scan). Every catalogue tool is in exactly one of the two sets."""
JOIN = {"payments.send", "comms.send_email", "billing.draft_invoice", "ledger.post",
        "compliance.record_finding", "supplier.set_risk_note", "crm.update_supplier", "crm.upsert_customer",
        "crm.delete_customer", "inventory.adjust", "ticket.set_priority", "billing.issue_credit", "docs.purge"}
"""Point or fixed-join adapters: a fixed, small number of named rows."""
NO_READ = {"ticket.create"}


def test_every_adapter_is_classified():
    assert AGGREGATE | JOIN | NO_READ == set(CATALOGUE)
    assert not (AGGREGATE & JOIN) and not (NO_READ & AGGREGATE) and not (NO_READ & JOIN)


def _run(store, seq, agent, tool, args):
    env = SimpleNamespace(agent_id=agent, action_id=f"{agent}-{seq}", tool=tool, args=args)
    with store.txn():
        return WorldDispatcher().execute(env, WorldTxn(store, seq))


def _store(tmp_path, n_inv=5):
    store = open_world_store(tmp_path / "a.db")
    with store.txn():
        seed_state(store)
    seq = 1
    for i in range(1, n_inv + 1):
        seq += 1
        _run(store, seq, "billing", "billing.draft_invoice",
             {"id": f"INV-{i:04d}", "supplier": ("S-17", "S-22")[i % 2], "qty": i})
    return store, seq


def test_docs_write_lists_every_invoice_read(tmp_path):
    store, seq = _store(tmp_path)
    ids = [f"INV-{i:04d}" for i in range(1, 6)]
    ex = _run(store, seq + 1, "reporter", "docs.write", {"id": "RPT-1", "title": "r", "invoices": ids})
    assert {e.obj for e in ex.read_set} == {f"invoices:{i}" for i in ids}
    for e in ex.read_set:  # each entry carries the version and hash actually read
        g = store.get(e.obj)
        assert (e.ver, e.hash) == (g.ver, g.hash)


def test_aggregate_over_sensitive_rows_lists_field_objects(tmp_path):
    store, seq = _store(tmp_path)
    r = store.read_table("suppliers")
    objs = {e.obj for e in r.read_set}
    assert objs == {f"suppliers:{p}" for p in SUPPLIER_MASTER} | {f"suppliers:{p}.iban" for p in SUPPLIER_MASTER}
    # projection that omits the sensitive key lists rows only (a field-only edit stays invisible to it)
    r2 = store.read_table("suppliers", project=("price",))
    assert {e.obj for e in r2.read_set} == {f"suppliers:{p}" for p in SUPPLIER_MASTER}


def test_join_adapters_list_row_and_field_objects(tmp_path):
    store, seq = _store(tmp_path)
    pay = _run(store, seq + 1, "payments", "payments.send", {"id": "P1", "invoice": "INV-0001"})
    objs = {e.obj for e in pay.read_set}
    assert {"invoices:INV-0001", "suppliers:S-22", "suppliers:S-22.iban"} <= objs
    mail = _run(store, seq + 2, "comms", "comms.send_email", {"id": "E1", "template": "r", "invoice": "INV-0002"})
    assert {"invoices:INV-0002", "suppliers:S-17", "suppliers:S-17.iban"} <= {e.obj for e in mail.read_set}
    inv = _run(store, seq + 3, "billing", "billing.draft_invoice", {"id": "INV-9", "supplier": "S-11", "qty": 1})
    assert {e.obj for e in inv.read_set} == {"suppliers:S-11", "suppliers:S-11.iban"}


def test_scan_that_finds_nothing_records_no_read(tmp_path):
    store, seq = _store(tmp_path, n_inv=0)
    assert store.read_table("invoices").read_set == ()  # empty table: no read, documented limitation
    ex = _run(store, seq + 1, "reporter", "docs.write", {"id": "RPT-1", "title": "r", "invoices": ["INV-0001"]})
    assert ex.read_set == ()
    ex2 = _run(store, seq + 2, "reporter", "docs.write", {"id": "RPT-2", "title": "r", "invoices": []})
    assert ex2.read_set == () and ex2.write_set  # the report is still written
