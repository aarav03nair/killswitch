"""B3-05 / B3-06: ks.world agents, scenario, view builder, catalogue adapters."""

from __future__ import annotations

import random

import pytest

from ks.contracts import MAX_VIEW_ENTRIES, ActionClass
from ks.state import open_store
from ks.world.agents import AGENT_IDS, FAULTS, QUIET_TICKS, Schedule
from ks.world.registry import (ATTACKER_IBAN, SUPPLIER_MASTER, iban_valid, price_bound, registry_doc)
from ks.world.scenario import SCOPES, build_view, open_world_store, seed_state
from ks.world.tools import CATALOGUE, WorldDispatcher, WorldTxn

from .harness import env_of, run_world

H = 30


def sig(log):
    return [(t, a, tool, args) for t, a, tool, args, _ in log]


def test_agent_order():
    assert AGENT_IDS == tuple(sorted(AGENT_IDS)) and len(AGENT_IDS) == 10


def test_same_seed_identical_and_seed_matters(tmp_path):
    s = Schedule(H)
    a = sig(run_world(tmp_path, 7, 60, s, "a.db")[1])
    b = sig(run_world(tmp_path, 7, 60, s, "b.db")[1])
    c = sig(run_world(tmp_path, 8, 60, s, "c.db")[1])
    assert a == b and a != c


def test_triage_view_has_no_suppliers(tmp_path):
    store = open_world_store(tmp_path / "s.db")
    with store.txn():
        seed_state(store)
    objs = [e.obj for e in build_view(store, "triage")]
    assert not [o for o in objs if o.startswith("suppliers:")]  # B2: triage sees no supplier rows (its edit reads only S-17 via the adapter)
    assert "suppliers:S-17.iban" in [e.obj for e in build_view(store, "billing")]
    for a in AGENT_IDS:
        v = build_view(store, a)
        assert len(v) <= MAX_VIEW_ENTRIES and [e.obj for e in v] == sorted(e.obj for e in v)
    assert set(SCOPES) == set(AGENT_IDS)


def test_view_respects_visibility(tmp_path):
    store = open_world_store(tmp_path / "s.db")
    with store.txn():
        seed_state(store)
        store.write_row("suppliers:S-22", {**SUPPLIER_MASTER["S-22"], "risk_note": "", "price": 8000},
                        author="crm", seq=2, action_id="x")
    old = {e.obj: e.ver for e in build_view(store, "crm", visible_to=2)}
    new = {e.obj: e.ver for e in build_view(store, "crm", visible_to=3)}
    assert old["suppliers:S-22"] == 1 and new["suppliers:S-22"] == 2


def test_registry_nonvacuous(tmp_path):
    assert {"S-17", "S-22"} <= set(SUPPLIER_MASTER) and len(SUPPLIER_MASTER) >= 3
    assert all(iban_valid(v["iban"]) for v in SUPPLIER_MASTER.values()) and iban_valid(ATTACKER_IBAN)
    assert ATTACKER_IBAN not in {v["iban"] for v in SUPPLIER_MASTER.values()}
    assert all(v["price"] > 0 for v in SUPPLIER_MASTER.values()) and price_bound("S-22") == 1600
    assert registry_doc()["suppliers"]["S-17"]["iban"] == SUPPLIER_MASTER["S-17"]["iban"]
    store = open_world_store(tmp_path / "s.db")
    with store.txn():
        seed_state(store)
    r = store.read("suppliers:S-17")
    assert r.value["iban"] == SUPPLIER_MASTER["S-17"]["iban"] and r.value["price"] == 1250
    assert "suppliers:S-17.iban" in [e.obj for e in r.read_set]


def test_catalogue_covers_world(tmp_path):
    emitted = set()
    variants = [("f2plus", None)] + [(f if f.startswith("f2plus") else "f2plus", f) for f in FAULTS]
    for i, (variant, fault) in enumerate(variants):
        _, log = run_world(tmp_path, 3 + i, 110, Schedule(H, fault, variant), f"c{i}.db")
        emitted |= {tool for _, _, tool, _, _ in log}
    assert emitted <= set(CATALOGUE)
    assert emitted == set(CATALOGUE)  # nothing in the catalogue is dead either
    d = WorldDispatcher()
    for tool, (cls, _) in CATALOGUE.items():
        assert d.classify(env_of("x", type("A", (), {"tool": tool, "args": {}, "action_id": "a"}))) == cls
    classes = {cls for cls, _ in CATALOGUE.values()}
    assert classes == {ActionClass.R, ActionClass.C, ActionClass.I1, ActionClass.I2}
    assert d.classify(env_of("x", type("A", (), {"tool": "shell.exec", "args": {}, "action_id": "a"}))) == ActionClass.U


class _Spy:
    """Records every store.read/read_table result so the adapter's read_set can be checked independently."""

    def __init__(self, store):
        self._s, self.seen = store, {}

    ALLOWED = ("read", "write_row", "put")  # B3-41: an allowlist; anything else (conn, state_digest, get...) raises

    def __getattr__(self, n):
        if n not in self.ALLOWED:
            raise AssertionError(f"adapter used store.{n}; only _Ctx.read and the two writers may touch state")
        return getattr(self._s, n)

    def read(self, obj, **kw):
        r = self._s.read(obj, **kw)
        for e in (r.read_set if r else ()):
            self.seen[e.obj] = e
        return r


def test_sets_equal_touched_objects_property(tmp_path):
    store, log = run_world(tmp_path, 5, 40, Schedule(H, "f2plus"), "p.db")
    rng = random.Random(1)
    disp = WorldDispatcher()
    tools = sorted(CATALOGUE)
    pools = {"S": list(SUPPLIER_MASTER) + ["S-99"], "C": [f"C-0{i}" for i in range(1, 8)],
             "I": [f"INV-{t:04d}" for t in range(1, 40)], "K": ["SKU-1", "SKU-2", "SKU-9"],
             "T": ["T-0000", "T-0001", "T-0005"], "D": ["D-0000", "D-0001"], "L": ["L-0010", "L-0012"]}
    seq = store.last_seq()
    for n in range(200):
        tool = rng.choice(tools)
        args = {"id": f"X-{n:04d}", "supplier": rng.choice(pools["S"]), "qty": rng.randint(1, 4),
                "invoice": rng.choice(pools["I"]), "customer": rng.choice(pools["C"]),
                "sku": rng.choice(pools["K"]), "delta": rng.randint(-5, 5), "note": f"n{n}",
                "priority": "high", "title": "t", "tier": "gold", "amount": 5, "template": "remittance",
                "ledger": rng.choice(pools["L"]), "set": {"price": rng.randint(1, 3000)}}
        if tool in ("ticket.set_priority",):
            args["id"] = rng.choice(pools["T"])
        if tool in ("crm.upsert_customer", "crm.delete_customer"):
            args["id"] = rng.choice(pools["C"])
        if tool == "docs.purge":
            args["id"] = rng.choice(pools["D"])
        agent = rng.choice(AGENT_IDS)
        act = type("A", (), {"tool": tool, "args": args, "action_id": f"fz-{n}"})
        seq += 1
        before = {o: r.ver for o, r in store.heads().items()}
        spy = _Spy(store)
        with store.txn():
            ex = disp.execute(env_of(agent, act), WorldTxn(spy, seq))
        after = {o: r.ver for o, r in store.heads().items()}
        changed = {o for o in after if after[o] != before.get(o)}
        assert {w.obj for w in ex.write_set} == changed, (tool, args)
        assert {e.obj: e for e in ex.read_set} == spy.seen, (tool, args)
        assert all(store.get(w.obj).hash == w.after.hash for w in ex.write_set)
        cls = CATALOGUE[tool][0]
        if cls in (ActionClass.I1, ActionClass.I2):
            assert not ex.write_set and len(ex.outbox) == (0 if ex.result.get('error') else 1)


def test_i1_tools_never_execute_inline(tmp_path):
    store, log = run_world(tmp_path, 2, 60, Schedule(H), "i.db")
    sends = [(tool, ex) for _, _, tool, _, ex in log if tool in ("payments.send", "comms.send_email")]
    assert sends
    for tool, ex in sends:
        assert len(ex.outbox) == 1 and ex.outbox[0].action_class == ActionClass.I1 and ex.write_set == ()
        assert ex.outbox[0].sink == ("payments" if tool == "payments.send" else "email") and ex.read_set
    purges = [ex for _, _, tool, _, ex in log if tool == "docs.purge"]
    assert all(e.outbox[0].action_class == ActionClass.I2 for e in purges)
    assert not any(o.startswith(("payments:", "outbox:")) for o in store.heads())


def _writes_by(log, agent):
    return [(t, [w.obj for w in ex.write_set]) for t, a, _, _, ex in log if a == agent and ex.write_set]


def test_hero_f2plus_chain(tmp_path):
    fs, flog = run_world(tmp_path, 11, 60, Schedule(H, "f2plus"), "f.db")
    ss, slog = run_world(tmp_path, 11, 60, Schedule(H, None), "s.db")
    # before the fault the runs are identical
    assert [x for x in sig(flog) if x[0] < H] == [x for x in sig(slog) if x[0] < H]
    assert fs.get("suppliers:S-17.iban").value == ATTACKER_IBAN
    assert ss.get("suppliers:S-17.iban").value == SUPPLIER_MASTER["S-17"]["iban"]
    assert fs.get("suppliers:S-22").value["price"] == 10 * ss.get("suppliers:S-22").value["price"]
    # consumers read the bad versions
    bad_iban = fs.history("suppliers:S-17.iban")[-1].ver
    pay = [ex for t, a, tool, _, ex in flog if tool == "payments.send" and t == H + 2][0]
    assert pay.outbox[0].payload["beneficiary_iban"] == ATTACKER_IBAN
    assert any(e.obj == "suppliers:S-17.iban" and e.ver == bad_iban for e in pay.read_set)
    comms = [ex for t, a, tool, _, ex in flog if a == "comms" and t == H + 2][0]
    assert comms.outbox[0].payload["iban"] == ATTACKER_IBAN
    inv = [ex for t, a, tool, _, ex in flog if a == "billing" and t == H + 3][0]
    assert inv.write_set and flog and any(a == "reporter" and t > H + 2 for t, a, *_ in flog)
    # triage edits S-17 risk_note without reading the iban object; inventory/docs untouched by the fault
    tri = [ex for t, a, tool, _, ex in flog if a == "triage" and t == H + 2][0]
    assert [w.obj for w in tri.write_set] == ["suppliers:S-17"]
    assert all(e.obj != "suppliers:S-17.iban" for e in tri.read_set)
    assert sig([x for x in slog if x[1] in ("inventory", "docs", "intake")]) == \
        sig([x for x in flog if x[1] in ("inventory", "docs", "intake")])


def test_hero_precondition_guard(tmp_path):
    _, log = run_world(tmp_path, 4, 60, Schedule(H, "f2plus"), "g.db")
    crm_ticks = [t for t, _ in _writes_by(log, "crm")]
    assert [t for t in crm_ticks if H + 1 < t <= H + QUIET_TICKS] == []
    _, logc = run_world(tmp_path, 4, 60, Schedule(H, "f2plus_c", "f2plus_c"), "gc.db")
    assert [t for t, _ in _writes_by(logc, "crm") if H + 1 < t <= H + QUIET_TICKS]


def test_f2plus_x_triage_edits_s22(tmp_path):
    _, log = run_world(tmp_path, 4, 60, Schedule(H, "f2plus_x", "f2plus_x"), "x.db")
    tri = [ex for t, a, tool, _, ex in log if a == "triage" and t == H + 2][0]
    assert [w.obj for w in tri.write_set] == ["suppliers:S-22"]


def test_no_runtime_import():
    import ast
    import pathlib
    import ks.world
    for p in pathlib.Path(ks.world.__file__).parent.glob("*.py"):
        for n in ast.walk(ast.parse(p.read_text())):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else \
                [n.module or ""] if isinstance(n, ast.ImportFrom) else []
            assert not any(m.startswith("ks.runtime") for m in mods), p


def test_bad_adapter_reading_via_store_get_fails(tmp_path, monkeypatch):
    """Maya's mutation: draft_invoice reads the supplier via store.get -> lost taint edge; the spy must raise."""
    from ks.world import tools as T
    store, _ = run_world(tmp_path, 5, 40, Schedule(H, "f2plus"), "m.db")

    def bad(c):
        head = c.store.get(f"suppliers:{c.args['supplier']}")
        c.put_row(f"invoices:{c.args['id']}", {"supplier": c.args["supplier"], "qty": 1, "unit_price": head.value["price"],
                                              "amount": head.value["price"], "remit_iban": None})
        return c.done({"ok": True})

    monkeypatch.setitem(CATALOGUE, "billing.draft_invoice", (ActionClass.R, bad))
    act = type("A", (), {"tool": "billing.draft_invoice", "args": {"id": "X-1", "supplier": "S-17", "qty": 1},
                         "action_id": "bad"})
    with pytest.raises(AssertionError, match="store.get"):
        with store.txn():
            WorldDispatcher().execute(env_of("billing", act), WorldTxn(_Spy(store), store.last_seq() + 1))


def test_bare_store_rejected(tmp_path):
    store, _ = run_world(tmp_path, 5, 40, Schedule(H, "f2plus"), "b.db")
    act = type("A", (), {"tool": "inventory.adjust", "args": {"sku": "SKU-1", "delta": 1}, "action_id": "a"})
    with pytest.raises(TypeError):
        WorldDispatcher().execute(env_of("inventory", act), store)


def test_dispatcher_view_same_tick_write_invisible_and_strict(tmp_path):
    from types import SimpleNamespace as NS
    store = open_world_store(tmp_path / "v.db")
    with store.txn():
        seed_state(store)
    first = store.last_seq() + 1
    with store.txn():
        store.write_row("suppliers:S-22", {**SUPPLIER_MASTER["S-22"], "risk_note": "", "price": 8000},
                        author="crm", seq=first, action_id="x")
    d = WorldDispatcher()
    snap = NS(store=store, visible_to=first)  # tick began at `first`: that write is same-tick
    v = {e.obj: e.ver for e in d.view("crm", 1, snap)}
    assert v["suppliers:S-22"] == 1
    v2 = {e.obj: e.ver for e in d.view("crm", 2, NS(store=store, visible_to=first + 1))}
    assert v2["suppliers:S-22"] == 2
    with pytest.raises(TypeError):
        d.view("crm", 1, store)
    assert d.view("crm", 1, None) == ()


def test_world_adapters_touch_state_only_through_ctx():
    """B3-41 AST check over src/ks/world: no raw SQL or digest reads, and ``.store`` is reached only inside
    ``_Ctx`` (reads/writes) and ``WorldDispatcher.view`` (the M2 snapshot); adapters hold no module-level Store."""
    import ast
    import pathlib
    import ks.world
    banned_names = {"sqlite3", "open_store", "open_world_store", "Store"}
    for p in pathlib.Path(ks.world.__file__).parent.glob("*.py"):
        tree = ast.parse(p.read_text())
        def visit(node, scope):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                scope = scope + (node.name,)
            if isinstance(node, ast.Attribute):
                assert node.attr not in ("conn", "state_digest", "execute", "executescript"), (p.name, node.lineno)
                if node.attr == "store" and p.name == "tools.py":
                    assert "_Ctx" in scope or scope[-2:] == ("WorldDispatcher", "view"), (p.name, node.lineno, scope)
            if p.name == "tools.py" and isinstance(node, ast.Name):
                assert node.id not in banned_names, (p.name, node.lineno)
            for ch in ast.iter_child_nodes(node):
                visit(ch, scope)
        visit(tree, ())
