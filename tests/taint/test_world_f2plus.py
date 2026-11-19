"""B3-18 on the real ks.world F2+ run: records built with read_set = adapter reads + the tick's view (I1)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ks.contracts import ObjVer, ReadEntry, merge_read_set
from ks.taint import t0_seq_est, taint_from_alerts
from ks.world.agents import AGENT_IDS, Schedule, step
from ks.world.scenario import build_view, open_world_store, seed_state
from ks.world.tools import WorldDispatcher, WorldTxn

from .fixture import Book, alert

H = 30
IBAN = "suppliers:S-17.iban"


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    store = open_world_store(tmp_path_factory.mktemp("w") / "s.db")
    with store.txn():
        seed_state(store)
    b = Book()
    b.seed({o: store.get(o).value for o in store.heads()})
    disp, log = WorldDispatcher(), {}
    for t in range(1, H + 6):
        if t == H + 3:
            b.suspend("crm", t)  # containment at the control phase after the payment is created (h+2)
        snap = b.next_seq
        for a in AGENT_IDS:
            if a == "crm" and t >= H + 3:
                continue
            view = build_view(store, a, visible_to=snap)
            act = step(a, 11, t, view, Schedule(H, "f2plus"))
            if act is None:
                continue
            seq = b.next_seq
            with store.txn():
                ex = disp.execute(SimpleNamespace(agent_id=a, action_id=act.action_id, tool=act.tool,
                                                  args=act.args), WorldTxn(store, seq))
            rs = merge_read_set([ReadEntry(obj=e.obj, ver=e.ver, hash=e.hash) for e in view], ex.read_set)
            for w in ex.write_set:
                b.head[w.obj] = (w.after.ver, w.after.hash)
            log[(t, a)] = b._seal(tick=t, env=b._env(a, act.tool, act.args, t, act_id=act.action_id), conn="c-1",
                                  reads=list(rs), writes=ex.write_set,
                                  outbox=[f"ob-{seq:06d}"] if ex.outbox else [])
    ev = ObjVer(obj=IBAN, ver=store.history(IBAN)[-1].ver)
    return b, log, ev, taint_from_alerts(b.records, [alert([ev])])


def test_world_hero_seed(world):
    b, log, ev, t = world
    assert t.t0_seq_est == log[(H, "crm")].seq
    assert t.seed == (ObjVer(obj=IBAN, ver=2), ObjVer(obj="suppliers:S-22", ver=2))
    assert {"billing", "payments", "comms", "reporter"} <= set(t.agents)
    assert not {"inventory", "intake"} & set(t.agents)


def test_world_literal_walk_pulls_t0_back(world):
    """B3-45: the literal ADR-05 §4 walk follows crm's view-reads of its own earlier writes; the option C default
    (B3-46) does not, and crm's tool reads at h touch no earlier crm version."""
    b, log, ev, t = world
    assert t0_seq_est(b.records, [ev], "crm", follow_self_reads=True) < log[(H, "crm")].seq


def test_world_triage_kept(world):
    b, log, ev, t = world
    assert log[(H + 2, "triage")].seq not in {r.seq for r in t.actions}


def test_world_docs_independent(world):
    b, log, ev, t = world
    assert "docs" not in t.agents


def test_world_triage_reads_s17_row_untainted(world):
    b, log, ev, t = world
    r = log[(H + 2, "triage")]
    assert "suppliers:S-17" in {e.obj for e in r.read_set} and r.seq not in t.via
    assert IBAN not in {e.obj for e in r.read_set}  # field-object rule (B3-04): row read without .iban
