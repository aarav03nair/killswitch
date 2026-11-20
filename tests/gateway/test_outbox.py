"""B3-23: outbox items, lineage/sensitive holds, ks.dispatch (F4); every refusal is a record."""

from __future__ import annotations

from ks.contracts import ActionClass, Decision, OutboxItem, OutboxStatus, idempotency_key
from ks.gateway import Execution, OutboxRequest
from ks.world.agents import AGENT_IDS
from ks.world.tools import WorldDispatcher

from . import test_pipeline as tp
from .test_pipeline import A, frame

IBAN = "suppliers:S-17.iban"


class Emit(WorldDispatcher):
    """Reads the supplier (row + iban field) and asks for one effect."""

    def __init__(self, n=1, sink="payments", cls=ActionClass.I1):
        self.n, self.sink, self.cls = n, sink, cls

    def execute(self, env, txn):
        r = txn.store.read("suppliers:S-17")
        return Execution({"queued": True}, r.read_set, (),
                         tuple(OutboxRequest(self.sink, self.cls, {"to": "S-17", "i": i}) for i in range(self.n)))


class Taint:
    def __init__(self):
        self.bad: set[tuple[str, int]] = set()

    def is_tainted(self, obj, ver):
        return (obj, ver) in self.bad


def build(tmp_path, h, taint=None):
    g, keys, ctl, store, ring = tp.build(tmp_path)
    g.config = g.config.model_copy(update={"hold_window_ticks": h})
    g.outbox.config = g.config
    g.outbox.taint = taint
    g.dispatcher = Emit()
    return g, keys, store


def records(g):
    return list(g.recorder.rundir.records())


def item(store, oid="ob-000001"):
    return OutboxItem.from_obj(store.get("outbox:" + oid).value)


def test_item_is_created_in_the_record_with_derived_key_and_lineage(tmp_path):
    g, keys, store = build(tmp_path, 3)
    g.open(1, AGENT_IDS)
    r = g.admit("c-1", frame(keys, action="p1")).record
    assert r.decision == Decision.EXEC and r.outbox_ids == ("ob-000001",)
    it = item(store)
    assert {w.obj for w in r.write_set} == {"outbox:ob-000001"}
    assert it.idempotency_key == idempotency_key(A, "p1", "payments", 0)
    assert it.lineage == tuple(sorted(r.read_set, key=lambda e: (e.obj, e.ver))) and any(e.obj == IBAN for e in it.lineage)
    assert (it.status, it.created_seq, it.author) == (OutboxStatus.QUEUED, r.seq, A)
    # seed iban written at tick 0, H=3: max(1+3, 0+6) = 6
    assert it.release_tick == 6


def test_h0_disables_the_early_hold(tmp_path):
    g, keys, store = build(tmp_path, 0)
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    assert item(store).release_tick == 1


def test_dispatch_record_f4(tmp_path):
    g, keys, store = build(tmp_path, 2)
    g.open(1, AGENT_IDS)
    c = g.admit("c-1", frame(keys, action="p1")).record
    for t in (2, 3):
        g.open(t, AGENT_IDS)
        assert item(store).status == OutboxStatus.QUEUED  # release_tick = max(1+2, 0+2*2) = 4
    n = len(records(g))
    g.open(4, AGENT_IDS)
    d = [r for r in records(g) if r.envelope.tool == "ks.dispatch"]
    assert len(records(g)) == n + 1 and len(d) == 1 and d[0].tick == 4
    d = d[0]
    it = item(store)
    assert it.status == OutboxStatus.DISPATCHED and it.dispatched_seq == d.seq
    assert (d.conn_id, d.envelope.agent_id, d.decision, d.sig_ok) == ("c-0", "ks.gateway", Decision.EXEC, True)
    assert {e.obj for e in d.read_set} == {e.obj for e in c.read_set} | {"outbox:ob-000001"}
    assert [w.obj for w in d.write_set] == ["outbox:ob-000001"]
    assert not d.integrity_problems()


def test_h0_dispatches_next_tick(tmp_path):
    g, keys, store = build(tmp_path, 0)
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    g.open(2, AGENT_IDS)
    assert item(store).status == OutboxStatus.DISPATCHED


def test_tainted_lineage_is_held_at_creation_and_never_dispatches(tmp_path):
    tn = Taint()
    g, keys, store = build(tmp_path, 0, tn)
    tn.bad.add((IBAN, 1))
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    assert item(store).status == OutboxStatus.HELD
    g.open(2, AGENT_IDS)
    g.open(9, AGENT_IDS)
    assert item(store).status == OutboxStatus.HELD and not [r for r in records(g) if r.envelope.tool == "ks.dispatch"]


def test_alert_after_creation_holds_at_release_with_a_control_record(tmp_path):
    tn = Taint()
    g, keys, store = build(tmp_path, 0, tn)
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    tn.bad.add((IBAN, 1))
    g.open(2, AGENT_IDS)
    c = records(g)[-1]
    assert c.envelope.tool == "ks.control" and c.control.op == "hold" and c.control.reason == "lineage_hold"
    assert c.control.target == "outbox:ob-000001" and [w.obj for w in c.write_set] == ["outbox:ob-000001"]
    assert item(store).status == OutboxStatus.HELD and not c.integrity_problems()


def test_sensitive_field_change_after_creation_holds(tmp_path):
    g, keys, store = build(tmp_path, 1)
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    store.conn.execute("BEGIN IMMEDIATE")
    store.put(IBAN, "DE00X", author="crm", seq=store.last_seq() + 1, action_id="w")
    store.conn.execute("COMMIT")
    g.open(2, AGENT_IDS)
    g.open(3, AGENT_IDS)
    c = [r for r in records(g) if r.envelope.tool == "ks.control"]
    assert len(c) == 1 and c[0].control.reason == "sensitive_field" and item(store).status == OutboxStatus.HELD


def test_rerun_reuses_the_object_at_v_plus_1_on_hold(tmp_path):
    g, keys, store = build(tmp_path, 0)
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    # recovery re-runs the same action before release: same key -> same object, back on hold
    store.conn.execute("BEGIN IMMEDIATE")
    from ks.contracts import Envelope
    env = Envelope(agent_id=A, action_id="p1", parent_action_id=None, act_chain=(), tool="x.y", args={}, nonce="0" * 32,
                   expiry_tick=1, epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)
    ids = g.outbox.create((OutboxRequest("payments", ActionClass.I1, {"to": "S-17", "i": 0}),), env,
                          store.last_seq() + 1, 1, ())[1]
    store.conn.execute("COMMIT")
    assert ids == ("ob-000001",) and len(store.history("outbox:ob-000001")) == 2
    assert item(store).status == OutboxStatus.HELD
    g.open(2, AGENT_IDS)
    assert item(store).status == OutboxStatus.HELD


def test_two_effects_in_one_action_get_distinct_ids_and_keys(tmp_path):
    g, keys, store = build(tmp_path, 0)
    g.dispatcher = Emit(2)
    g.open(1, AGENT_IDS)
    r = g.admit("c-1", frame(keys, action="p1")).record
    assert r.outbox_ids == ("ob-000001", "ob-000002")
    assert item(store).idempotency_key != item(store, "ob-000002").idempotency_key


class ForgeOutbox(WorldDispatcher):
    """A tool that writes outbox:* itself (kabir's probe)."""

    def __init__(self, oid="ob-000001"):
        self.oid = oid

    def execute(self, env, txn):
        it = OutboxItem(outbox_id=self.oid, author=A, action_id=env.action_id, created_seq=txn.seq, sink="payments",
                        action_class="I1", payload_hash="0" * 64, idempotency_key="k" * 8, lineage=(),
                        status=OutboxStatus.QUEUED, release_tick=0, dispatched_seq=None)
        w = txn.store.put("outbox:" + self.oid, it.to_obj(), author=A, seq=txn.seq, action_id=env.action_id)
        return Execution({}, (), (w,))


def test_tool_cannot_create_an_outbox_item(tmp_path):
    g, keys, store = build(tmp_path, 3)
    g.dispatcher = ForgeOutbox()
    g.open(1, AGENT_IDS)
    r = g.admit("c-1", frame(keys, action="f1")).record
    assert r.decision == Decision.DENY and r.reason == "tool_error"
    assert store.get("outbox:ob-000001") is None
    for t in range(2, 12):
        g.open(t, AGENT_IDS)
    assert not [x for x in records(g) if x.envelope.tool == "ks.dispatch"]


def test_tool_cannot_flip_a_held_item_to_queued(tmp_path):
    tn = Taint()
    g, keys, store = build(tmp_path, 0, tn)
    tn.bad.add((IBAN, 1))
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    assert item(store).status == OutboxStatus.HELD
    g.dispatcher = ForgeOutbox()
    g.open(2, AGENT_IDS)
    r = g.admit("c-1", frame(keys, action="f1", tick=2)).record
    assert r.decision == Decision.DENY and r.reason == "tool_error"
    g.open(9, AGENT_IDS)
    assert item(store).status == OutboxStatus.HELD and not [x for x in records(g) if x.envelope.tool == "ks.dispatch"]


def test_hold_at_creation_is_a_control_hold_record(tmp_path):
    tn = Taint()
    g, keys, store = build(tmp_path, 0, tn)
    tn.bad.add((IBAN, 1))
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    c = records(g)[-1]
    assert c.envelope.tool == "ks.control" and c.control.op == "hold" and c.control.reason == "lineage_hold"
    assert c.control.target == "outbox:ob-000001" and item(store).status == OutboxStatus.HELD


def test_early_hold_tick_survives_a_restart(tmp_path):
    g, keys, store = build(tmp_path, 3)
    g._seq_tick.clear()  # a fresh process: nothing in memory, the tick comes from the record
    g.open(1, AGENT_IDS)
    g._seq_tick.clear()
    g.admit("c-1", frame(keys, action="p1"))
    assert item(store).release_tick == 6  # not t+H = 4


# --- Kabir probe: an item no record created never dispatches (B3-23 round 3) ----------------------------
def _disp(g):
    return [x for x in records(g) if x.envelope is not None and x.envelope.tool == "ks.dispatch"]


def _holds(g, why="unrecorded_item"):
    return [x for x in records(g) if x.control is not None and x.control.reason == why]


def test_offlog_created_item_is_held_never_dispatched(tmp_path):
    from ks.contracts import OutboxStatus as S
    g, keys, store = build(tmp_path, 0)
    g.open(1, AGENT_IDS)
    store.conn.execute("BEGIN IMMEDIATE")
    it = OutboxItem(outbox_id="ob-000099", author=A, action_id="zz", created_seq=1, sink="payments",
                    action_class="I1", payload_hash="0" * 64, idempotency_key="a" * 64, lineage=(),
                    status=S.QUEUED, release_tick=0, dispatched_seq=None)
    store.put("outbox:ob-000099", it.to_obj(), author=A, seq=g.recorder.seq, action_id="zz")
    store.conn.execute("COMMIT")
    g.open(2, AGENT_IDS)
    assert not _disp(g) and item(store, "ob-000099").status == S.HELD and len(_holds(g)) == 1


def test_raw_sql_flip_of_a_held_item_is_held_again(tmp_path):
    import json
    tn = Taint()
    g, keys, store = build(tmp_path, 0, tn)
    tn.bad.add((IBAN, 1))
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    assert item(store).status == OutboxStatus.HELD
    tn.bad.clear()
    v = json.loads(store.conn.execute("SELECT head_value FROM objects WHERE obj='outbox:ob-000001'").fetchone()[0])
    v["status"], v["lineage"] = "queued", []
    store.conn.execute("UPDATE objects SET head_value=? WHERE obj='outbox:ob-000001'",
                       (json.dumps(v, sort_keys=True, separators=(",", ":")),))
    store.conn.commit()
    g.open(2, AGENT_IDS)
    assert not _disp(g) and item(store).status == OutboxStatus.HELD and len(_holds(g)) == 1



def _held_at_release(tmp_path):
    tn = Taint()
    g, keys, store = build(tmp_path, 0, tn)
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    tn.bad.add((IBAN, 1))
    g.open(2, AGENT_IDS)  # release-phase hold: v2 by ks.control
    assert item(store).status == OutboxStatus.HELD
    tn.bad.clear()
    return g, store


def _roll_head_back(store, drop_row):
    import json
    v1 = store.history("outbox:ob-000001")[0]
    val = store.value_at("outbox:ob-000001", 1)
    if drop_row:
        store.conn.execute("DROP TRIGGER versions_no_delete")
        store.conn.execute("DELETE FROM versions WHERE obj='outbox:ob-000001' AND ver=2")
    store.conn.execute("UPDATE objects SET head_ver=1, head_hash=?, head_value=? WHERE obj='outbox:ob-000001'",
                       (v1.hash, json.dumps(val, sort_keys=True, separators=(",", ":"))))
    store.conn.commit()


def test_head_rolled_back_to_creation_dropping_the_hold_row_is_held_again(tmp_path):
    g, store = _held_at_release(tmp_path)
    _roll_head_back(store, drop_row=True)
    n = len(_holds(g))
    g.open(3, AGENT_IDS)
    assert not _disp(g) and item(store).status == OutboxStatus.HELD and len(_holds(g)) == n + 1


def test_head_rolled_back_keeping_the_hold_row_records_a_hold_not_a_crash(tmp_path):
    g, store = _held_at_release(tmp_path)
    _roll_head_back(store, drop_row=False)
    n = len(_holds(g))
    g.open(3, AGENT_IDS)
    assert not _disp(g) and item(store).status == OutboxStatus.HELD and len(_holds(g)) == n + 1
    assert store.conn.execute("SELECT MAX(ver) FROM versions WHERE obj='outbox:ob-000001'").fetchone()[0] == \
        item_ver(store)
    g.open(4, AGENT_IDS)
    assert not _disp(g)


def item_ver(store):
    return store.get("outbox:ob-000001").ver
