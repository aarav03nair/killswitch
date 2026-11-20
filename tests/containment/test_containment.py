"""B3-19: alert -> suspend (epoch fence), release, hold/unhold (F9 gateway side), time-to-contain from records."""

from __future__ import annotations

import json

from ks.containment import Containment, MonitorLoop, contain_times, writes_after
from ks.contracts import (CONTROL_TOOL, Control, ControlOp, Decision, OutboxStatus, Reason)
from ks.gateway.control import FoldedControl
from ks.gateway.system import system_envelope
from ks.policy import WorldPolicy
from ks.world.agents import AGENT_IDS

from tests.gateway import test_outbox as to
from tests.gateway import test_pipeline as tp
from tests.gateway.test_pipeline import frame

BAD = "GB00BADBADBADBAD"
CRM_SET = {"supplier": "S-17", "set": {"iban": BAD}}


def folded(tmp_path, **kw):
    g, keys, ctl, store, ring = tp.build(tmp_path, **kw)
    g.control = FoldedControl(AGENT_IDS)
    g.bind("c-2", "crm")
    return g, keys, store


def operator(g, keys, op, target, n, *, auto=False, who="ks.operator"):
    kind, ident = target.split(":", 1)
    epoch = g.control.next_epoch(ident) if kind == "agent" else None
    seq = g.recorder.seq + 1
    ctl = Control(control_id=f"k-{seq:06d}", op=ControlOp(op), target=target, epoch=epoch, alert_id=None,
                  issued_by=who, auto=auto, reason="test")
    env = system_envelope(who, CONTROL_TOOL, ctl.to_obj(), action_id=f"op-{n}", tick=g._tick, sign=keys.signer(who))
    return g.admit_system(env).record


def crm(keys, **kw):
    return frame(keys, agent="crm", tool="crm.update_supplier", args=CRM_SET, **kw)


def test_hard_alert_suspends_in_the_same_tick_and_the_culprit_writes_nothing_after(tmp_path):
    g, keys, store = folded(tmp_path)
    loop = MonitorLoop(g, keys.signer("ks.monitor"), state=store, side=store.side)
    g.open(1, AGENT_IDS)
    bad = g.admit("c-2", crm(keys, tick=1, action="c1")).record
    assert bad.decision == Decision.EXEC and bad.write_set
    adms = loop.step()                                   # still tick 1: before the next open
    recs = list(g.recorder.rundir.records())
    ctl = [r for r in recs if r.control and r.control.op == ControlOp.SUSPEND]
    assert [r.tick for r in recs if r.envelope.tool == "ks.alert"] == [1] and len(ctl) == 1 and adms
    s = ctl[0]
    assert (s.tick, s.control.target, s.control.auto, s.control.issued_by) == (1, "agent:crm", True, "ks.monitor")
    assert s.control.epoch == 1 and s.control.alert_id == "a-000001" and s.sig_ok and not s.integrity_problems()
    assert s.seq > bad.seq
    # the fence: the same epoch-0 envelope, one tick later, is refused
    g.open(2, AGENT_IDS)
    again = g.admit("c-2", crm(keys, tick=2, action="c2")).record
    assert (again.decision, again.reason) == (Decision.DENY, Reason.SUSPENDED)
    assert writes_after(recs + [again], "crm", s.seq) == []
    [t] = contain_times(g.recorder.rundir.path)
    assert (t.target, t.alert_tick, t.contain_tick, t.ticks) == ("agent:crm", 1, 1, 0) and t.contain_seq == s.seq
    assert loop.step() == []                             # deduped: no second suspend


def test_second_hard_alert_does_not_bump_the_epoch_twice(tmp_path):
    g, keys, store = folded(tmp_path)
    loop = MonitorLoop(g, keys.signer("ks.monitor"), state=store, side=store.side)
    g.open(1, AGENT_IDS)
    g.admit("c-2", crm(keys, tick=1, action="c1"))
    loop.step()
    g.open(2, AGENT_IDS)
    assert g.control.fold.max_epoch("crm") == 1 and g.control.agent_denial("crm") == Reason.SUSPENDED
    g.recorder.rundir  # noqa: B018
    assert sum(1 for r in g.recorder.rundir.records() if r.control and r.control.op == ControlOp.SUSPEND) == 1


def test_release_gives_a_strictly_higher_epoch_and_presigned_envelopes_stay_dead(tmp_path):
    g, keys, store = folded(tmp_path)
    loop = MonitorLoop(g, keys.signer("ks.monitor"), state=store, side=store.side)
    g.open(1, AGENT_IDS)
    g.admit("c-2", crm(keys, tick=1, action="c1"))
    loop.step()
    g.open(2, AGENT_IDS)
    rel = operator(g, keys, "release", "agent:crm", 1)
    assert rel.decision == Decision.EXEC and rel.control.epoch == 2 > 1
    old0 = g.admit("c-2", crm(keys, tick=2, action="c3", epoch=0)).record  # presigned before the suspend
    old1 = g.admit("c-2", crm(keys, tick=2, action="c4", epoch=1)).record  # signed at the suspend epoch
    assert (old0.decision, old0.reason) == (Decision.DENY, Reason.STALE_EPOCH)
    assert (old1.decision, old1.reason) == (Decision.DENY, Reason.STALE_EPOCH)
    new = g.admit("c-2", crm(keys, tick=2, action="c5", epoch=2)).record
    assert new.decision == Decision.EXEC
    assert g.open(3, AGENT_IDS)["crm"].epoch == 2


def test_revoke_is_permanent_and_release_after_revoke_is_refused(tmp_path):
    g, keys, store = folded(tmp_path)
    g.open(1, AGENT_IDS)
    assert operator(g, keys, "revoke", "agent:crm", 1).decision == Decision.EXEC
    r = g.admit("c-2", crm(keys, tick=1, action="c1", epoch=1)).record
    assert (r.decision, r.reason) == (Decision.DENY, Reason.REVOKED)
    assert operator(g, keys, "release", "agent:crm", 2).reason == Reason.TOOL_ERROR


def test_signature_alert_suspends_the_connection_never_the_claimed_agent(tmp_path):
    g, keys, store = folded(tmp_path)
    loop = MonitorLoop(g, keys.signer("ks.monitor"), state=store, side=store.side)
    g.open(1, AGENT_IDS)
    g.admit("c-2", frame(keys, agent="crm", signer="docs", tool="crm.update_supplier", args=CRM_SET, tick=1,
                         action="f1"))                       # crm's id signed with docs' key
    loop.step()
    ctl = [r.control for r in g.recorder.rundir.records() if r.control and r.control.op == ControlOp.SUSPEND]
    assert [c.target for c in ctl] == ["conn:c-2"] and ctl[0].epoch is None
    assert g.control.agent_denial("crm") is None and g.control.epoch_of("crm") == 0


# --- hold / unhold (F9) -------------------------------------------------------------------------------------
def held_item(tmp_path):
    tn = to.Taint()
    g, keys, store = to.build(tmp_path, 0, tn)
    g.control = FoldedControl(AGENT_IDS)
    tn.bad.add((to.IBAN, 1))
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    assert to.item(store).status == OutboxStatus.HELD
    return g, keys, store, tn


def test_unhold_outbox_requeues_and_the_dispatcher_rechecks_taint(tmp_path):
    g, keys, store, tn = held_item(tmp_path)
    g.open(2, AGENT_IDS)
    r = operator(g, keys, "unhold", "outbox:ob-000001", 1)
    assert r.decision == Decision.EXEC and [w.obj for w in r.write_set] == ["outbox:ob-000001"]
    assert to.item(store).status == OutboxStatus.QUEUED and not r.integrity_problems()
    g.open(3, AGENT_IDS)                                     # taint still there: held again, never dispatched
    assert to.item(store).status == OutboxStatus.HELD
    assert not [x for x in to.records(g) if x.envelope.tool == "ks.dispatch"]
    tn.bad.clear()                                           # a human cleared the taint
    assert operator(g, keys, "unhold", "outbox:ob-000001", 2).decision == Decision.EXEC
    g.open(4, AGENT_IDS)
    assert to.item(store).status == OutboxStatus.DISPATCHED
    # an unhold of an item that is not held is a recorded deny and changes nothing
    r = operator(g, keys, "unhold", "outbox:ob-000001", 3)
    assert (r.decision, r.reason) == (Decision.DENY, Reason.TOOL_ERROR) and not r.write_set


def test_hold_a_queued_item_then_it_never_dispatches(tmp_path):
    g, keys, store = to.build(tmp_path, 3)
    g.control = FoldedControl(AGENT_IDS)
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys, action="p1"))
    assert to.item(store).status == OutboxStatus.QUEUED
    r = operator(g, keys, "hold", "outbox:ob-000001", 1, auto=True, who="ks.monitor")
    assert r.decision == Decision.EXEC and to.item(store).status == OutboxStatus.HELD
    g.open(9, AGENT_IDS)
    assert not [x for x in to.records(g) if x.envelope.tool == "ks.dispatch"]


def purge_frame(keys, tick, action, epoch=0):
    return frame(keys, agent="docs", tool="docs.purge", args={"id": "D-0000"}, tick=tick, action=action, epoch=epoch)


def held_action(tmp_path):
    g, keys, ctl, store, ring = tp.build(tmp_path, policy=WorldPolicy())
    g.control = FoldedControl(AGENT_IDS)
    g.bind("c-3", "docs")
    g.open(1, AGENT_IDS)
    h = g.admit("c-3", purge_frame(keys, 1, "d1")).record
    assert (h.decision, h.reason) == (Decision.HOLD, Reason.NEEDS_APPROVAL)
    return g, keys, store, h


def test_unhold_action_reexecutes_once_citing_the_hold(tmp_path):
    g, keys, store, h = held_action(tmp_path)
    g.open(5, AGENT_IDS)                                     # nonce and expiry are not re-checked (M10)
    n = g.recorder.seq
    c = operator(g, keys, "unhold", f"action:{h.record_id}", 1)
    recs = list(g.recorder.rundir.records())
    assert c.decision == Decision.EXEC and recs[-1].seq == n + 2
    r = recs[-1]
    assert (r.reexec_of, r.decision, r.conn_id, r.envelope_hash) == (h.seq, Decision.EXEC, "c-3", h.envelope_hash)
    assert r.envelope.agent_id == "docs" and r.sig_ok and r.outbox_ids and not r.integrity_problems()
    assert r.tick == 5 and r.seq > c.seq
    again = operator(g, keys, "unhold", f"action:{h.record_id}", 2)          # F9: once
    assert (again.decision, again.reason) == (Decision.DENY, Reason.TOOL_ERROR)
    assert [x.reexec_of for x in g.recorder.rundir.records() if x.reexec_of] == [h.seq]


def test_unhold_action_is_refused_once_the_agent_is_fenced(tmp_path):
    g, keys, store, h = held_action(tmp_path)
    g.open(2, AGENT_IDS)
    operator(g, keys, "suspend", "agent:docs", 1)
    r = operator(g, keys, "unhold", f"action:{h.record_id}", 2)
    assert (r.decision, r.reason) == (Decision.DENY, Reason.TOOL_ERROR)
    operator(g, keys, "release", "agent:docs", 3)             # epoch 2 now: the held envelope (epoch 0) is stale
    r = operator(g, keys, "unhold", f"action:{h.record_id}", 4)
    assert r.decision == Decision.DENY and not [x for x in g.recorder.rundir.records() if x.reexec_of]


def test_auto_issuers_cannot_unhold_an_action(tmp_path):
    g, keys, store, h = held_action(tmp_path)
    r = operator(g, keys, "unhold", f"action:{h.record_id}", 1, auto=True, who="ks.monitor")
    assert (r.decision, r.reason) == (Decision.DENY, Reason.TOOL_ERROR)
    r = operator(g, keys, "unhold", "action:r-000001", 2)      # the seed record is not a hold
    assert r.decision == Decision.DENY


def test_clean_world_run_with_the_monitor_on_suspends_nobody(tmp_path):
    """RunOptions(monitor=True) over the 10-agent world: no fault, so no hard alert and no suspension (anti-framing)."""
    from ks.contracts import RunDir
    from ks.runtime import RunOptions
    from ks.runtime.run import run
    res = run(scenario="world", agents=None, ticks=14, seed=5, key_mode="fresh", out=tmp_path / "r",
              say=lambda s: None, options=RunOptions(monitor=True))
    recs = list(RunDir(res.rundir.path).records())
    assert not [r for r in recs if r.control and r.control.op == ControlOp.SUSPEND]
    assert contain_times(res.rundir.path) == []
