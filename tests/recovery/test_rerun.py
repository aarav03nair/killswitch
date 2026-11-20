"""B3-24: re-run simulation in a savepoint (ADR-05 §6.3 M14, §7; CALL-02 B2/B3; M8 halt at the first stale step).

End to end on the real ks.world F2+ records (tests/recovery/world.py): taint -> plan -> dry-run with
ToolRerunner(WorldDispatcher) -> compare the simulated state with S* (same seed, fault off)."""

from __future__ import annotations

import pytest

from ks.contracts import ActionClass, ObjVer, OutboxItem, OutboxStatus, idempotency_key, value_hash
from ks.gateway.dispatch import Execution, OutboxRequest
from ks.recovery import (C_IDENTICAL, ArgsUnavailable, StaleRerun, ToolRerunner, args_from_mapping, args_from_sidestore, dry_run,
                         plan_recovery, render)
from ks.state import StaleExpect
from ks.taint import taint_from_alerts
from ks.world.tools import WorldDispatcher

from . import world as W
from .fixture import H as FH, IBAN as FIBAN, alert, seeded


def ops(plan, op):
    return [s for s in plan.steps if s.op == op]


def _plan(w):
    return plan_recovery(w.records, w.taint, alert_id="a-000001", state=w.store)


def _dry(w, pl=None, args=None, **kw):
    rr = ToolRerunner(WorldDispatcher(), args_from_mapping(w.args if args is None else args))
    return dry_run(w.store, pl or _plan(w), rerunner=rr, **kw)


@pytest.fixture(scope="module")
def hero(tmp_path_factory):
    d = tmp_path_factory.mktemp("hero")
    w = W.run(d / "f2plus.db")
    s = W.run(d / "sstar.db", fault=None)
    digest = w.store.state_digest()
    held_before = _snapshot(w)
    rr = ToolRerunner(WorldDispatcher(), args_from_sidestore(w.rundir.path))  # args as the gateway stored them
    dr = dry_run(w.store, _plan(w), rerunner=rr)
    return w, s, digest, dr, held_before


def _snapshot(w):
    return {oid: (it.status, it.release_tick) for oid, it in w.items().items()}


def _final(w, dr):
    out = {o: r.hash for o, r in w.store.heads().items()}
    out.update({e.obj: e.planned_hash for e in dr.plan.diff})
    return out


def _tainted_dispatches(w):
    """ks.dispatch records whose read set (lineage + outbox object) touches a tainted version: escaped effects."""
    return [r for r in w.records if r.envelope is not None and r.envelope.tool == "ks.dispatch"
            and any(w.taint.is_tainted(e.obj, e.ver) for e in r.read_set)]


def _holds(w):
    return {r.control.target.removeprefix("outbox:"): (r.tick, r.control.reason) for r in w.records
            if r.control is not None and r.control.op.value == "hold"}


# --- hero (B2): before recovery the gateway holds every tainted effect -----------------------------------------------
def test_hero_tainted_effects_held_by_the_gateway_before_recovery(hero):
    """The real release phase ran every tick: every tainted item is HELD by a ks.control hold record (lineage_hold),
    none is dispatched, no ks.dispatch record touches a tainted version (R = 0 from effects)."""
    w, s, digest, dr, before = hero
    tainted = w.taint.outbox_ids
    assert tainted and _tainted_dispatches(w) == []
    holds = _holds(w)
    for oid in tainted:
        assert before[oid][0] == OutboxStatus.HELD, oid
        assert holds[oid][1] == "lineage_hold", oid
    # payments/comms of h+2 were queued (taint off at creation) and held by the release phase on their due tick;
    # those of h+4 were created after containment and held at creation
    for t, how in ((W.H + 2, "release"), (W.H + 4, "creation")):
        for a in ("payments", "comms"):
            (oid,) = w.log[(t, a)].outbox_ids
            tick, _ = holds[oid]
            assert tick == (before[oid][1] if how == "release" else t), (a, t, how)
    # honest items before the fault still left the boundary (the outbox is not frozen)
    assert any(it.status == OutboxStatus.DISPATCHED for it in w.items().values())


def test_hero_rerun_set_and_plan_shape(hero):
    w, s, digest, dr, _ = hero
    p = dr.plan
    assert {r.agent_id for r in dr.outcomes.values()} >= {"billing", "payments", "comms", "reporter"}
    assert not {r.agent_id for r in dr.outcomes.values()} & {"triage", "inventory", "docs", "intake", "crm"}
    assert ops(p, "replan") == [] and ops(p, "cancel_outbox") == []
    assert {x.obj for x in ops(p, "restore")} == {W.IBAN, W.S22}
    assert dr.reemitted == 0 and dr.stale is None
    assert all(o.error is None for o in dr.outcomes.values())
    # billing.issue_credit at h+4 is class C (the gateway's classify), view-tainted, no compensator: the planner
    # flags it, the dry-run clears it (maya's ruling, narrowed A) -> rerun(c_rerun_identical), see test_hero_zero_flags
    assert [(f.reason, f.action.action_id) for f in ops(dr.planned.plan, "flag")] == \
        [("no_compensator", f"billing-t{W.H + 4}")]


def test_hero_zero_flags(hero):
    """ADR-05 golden: 0 flags. The class-C credit's flag is dropped only because (1) its landed record has no outbox
    item and (2) the simulated re-run's writes equal the landed ones by (obj, after.hash). It stays visible: a
    rerun(c_rerun_identical) step in the plan, a ClassC verdict and a 'class C' line in the dry-run."""
    w, s, digest, dr, _ = hero
    p = dr.plan
    assert ops(p, "flag") == []
    c = w.log[(W.H + 4, "billing")]
    assert c.action_class == ActionClass.C and c.outbox_ids == ()
    (step,) = [x for x in ops(p, "rerun") if x.reason == C_IDENTICAL]
    assert step.action.seq == c.seq and step.action.action_id == f"billing-t{W.H + 4}"
    v = dr.class_c[c.seq]
    assert v.cleared and v.outcome.changed == () and v.outcome.effects == () and v.outcome.error is None
    text = render(dr)
    assert f"class C      billing-t{W.H + 4} seq {c.seq} billing.issue_credit: re-run identical, no compensation " \
           f"needed" in text
    assert "flags 0" in text
    # the credit the taint touched is the credit the honest world issues
    for wr in c.write_set:
        assert _final(w, dr)[wr.obj] == s.store.get(wr.obj).hash
    # rerun steps stay in seq order (the cleared step sits at its seq position)
    seqs = [x.action.seq for x in ops(p, "rerun")]
    assert seqs == sorted(seqs)


class _CreditDiffers:
    """Dispatcher that changes what billing.issue_credit writes (or adds an outbox request): negative tests."""

    def __init__(self, mode):
        self.inner, self.mode = WorldDispatcher(), mode

    def classify(self, env):
        return self.inner.classify(env)

    def execute(self, call, txn):
        if call.tool == "billing.issue_credit":
            if self.mode == "amount":
                call = type(call)(**{**vars(call), "args": {**call.args, "amount": call.args["amount"] + 1}})
            elif self.mode == "outbox":
                ex = self.inner.execute(call, txn)
                return Execution(ex.result, ex.read_set, ex.write_set,
                                 (OutboxRequest("email", ActionClass.I1, {"credit": call.args["id"]}),))
        return self.inner.execute(call, txn)


@pytest.mark.parametrize("mode,why", [("amount", "re-run writes differ: credits:"),
                                      ("outbox", "re-run makes an outbox request")])
def test_class_c_rerun_that_differs_keeps_no_compensator_flag(hero, mode, why):
    """Narrowed A, negative: a class-C re-run whose writes differ (or that asks for an external effect) keeps
    flag(no_compensator); its simulated writes are rolled back (no diff entry, no rerun step) and the dry-run says why."""
    w, s, digest, _, _ = hero
    c = w.log[(W.H + 4, "billing")]
    rr = ToolRerunner(_CreditDiffers(mode), args_from_sidestore(w.rundir.path))
    d = dry_run(w.store, _plan(w), rerunner=rr)
    assert [(f.reason, f.action.seq) for f in ops(d.plan, "flag")] == [("no_compensator", c.seq)]
    assert not [x for x in ops(d.plan, "rerun") if x.reason == C_IDENTICAL or x.action.seq == c.seq]
    v = d.class_c[c.seq]
    assert not v.cleared and why in v.why
    assert c.seq not in d.outcomes and not {wr.obj for wr in c.write_set} & {e.obj for e in d.plan.diff}
    assert f"flag(no_compensator) kept: {why}" in render(d) and "flags 1" in render(d)
    assert w.store.state_digest() == digest


def test_class_c_without_rerunner_keeps_flag(hero):
    """No simulation, no proof: the planner's flag stands."""
    w = hero[0]
    d = dry_run(w.store, _plan(w))
    assert [f.reason for f in ops(d.plan, "flag")] == ["no_compensator"] and d.class_c == {}


def test_hero_payment_same_outbox_id_v_plus_1_back_on_hold(hero):
    """B2/M14: after recovery the payments item is the same outbox:<id> at v+1 of its head (the gateway's hold
    version), status held, release_tick and author unchanged, payload back to the S* payload."""
    w, s, digest, dr, before = hero
    pay = w.log[(W.H + 2, "payments")]
    (oid,) = pay.outbox_ids
    o = dr.outcomes[pay.seq]
    (e,) = o.effects
    assert (e.outbox_id, e.disposition) == (oid, "reheld")
    assert e.payload_hash != e.original_payload_hash           # the beneficiary IBAN changed back
    (ow,) = o.outbox_writes
    head = w.store.get(f"outbox:{oid}")
    assert ow.obj == f"outbox:{oid}" and ow.before.ver == head.ver == 2 and ow.after.ver == 3
    assert {d.obj: d.planned_hash for d in dr.plan.diff}[ow.obj] == ow.after.hash
    assert set(dr.reheld) == set(w.taint.outbox_ids)
    assert e.payload_hash == s.payloads[pay.envelope.action_id]


def test_hero_every_tainted_item_reheld_none_dispatched_or_new(hero):
    w, s, digest, dr, before = hero
    eff = [e for o in dr.outcomes.values() for e in o.effects]
    # reheld_same: comms remittance emails carry no beneficiary, their payload is unchanged by the restore
    assert {e.disposition for e in eff} <= {"reheld", "reheld_same"} and dr.reemitted == 0
    hero_pay = {w.log[(t, "payments")].envelope.action_id for t in (W.H + 2, W.H + 4)}  # S-17 iban, S-22 price
    assert {o.action_id for o in dr.outcomes.values() if any(e.disposition == "reheld" for e in o.effects)} \
        >= hero_pay
    assert {e.outbox_id for e in eff} == set(w.taint.outbox_ids)


def test_rerun_reheld_item_equals_gateway_outbox_create(hero):
    """Fidelity: the re-held version the re-runner writes is exactly what ks.gateway.outbox.Outbox.create writes
    for a re-created key with lineage = the re-run's tool reads (same state, same seq)."""
    from types import SimpleNamespace

    from ks.contracts import merge_read_set
    from ks.gateway import GatewayTxn
    from ks.gateway.outbox import Outbox

    w, s, digest, dr, _ = hero
    pay = w.log[(W.H + 2, "payments")]
    step = next(x for x in ops(dr.planned.plan, "rerun") if x.action.seq == pay.seq)
    seq, env = w.next_seq + 500, pay.envelope
    with w.store.simulate():
        o = ToolRerunner(WorldDispatcher(), args_from_mapping(w.args))(w.store, step, pay, seq)
    with w.store.simulate():
        call = SimpleNamespace(agent_id=env.agent_id, action_id=env.action_id, tool=env.tool,
                               args=w.args[env.args_hash])
        ex = WorldDispatcher().execute(call, GatewayTxn(w.store, seq))
        ow, _ = Outbox(w.store, w.gateway.config).create(ex.outbox, call, seq, pay.tick,
                                                         merge_read_set((), ex.read_set))
    assert [(x.obj, x.before, x.after) for x in o.outbox_writes] == [(x.obj, x.before, x.after) for x in ow]


def test_hero_simulated_state_equals_sstar(hero):
    """C = 0 in state: after restores + re-runs every object equals S* (same seed, fault off), and every re-held
    payload equals the S* payload of the same action."""
    w, s, digest, dr, _ = hero
    star = {o: r.hash for o, r in s.store.heads().items() if not o.startswith("outbox:")}
    final = {o: h for o, h in _final(w, dr).items() if not o.startswith("outbox:")}
    assert final == star
    for o in dr.outcomes.values():
        for e in o.effects:
            assert e.payload_hash == s.payloads[o.action_id], o.action_id


def test_hero_triage_kept_and_lanes(hero):
    w, s, digest, dr, _ = hero
    assert [(k.obj, k.author) for k in dr.planned.kept] == [("suppliers:S-17", "triage")]
    text = render(dr)
    assert "kept         suppliers:S-17" in text and "reemitted 0" in text and "flags 0" in text
    assert "pending simulation" not in text


def test_demo_hold_window_h6_holds_every_tainted_effect(tmp_path):
    """ADR-06 demo H = 6, run past h + 12 so the h+2 items fall due: still no tainted dispatch, every tainted item
    held. (No S* compare: crm is suspended here but works on in S* after its quiet window.)"""
    w = W.run(tmp_path / "h6.db", hold=6, ticks=W.H + 14)
    assert w.taint.outbox_ids and _tainted_dispatches(w) == []
    items = w.items()
    assert all(items[o].status == OutboxStatus.HELD for o in w.taint.outbox_ids)
    (oid,) = w.log[(W.H + 2, "payments")].outbox_ids
    assert items[oid].release_tick == W.H + 12 and _holds(w)[oid] == (W.H + 12, "lineage_hold")  # G3: v + 2H


def test_simulation_leaves_live_store_digest_unchanged(hero):
    w, s, digest, dr, _ = hero
    assert w.store.state_digest() == digest == dr.digest_before == dr.digest_after
    assert w.store.get(W.IBAN).ver == 2  # crm's version is still the live head until apply


def test_rerun_deterministic_two_runs_identical_plan_hash(tmp_path, hero):
    """Two independent runs of the same seed give byte-identical plans (diff from the simulation included)."""
    w2 = W.run(tmp_path / "again.db")
    d2 = dry_run(w2.store, _plan(w2), rerunner=ToolRerunner(WorldDispatcher(), args_from_sidestore(w2.rundir.path)))
    assert d2.plan.to_canonical() == hero[3].plan.to_canonical()
    assert d2.plan_hash == hero[3].plan_hash
    assert _dry(w2).plan_hash == d2.plan_hash  # and the same store twice


def test_rerun_uses_original_agent_and_action_ids(hero):
    """M14: idempotency keys from the original agent/action, writes authored by the original agent."""
    w, s, digest, dr, _ = hero
    for seq, o in dr.outcomes.items():
        rec = next(r for r in w.records if r.seq == seq)
        assert (o.agent_id, o.action_id, o.tool) == (rec.envelope.agent_id, rec.envelope.action_id, rec.envelope.tool)


# --- stale (M8, maya 7) ----------------------------------------------------------------------------------------
def _plant_after(w, obj, value, author="docs"):
    seq = w.next_seq + 100
    with w.store.txn():
        w.store.put(obj, value, author=author, seq=seq, action_id="late-honest")


def test_honest_write_after_plan_halts_at_first_stale_rerun(tmp_path):
    """An honest write lands on an object a re-run wrote, between plan and dry-run: hold/stale_plan, halt there."""
    w = W.run(tmp_path / "s.db")
    pl = _plan(w)
    inv = w.log[(W.H + 1, "billing")]
    _plant_after(w, "invoices:INV-0031", {"note": "late"})
    digest = w.store.state_digest()
    with pytest.raises(StaleRerun):
        _dry(w, pl)
    with pytest.raises(StaleExpect):  # StaleRerun is a StaleExpect: one except clause for callers
        _dry(w, pl)
    d = _dry(w, pl, on_stale="halt")
    assert d.stale is not None and d.stale.decision == "hold/stale_plan" and d.stale.op == "rerun"
    first = next(x for x in ops(pl.plan, "rerun") if x.action.seq == inv.seq)
    assert d.stale.n == first.n and d.stale.obj == "invoices:INV-0031"
    assert d.outcomes == {}  # nothing after the halt was simulated
    assert {e.obj for e in d.plan.diff} == {W.IBAN, W.S22}  # only the restores before it
    assert "hold/stale_plan" in render(d)
    assert w.store.state_digest() == digest


def test_stale_restore_halts_too(tmp_path):
    w = W.run(tmp_path / "s.db")
    pl = _plan(w)
    _plant_after(w, W.S22, {"name": "Northgate Metals", "price": 800, "terms": 30, "risk_note": "x"}, "triage")
    d = _dry(w, pl, on_stale="halt")
    assert (d.stale.op, d.stale.obj) == ("restore", W.S22) and d.outcomes == {}
    with pytest.raises(StaleExpect):
        _dry(w, pl)


# --- M14: redacted args, dispatched payload compare -----------------------------------------------------------
def test_redacted_args_become_flag_and_readers_ride(hero):
    w, s, digest, dr, _ = hero
    inv = w.log[(W.H + 1, "billing")]
    args = {h: a for h, a in w.args.items() if h != inv.envelope.args_hash}
    d = _dry(w, args=args)
    fl = [(f.reason, f.action.seq) for f in ops(d.plan, "flag")]
    assert ("redacted_args", inv.seq) in fl
    assert inv.seq not in {x.action.seq for x in ops(d.plan, "rerun")}
    rode = {r.action.seq for r in d.riders}
    assert w.log[(W.H + 2, "payments")].seq in rode and w.log[(W.H + 2, "comms")].seq in rode
    assert not rode & {x.action.seq for x in ops(d.plan, "rerun")}
    assert [x.n for x in d.plan.steps] == list(range(len(d.plan.steps)))
    # B3-48 (ADR-05 §6.1 amended): the riders' held items get no cancel_outbox; they stay held and are listed
    assert ops(d.plan, "cancel_outbox") == []
    pay = w.log[(W.H + 2, "payments")]
    want = {oid for q in rode for oid in d.planned.rerun_records[q].outbox_ids}
    assert set(pay.outbox_ids) <= want and {h.outbox_id for h in d.held} == want
    assert all(h.blocked_by[0].startswith("rides: blocked by ") for h in d.held if h.action.seq != inv.seq)
    assert sum(1 for x in render(d).splitlines() if x.startswith("held ")) == len(want)


def test_args_from_sidestore_rehashes(tmp_path, hero):
    from ks.contracts import SideDomain, SideEntry
    w = hero[0]
    rec = w.log[(W.H + 1, "billing")]
    h = rec.envelope.args_hash
    p = tmp_path / "sidestore" / h[:2] / f"{h}.json"
    p.parent.mkdir(parents=True)
    p.write_bytes(SideEntry(hash=h, domain=SideDomain.ARGS, value=w.args[h], redacted=False).to_canonical())
    assert args_from_sidestore(tmp_path)(rec) == w.args[h]
    p.write_bytes(SideEntry(hash=h, domain=SideDomain.ARGS, value=None, redacted=True).to_canonical())
    with pytest.raises(ArgsUnavailable):
        args_from_sidestore(tmp_path)(rec)
    with pytest.raises(ArgsUnavailable):
        args_from_sidestore(tmp_path)(w.log[(W.H + 2, "payments")])


class _FixedPay:
    """A dispatcher whose payments tool emits fixed payloads (``()`` = none), to test effect dispositions."""

    def __init__(self, *payloads):
        self.payloads = payloads

    def execute(self, env, txn):
        return Execution(None, (), (), tuple(OutboxRequest("payments", ActionClass.I1, p) for p in self.payloads))


def _paid_book(payload_hash, status=OutboxStatus.DISPATCHED):
    b = seeded()
    b.act("crm", FH, reads=[FIBAN], writes={FIBAN: "DE99ATTACKER"})
    pay = b.act("payments", FH + 2, reads=[FIBAN], outbox=1, tool="payments.send")
    b.suspend("crm", FH + 3)
    env = pay.envelope
    item = OutboxItem(outbox_id="ob-000001", author="payments", action_id=env.action_id, created_seq=pay.seq,
                      sink="payments", action_class="I1", payload_hash=payload_hash,
                      idempotency_key=idempotency_key("payments", env.action_id, "payments", 0), lineage=(),
                      status=status, release_tick=0,
                      dispatched_seq=pay.seq + 1 if status == OutboxStatus.DISPATCHED else None)
    with b.store.txn():
        b.store.put("outbox:ob-000001", item.to_obj(), author="ks.gateway", seq=b.next_seq + 1, action_id="d")
    t = taint_from_alerts(b.records, [alert([ObjVer(obj=FIBAN, ver=2)])])
    pl = plan_recovery(b.records, t, alert_id="a-000001", state=b.store)
    args = {pay.envelope.args_hash: {"t": pay.tick, "s": pay.seq}}
    return b, pay, pl, lambda r: args[r.envelope.args_hash]


PAYLOAD = {"payment": "PAY-1", "beneficiary_iban": "DE00S-17"}


@pytest.mark.parametrize("same", [True, False])
def test_dispatched_item_flag_dropped_only_when_payload_hash_equal(same):
    """ADR-05 §6.3: dispatched item, nothing emitted; flag(dispatched_tainted) iff the simulated payload differs."""
    b, pay, pl, args = _paid_book(value_hash(PAYLOAD if same else {"other": 1}))
    assert [f.reason for f in ops(pl.plan, "flag")] == ["dispatched_tainted"]  # planner: conservative
    d = dry_run(b.store, pl, rerunner=ToolRerunner(_FixedPay(PAYLOAD), args))
    (e,) = d.outcomes[pay.seq].effects
    assert e.disposition == ("dispatched_same" if same else "dispatched_tainted")
    assert d.outcomes[pay.seq].outbox_writes == ()  # nothing re-emitted, item stays dispatched
    assert [f.reason for f in ops(d.plan, "flag")] == ([] if same else ["dispatched_tainted"])
    assert d.reemitted == 0


def test_dropped_effect_cancels_held_item_and_new_effect_counts_reemitted():
    b, pay, pl, args = _paid_book(value_hash(PAYLOAD), OutboxStatus.HELD)
    d = dry_run(b.store, pl, rerunner=ToolRerunner(_FixedPay(), args))
    (e,) = d.outcomes[pay.seq].effects
    assert e.disposition == "dropped"
    (ow,) = d.outcomes[pay.seq].outbox_writes
    cancelled = OutboxItem.model_validate({**b.store.get("outbox:ob-000001").value, "status": "cancelled"})
    head = b.store.get("outbox:ob-000001")
    assert ow.after.ver == head.ver + 1 and ow.after.hash == value_hash(cancelled.to_obj()) and d.reemitted == 0
    d2 = dry_run(b.store, pl, rerunner=ToolRerunner(_FixedPay(PAYLOAD, {"x": 2}), args))
    assert [x.disposition for x in d2.outcomes[pay.seq].effects] == ["reheld_same", "new"]
    assert d2.reemitted == 1 and "reemitted 1" in render(d2)
