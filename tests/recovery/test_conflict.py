"""B3-29: conflict rule and flag (F2+x), revert-culprit-only baseline, hold/stale_plan at apply (M8).

All on the real ks.world records from the in-process gateway driver (tests/recovery/world.py), whose run dirs pass
ks.verify (test_world_verify). Binding: CALL-02 B5 (honest conflict lives in F2+x), ADR-05 §6.2 / §8 / tests
``test_triage_conflict``, ADR-06-metrics baselines (revert-culprit-only: per object, no reader repair, no conflict
check, outbox untouched; oracle-assisted)."""

from __future__ import annotations

import pytest

from ks.contracts.recovery import RerunStep
from ks.recovery import (ORACLE_NOTE, STALE_PLAN, ToolRerunner, args_from_sidestore, conflict_flags, dry_run,
                         first_stale, plan_recovery, recheck, render, revert_culprit_only)
from ks.world.tools import WorldDispatcher

from . import world as W


def ops(plan, op):
    return [s for s in plan.steps if s.op == op]


def _plan(w):
    return plan_recovery(w.records, w.taint, alert_id="a-000001", state=w.store)


def _dry(w, pl=None, **kw):
    rr = ToolRerunner(WorldDispatcher(), args_from_sidestore(w.rundir.path))
    return dry_run(w.store, pl or _plan(w), rerunner=rr, **kw)


def _final(w, d):
    out = {o: r.hash for o, r in w.store.heads().items()}
    out.update({e.obj: e.planned_hash for e in d.plan.diff})
    return out


@pytest.fixture(scope="module")
def fx(tmp_path_factory):
    """F2+x run, its S* (same honest world: triage edits S-22, fault off) and the dry-run."""
    d = tmp_path_factory.mktemp("f2x")
    w = W.run(d / "f2x.db", fault="f2plus_x")
    s = W.run(d / "sstar.db", fault=None, variant="f2plus_x")
    return w, s, _dry(w)


@pytest.fixture(scope="module")
def hero(tmp_path_factory):
    d = tmp_path_factory.mktemp("hero")
    w = W.run(d / "f2.db")
    s = W.run(d / "sstar.db", fault=None)
    return w, s, _dry(w)


def _triage_edit(w):
    return next(r for (t, a), r in sorted(w.log.items()) if a == "triage" and r.envelope.tool == "supplier.set_risk_note")


# --- F2+x: the honest conflict (B5) ---------------------------------------------------------------------------------
def test_triage_conflict(fx):
    """Triage reads crm's S-22 v2 and edits the row: no restore of S-22, exactly one
    flag(write_write_conflict, S-22, triage); the IBAN is still restored; triage's edit is not overwritten."""
    w, s, d = fx
    tri = _triage_edit(w)
    assert w.args[tri.envelope.args_hash]["supplier"] == "S-22" and tri.tick == W.H + 2
    head = w.store.history(W.S22)[-1]
    assert (head.author, head.seq) == ("triage", tri.seq)  # triage's edit is the head, over crm's v2
    assert w.taint.is_tainted(W.S22, head.ver)  # conservative: triage read crm's version
    for p in (_plan(w).plan, d.plan):  # at plan time and after the dry-run refinement
        cf = conflict_flags(p)
        assert len(cf) == 1
        f = cf[0]
        assert (f.reason, f.obj, f.action.agent_id, f.action.seq) == ("write_write_conflict", W.S22, "triage", tri.seq)
        assert [x.obj for x in ops(p, "restore")] == [W.IBAN]
        assert tri.seq not in {x.action.seq for x in ops(p, "rerun")}
    assert W.S22 not in {e.obj for e in d.plan.diff}  # not overwritten
    assert d.stale is None and d.digest_before == d.digest_after
    assert "write_write_conflict suppliers:S-22 triage" in render(d)


def test_triage_conflict_counts_in_R(fx):
    """R > 0: the unresolved flag leaves S-22 different from S* (ADR-06-metrics: an unresolved flag counts as left)."""
    w, s, d = fx
    sstar = {o: r.hash for o, r in s.store.heads().items()}
    final = _final(w, d)
    assert final[W.S22] != sstar[W.S22]
    assert final[W.IBAN] == sstar[W.IBAN]  # the IBAN restore still lands


def test_f2plus_x_rider_items_stay_held_not_cancelled(fx):
    """B3-48, ADR-05 §6.1 as amended 20 Nov (maya, B3-29 review): the items of the actions that ride with the
    conflict flag get no cancel_outbox (was 10); each stays held, is listed in Planned.held with the blocking flag,
    and the dry-run renders one held line per item. Still exactly one conflict flag."""
    w, s, d = fx
    pl = _plan(w)
    for p in (pl.plan, d.plan):
        assert ops(p, "cancel_outbox") == []
        assert len(conflict_flags(p)) == 1
    rider_seqs = {r.action.seq for r in pl.riders}
    assert pl.held and len(pl.held) == len({h.outbox_id for h in pl.held}) == len(d.held)
    for h in pl.held:
        assert h.status.value == "held" and h.action.seq in rider_seqs
        assert h.blocked_by == (f"flag(write_write_conflict {W.S22})",)
        assert w.store.get(f"outbox:{h.outbox_id}").value["status"] == "held"
    txt = render(d)
    lines = [x for x in txt.splitlines() if x.startswith("held ")]
    assert len(lines) == len(pl.held)
    assert all(f"outbox:{h.outbox_id} held {h.action.agent_id} seq {h.action.seq}" in x
               for h, x in zip(pl.held, lines))


def test_hero_f2plus_has_no_conflict_flag(hero):
    """Same rule on the hero: triage edits the S-17 row (not the IBAN object): kept, no conflict, 0 flags."""
    w, s, d = hero
    assert conflict_flags(d.plan) == () and ops(d.plan, "flag") == []
    assert ops(d.plan, "cancel_outbox") == [] and d.held == ()  # B3-48: no held-without-step items on the hero
    assert {x.obj for x in ops(d.plan, "restore")} == {W.IBAN, W.S22}
    assert [(k.obj, k.author) for k in d.planned.kept] == [("suppliers:S-17", "triage")]


# --- revert-culprit-only baseline (oracle-assisted, per object) ------------------------------------------------------
def test_revert_culprit_only_per_object_spares_triage(hero):
    """F2+: restores crm's two objects (S-17.iban field, S-22 row) to v1; triage's S-17 row edit stays (spared);
    no reader repair, so billing's invoice from the bad IBAN stays wrong (R > 0) where the system plan fixes it."""
    w, s, d = hero
    b = revert_culprit_only(w.records, culprit="crm", t_inject=W.H)
    p = b.planned.plan
    assert b.oracle_assisted and b.name == "revert_culprit_only" and ORACLE_NOTE in b.planned.notes
    assert [(x.op, x.obj, x.expect.ver, x.to.ver) for x in p.steps] == [("restore", W.IBAN, 2, 1),
                                                                         ("restore", W.S22, 2, 1)]
    assert b.clobbered == ()
    db = dry_run(w.store, b.planned)
    assert {e.obj for e in db.plan.diff} == {W.IBAN, W.S22}
    assert "suppliers:S-17" not in {e.obj for e in db.plan.diff}
    assert w.store.history("suppliers:S-17")[-1].author == "triage"  # spared
    sstar = {o: r.hash for o, r in s.store.heads().items()}
    inv = w.log[(W.H + 1, "billing")].write_set[0].obj
    assert _final(w, db)[inv] != sstar[inv]  # derived work left (R > 0)
    assert _final(w, d)[inv] == sstar[inv]  # the system plan re-ran it
    assert not [x for x in p.steps if x.op in ("rerun", "cancel_outbox", "flag")]  # outbox untouched


def test_revert_culprit_only_clobbers_triage_on_f2plus_x(fx):
    """F2+x: no conflict check, so the baseline restores S-22 over triage's honest edit (reported as clobbered);
    the system plan flags it instead."""
    w, s, d = fx
    tri = _triage_edit(w)
    b = revert_culprit_only(w.records, culprit="crm", t_inject=W.H)
    assert b.clobbered == ((W.S22, "triage", tri.seq),)
    db = dry_run(w.store, b.planned)
    v1 = w.store.history(W.S22)[0]
    assert {e.obj: e.planned_hash for e in db.plan.diff}[W.S22] == v1.hash  # triage's risk note is gone
    assert conflict_flags(d.plan) and W.S22 not in {e.obj for e in d.plan.diff}


def test_revert_culprit_only_is_tcb_blind_input():
    """The baseline takes culprit and t_inject from its caller; it rejects a system principal as culprit."""
    with pytest.raises(ValueError):
        revert_culprit_only([], culprit="ks.monitor", t_inject=1)


# --- M8: changed expect at apply -> hold/stale_plan ------------------------------------------------------------------
def test_honest_write_between_dry_run_and_apply_holds_stale_plan(tmp_path):
    """Hero dry-run approved; then triage (honest, through the gateway) edits S-22. At apply the re-check refuses
    the S-22 restore with hold/stale_plan; steps before it still pass (they stay applied). The new plan has a
    later as_of_seq and turns the edit into flag(write_write_conflict, S-22, triage) at plan time."""
    w = W.run(tmp_path / "m8.db")
    d = _dry(w)
    assert first_stale(w.store, d) is None
    n22 = next(x.n for x in ops(d.plan, "restore") if x.obj == W.S22)
    rec = W.extra_tick(w, "triage", "supplier.set_risk_note", {"supplier": "S-22", "note": "late"})
    assert rec.decision.value == "exec" and rec.write_set[0].obj == W.S22
    bad = first_stale(w.store, d)
    assert bad is not None and (bad.n, bad.op, bad.obj, bad.decision) == (n22, "restore", W.S22, STALE_PLAN)
    assert all(recheck(w.store, d, x) is None for x in d.plan.steps[:n22])
    p2 = _plan(w).plan
    assert p2.as_of_seq == rec.seq > d.plan.as_of_seq
    assert [(f.obj, f.action.agent_id, f.action.seq) for f in conflict_flags(p2)] == [(W.S22, "triage", rec.seq)]
    assert [x.obj for x in ops(p2, "restore")] == [W.IBAN]


def test_rerun_stale_at_apply_but_own_writes_pass(tmp_path):
    """A re-run step is stale at apply if an honest write landed on an object it writes after the original action;
    the plan's own applied steps (restores by ks.recovery, re-runs under the original agent/action) are not."""
    w = W.run(tmp_path / "rr.db")
    d = _dry(w)
    first = ops(d.plan, "rerun")[0]
    rec = d.planned.rerun_records[first.action.seq]
    obj = rec.write_set[0].obj
    rr = ToolRerunner(WorldDispatcher(), args_from_sidestore(w.rundir.path))
    seq = w.store.last_seq() + 1
    with w.store.simulate():  # apply the steps up to and including the first re-run, as the gateway would
        from ks.recovery import apply_restore
        for x in d.plan.steps:
            if x.op == "restore":
                assert recheck(w.store, d, x) is None
                apply_restore(w.store, x, seq=seq, action_id=f"{d.plan.plan_id}.{x.n}")
                seq += 1
        assert recheck(w.store, d, first) is None
        rr(w.store, first, rec, seq)
        seq += 1
        assert all(recheck(w.store, d, x) is None for x in d.plan.steps if isinstance(x, RerunStep))
        with w.store.savepoint():
            w.store.put(obj, {"note": "honest late write"}, author="docs", seq=seq, action_id="docs-late")
            bad = recheck(w.store, d, first)
            assert bad is not None and (bad.op, bad.obj, bad.decision) == ("rerun", obj, STALE_PLAN)
