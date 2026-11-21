"""S4-13 (D-18, ADR-05a, CALL-02 B5-a): the auditable, reversible write-write resolver ``ww_rebase/1``.

On the real ks.world F2+x run (tests/recovery/world.py: triage edits S-22 at h+2 after reading crm's tainted v2)
driven through the real Gateway. Covers: F2+x resolved and equal to S*; resolver off unchanged; one refusal test per
check (each refusal keeps the flag and the held items: a person decides); M8 stale; apply as one signed c-0 record;
undo (``ks.recover.unresolve``) round trip, blocked paths, no re-resolve after an undo; determinism; TCB blindness;
the property "a culprit write never survives a resolution" over seeds; verify ``resolution_invalid`` on forged,
altered, replayed and out-of-order resolutions.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from ks.contracts import (OutboxStatus, ReadEntry, RecoverArgs, ResolveStep, SideDomain, SideEntry, UnresolveStep,
                          args_hash, canonical, sidestore_relpath)
from ks.contracts.recovery import RecoveryPlan
from ks.recovery import ToolRerunner, args_from_sidestore, conflict_flags, dry_run, plan_recovery, recheck, render, write_plan
from ks.recovery import resolver as RS
from ks.recovery.resolver import CHECKS, RECORD_CHECKS, Context, eligible, plan_unresolve
from ks.runtime.recover import UNRESOLVED_REASON, RecoveryService, bench_releasable
from ks.taint import RecordIndex
from ks.verify import verify
from ks.verify.recovery import resolution_pass
from ks.verify.window import Violation
from ks.world.tools import WorldDispatcher

from tests.recovery import world as W
from tests.runtime import test_recover as T

ON = "ww_rebase/1"


def _q(_s):
    pass


def ops(plan, op):
    return [s for s in plan.steps if s.op == op]


def _triage(w):
    return next(r for (t, a), r in sorted(w.log.items()) if a == "triage" and r.envelope.tool == "supplier.set_risk_note")


def _plan(w, resolver=ON, **kw):
    return plan_recovery(w.records, w.taint, alert_id="a-000001", state=w.store, resolver=resolver,
                         args_of=args_from_sidestore(w.rundir.path), **kw)


def _dry(w, pl, rerunner=None):
    rr = rerunner or ToolRerunner(WorldDispatcher(), args_from_sidestore(w.rundir.path))
    return dry_run(w.store, pl, rerunner=rr, on_stale="halt")


def _ctx(w, **kw):
    ix = RecordIndex(w.records)
    base = dict(ix=ix, as_of=w.taint.as_of_seq, suspect="crm", taint=frozenset(w.taint.versions),
                restored=frozenset({W.IBAN}))
    base.update(kw)
    return Context(**base)


def _apply(w, plan, steps=None):
    """Approve + apply ``plan`` in-process (as test_recover), with the RecoveryService installed; one idle tick."""
    g = w.gateway
    if getattr(g, "recovery", None) is None:
        g.system._signers.update({p: w.keys.signer(p) for p in ("ks.operator", "ks.recovery", "ks.monitor")})
        g.recovery = RecoveryService(w.rundir.path, w.keys.signer("ks.recovery"), dispatcher=g.dispatcher)
    write_plan(plan, w.rundir)
    T.approve(w, plan, steps)
    out = T.recover(w, plan, steps)
    T.tick(w)
    return out


def _status(w):
    return lambda oid: w.gateway.outbox.get(oid).item.status


def _undo_plan(w, ref):
    return plan_unresolve(w.records, ref, plan_of=lambda pid: RecoveryPlan.from_canonical(
        (w.rundir.path / "plans" / f"{pid}.json").read_bytes()), args_value=args_from_sidestore(w.rundir.path),
        status_of=_status(w))


@pytest.fixture(scope="module")
def fx(tmp_path_factory):
    d = tmp_path_factory.mktemp("s413")
    w = W.run(d / "f2x.db", fault="f2plus_x")
    s = W.run(d / "sstar.db", fault=None, variant="f2plus_x")
    return w, s, _dry(w, _plan(w))


@pytest.fixture
def applied(tmp_path):
    """A fresh F2+x run with the resolver plan approved and applied (no release)."""
    w = W.run(tmp_path / "x.db", fault="f2plus_x")
    dr = _dry(w, _plan(w))
    out = _apply(w, dr.plan)
    assert all(getattr(o, "record", None) is not None and o.record.decision.value == "exec" for o in out), out
    return w, dr


# --- F2+x resolved; resolver off unchanged ---------------------------------------------------------------------------
def test_f2x_resolved(fx):
    """One resolve on S-22, rebased value == S*'s S-22, billing's readers re-run, 0 write-write flags, and triage's h+2
    record has no view-source tainted read (ADR-05a §2: the assertion maya asked for)."""
    w, s, d = fx
    tri = _triage(w)
    assert tri.tick == W.H + 2
    assert not [e for e in tri.read_set if e.source == "view" and w.taint.is_tainted(e.obj, e.ver)]
    assert [(e.obj, e.ver, e.source) for e in tri.read_set if w.taint.is_tainted(e.obj, e.ver)] == [(W.S22, 2, "tool")]
    rs = ops(d.plan, "resolve")
    assert len(rs) == 1 and conflict_flags(d.plan) == ()
    r = rs[0]
    assert (r.obj, r.rule, r.rule_version, r.culprit_ver.ver, r.expect.ver, r.to.ver) == (W.S22, "ww_rebase", 1, 2, 3, 1)
    assert (r.rebased.agent_id, r.rebased.seq) == ("triage", tri.seq) and r.rationale == CHECKS
    assert r.rebased_hash == s.store.get(W.S22).hash  # the honest edit on clean inputs == S*
    reruns = {x.action.seq for x in ops(d.plan, "rerun")}
    billing_v3 = w.log[(W.H + 3, "billing")]
    assert billing_v3.seq in reruns and tri.seq not in reruns
    assert r.unblocked and set(r.unblocked) == {h.outbox_id for h in _plan(w, "off").held}
    assert d.held == () and ops(d.plan, "flag") == []
    assert [x.op for x in d.plan.steps][:2] == ["restore", "resolve"]
    sstar = {o: v.hash for o, v in s.store.heads().items() if not o.startswith("outbox:")}
    final = {o: v.hash for o, v in w.store.heads().items()}
    final.update({e.obj: e.planned_hash for e in d.plan.diff})
    assert {o for o in sstar if final.get(o) != sstar[o]} == set()  # R = 0 at plan level
    txt = render(d)
    assert "resolver: ww_rebase/1 (on)" in txt and f"undo: ks recover RUN --unresolve {d.plan.plan_id}.{r.n}" in txt
    assert "triage edit rebased on v1" in txt and "ww_flags_before 1  ww_flags_after 0" in txt


def test_f2x_resolver_off_unchanged(fx):
    """B5 before-row: resolver off gives exactly the pre-1.7 plan (same bytes as calling without the kwarg)."""
    w, s, d = fx
    off = plan_recovery(w.records, w.taint, alert_id="a-000001", state=w.store)
    off2 = _plan(w, "off")
    assert off.plan.content_hash() == off2.plan.content_hash()
    assert len(conflict_flags(off.plan)) == 1 and ops(off.plan, "resolve") == []
    assert "resolver: off" in render(_dry(w, off))


def test_hero_unchanged_resolver_on_and_off(tmp_path):
    """Hero F2+ has no flag: the resolver changes nothing (same plan bytes on and off)."""
    w = W.run(tmp_path / "f2.db")
    a, b = _dry(w, _plan(w, "off")), _dry(w, _plan(w, ON))
    assert a.plan.content_hash() == b.plan.content_hash() and ops(b.plan, "resolve") == []
    assert b.planned.ww_flags_before == 0


# --- each check failing -> the flag stays, a person decides ----------------------------------------------------------
def _act(w):
    tri = _triage(w)
    return RS._ref(tri)


def test_eligible_passes_on_f2x(fx):
    w, _, _ = fx
    el = eligible(_ctx(w), W.S22, _act(w))
    assert el.ok and el.passed == RECORD_CHECKS and el.seed_objs == ()


@pytest.mark.parametrize("check", RECORD_CHECKS)
def test_each_check_refuses(fx, check):
    """One refusal per record-only check (sim_clean below). The failed id is the first failing check."""
    w, _, _ = fx
    tri = _triage(w)
    obj, act, kw = W.S22, _act(w), {}
    if check == "row_object":
        obj = W.IBAN
    elif check == "single_honest_write":
        act = act.model_copy(update={"seq": act.seq - 1})
    elif check == "honest_deterministic":
        kw = {"alerts": (w.alert.model_copy(update={"root_candidates": ("triage",)}),)}
    elif check == "single_object":
        kw = {"args_ok": lambda r: False}  # args redacted / missing from the side store
    elif check == "no_tainted_view_reads":
        v = next(e for e in tri.read_set if e.source == "view" and RecordIndex(w.records).writer(e.obj, e.ver).attributed_agent != "triage")  # noqa: E501 (a triage-written version would make triage a taint-origin author, §2a)
        kw = {"taint": frozenset(w.taint.versions) | {(v.obj, v.ver)}}
    elif check == "seed_reads_only":
        bad = ReadEntry(obj="invoices:INV-0031", ver=1, hash=tri.read_set[0].hash)  # tainted, written by billing
        recs = [r.model_copy(update={"read_set": (*r.read_set, bad)}) if r.seq == tri.seq else r for r in w.records]
        kw = {"ix": RecordIndex(recs)}
        assert w.taint.is_tainted("invoices:INV-0031", 1)
    elif check == "clean_base":
        kw = {"taint": frozenset(w.taint.versions) | {(W.S22, 1)}}
    elif check == "not_undone":
        kw = {"undone": frozenset({(W.S22, tri.seq)})}
    el = eligible(_ctx(w, **kw), obj, act)
    assert not el.ok and el.failed == check, el
    assert el.passed == RECORD_CHECKS[:RECORD_CHECKS.index(check)]


def test_refuse_view_copied_arg(fx):
    """kabir S4-12: a deterministic writer whose args could carry a tainted view value is refused (args are
    replayed), even when every other check passes."""
    w, _, _ = fx
    tri = _triage(w)
    v = next(e for e in tri.read_set if e.source == "view" and RecordIndex(w.records).writer(e.obj, e.ver).attributed_agent != "triage")  # noqa: E501 (a triage-written version would make triage a taint-origin author, §2a)
    el = eligible(_ctx(w, taint=frozenset(w.taint.versions) | {(v.obj, v.ver)}), W.S22, _act(w))
    assert (el.ok, el.failed) == (False, "no_tainted_view_reads") and v.obj in el.detail


def test_refused_flag_waits_for_a_person(fx):
    """Planner level: a refused conflict stays a flag, its riders' items stay held (same as resolver off), and the
    dry-run flag line names the failed check."""
    w, _, _ = fx
    pl = _plan(w, alerts=(w.alert.model_copy(update={"root_candidates": ("triage",)}),))
    off = _plan(w, "off")
    assert pl.refused == {W.S22: "honest_deterministic"} and ops(pl.plan, "resolve") == []
    assert pl.plan.content_hash() == off.plan.content_hash() and pl.held == off.held
    assert "(resolver: honest_deterministic failed)" in render(_dry(w, pl))


def test_sim_clean_failure_replans_as_flag(fx):
    """sim_clean: a re-run that errors in the simulation -> the dry-run re-plans once with the object kept a flag."""
    w, _, _ = fx
    real = ToolRerunner(WorldDispatcher(), args_from_sidestore(w.rundir.path))

    def broken(store, step, rec, seq):
        if step.reason == "ww_rebase":
            raise RuntimeError("tool exploded")
        return real(store, step, rec, seq)
    d = _dry(w, _plan(w), rerunner=broken)
    assert ops(d.plan, "resolve") == [] and len(conflict_flags(d.plan)) == 1
    assert d.planned.refused == {W.S22: "sim_clean"} and W.S22 in d.resolve_failed
    assert "(resolver: sim_clean failed: RuntimeError: tool exploded)" in render(d)
    assert d.digest_before == d.digest_after


def test_no_rerunner_keeps_flag(fx):
    w, _, _ = fx
    d = dry_run(w.store, _plan(w))
    assert ops(d.plan, "resolve") == [] and len(conflict_flags(d.plan)) == 1


def test_resolve_stale(fx):
    """M8: a resolve whose honest head moved is hold/stale_plan (recheck), and the dry-run halts on it."""
    w, _, d = fx
    r = ops(d.plan, "resolve")[0]
    moved = r.model_copy(update={"expect": r.expect.model_copy(update={"ver": r.expect.ver - 1})})
    st = recheck(w.store, d, moved)
    assert st is not None and st.op == "resolve" and st.decision == "hold/stale_plan"
    assert recheck(w.store, d, r) is None


def test_resolver_deterministic(fx, tmp_path):
    """Same seed -> byte-identical plan (another run of the same world, repro keys)."""
    w, _, d = fx
    w2 = W.run(tmp_path / "again.db", fault="f2plus_x")
    assert _dry(w2, _plan(w2)).plan.to_canonical() == d.plan.to_canonical()
    assert _dry(w, _plan(w)).plan.to_canonical() == d.plan.to_canonical()


def test_resolver_tcb_blind():
    """A3: ks.recovery.resolver never imports the run config nor reads fault/culprit/fault_tick from it."""
    src = Path(RS.__file__).read_text()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + [getattr(node, "module", "") or ""]
            assert not any(n.startswith(("ks.contracts.rundir", "ks.world", "ks.score", "ks.oracle", "ks.inject"))
                           or n == "RunConfig" for n in names), names
        if isinstance(node, ast.Attribute):
            assert node.attr not in ("fault", "fault_tick", "tcb_view"), node.attr


# --- apply: one signed c-0 record ------------------------------------------------------------------------------------
def test_apply_one_record_and_verify(applied, tmp_path):
    w, dr = applied
    s = W.run(tmp_path / "s.db", fault=None, variant="f2plus_x")
    rr = [r for r in w.records if r.envelope and r.envelope.tool == "ks.recover.resolve"]
    assert len(rr) == 1
    r = rr[0]
    step = ops(dr.plan, "resolve")[0]
    assert r.attributed_agent == "ks.recovery" and r.conn_id == "c-0" and r.envelope.action_id == f"{dr.plan.plan_id}.{step.n}"
    assert [(x.obj, x.before.ver, x.after.hash) for x in r.write_set] == [(W.S22, 3, step.rebased_hash)]
    assert [(e.obj, e.ver) for e in r.read_set] == [(W.S22, 1)]
    assert w.store.get(W.S22).hash == s.store.get(W.S22).hash
    held = [c for c in w.records if c.control is not None and c.control.reason == "rerun_reheld"]
    assert {c.control.target[len("outbox:"):] for c in held} == set(step.unblocked)
    assert verify(w.rundir.path, log=_q).ok


# --- undo ------------------------------------------------------------------------------------------------------------
def test_unresolve_roundtrip(applied):
    """Undo restores the pre-resolution state (S-22 back to triage's value, the dependent re-runs' objects back),
    is itself an approved, recorded, verified c-0 record; its items wait for a person (resolution_reverted, never
    bench-released); the flag is back and the rule never resolves it again."""
    w, dr = applied
    step = ops(dr.plan, "resolve")[0]
    ref = f"{dr.plan.plan_id}.{step.n}"
    before = {e.obj: e.current for e in dr.plan.diff if not e.obj.startswith("outbox:")}
    up, why = _undo_plan(w, ref)
    assert why is None
    u = up.steps[0]
    assert isinstance(u, UnresolveStep) and u.reverts[0].obj == W.S22 and u.reverts[0].to == step.expect
    # ADR-05a §5: only re-runs whose landed record read the rebased version (transitively) are reverted; re-runs that
    # read S-22 only through the view re-ran without it (tool reads only), so their items are independent of it
    assert u.reheld and set(u.reheld) < set(step.unblocked)
    out = _apply(w, up)
    assert out[0].record.decision.value == "exec"
    ur = out[0].record
    assert ur.envelope.tool == "ks.recover.unresolve" and ur.attributed_agent == "ks.recovery"
    assert w.store.get(W.S22).hash == step.expect.hash
    for e in u.reverts:  # every reverted object holds its pre-resolution value again
        assert w.store.get(e.obj).hash == before.get(e.obj, e.to).hash == e.to.hash
    holds = {c.control.target[len("outbox:"):] for c in w.records
             if c.control is not None and c.control.reason == UNRESOLVED_REASON and c.seq > ur.seq}
    assert holds == set(u.reheld)
    assert not set(bench_releasable(w.records, _status(w))) & set(u.reheld)
    assert verify(w.rundir.path, log=_q).ok
    # the flag is back; the rule refuses it (undoing an undo is a person's job)
    from ks.taint import taint_from_alerts
    t2 = taint_from_alerts(w.records, [w.alert])
    assert t2.is_tainted(W.S22, w.store.get(W.S22).ver)  # taint flows through the undo as before
    pl = plan_recovery(w.records, t2, alert_id="a-000001", state=w.store, resolver=ON,
                       args_of=args_from_sidestore(w.rundir.path))
    assert ops(pl.plan, "resolve") == [] and len(conflict_flags(pl.plan)) == 1 and W.S22 in pl.refused
    with pytest.raises(ValueError, match="already undone"):
        _undo_plan(w, ref)


def test_no_reresolve_after_undo(applied):
    """not_undone: even the original (O, H) pair is refused once an executed unresolve names it."""
    w, dr = applied
    step = ops(dr.plan, "resolve")[0]
    up, _ = _undo_plan(w, f"{dr.plan.plan_id}.{step.n}")
    _apply(w, up)
    und = RS.undone_pairs(w.records, args_from_sidestore(w.rundir.path))
    assert (W.S22, step.rebased.seq) in und
    recs = [r for r in w.records if r.seq <= dr.plan.as_of_seq] + [r for r in w.records
                                                                    if r.envelope and r.envelope.tool == "ks.recover.unresolve"]
    el = eligible(_ctx(w, ix=RecordIndex(recs), undone=und), W.S22, step.rebased)
    assert (el.ok, el.failed) == (False, "not_undone")


def test_unresolve_blocked(applied):
    """A record outside the resolving plan touched the object since the resolution: flag(unresolve_blocked)."""
    w, dr = applied
    step = ops(dr.plan, "resolve")[0]
    rr = next(r for r in w.records if r.envelope and r.envelope.tool == "ks.recover.resolve")
    foreign = _triage(w).model_copy(update={"seq": w.records[-1].seq + 1, "read_set": (
        ReadEntry(obj=W.S22, ver=rr.write_set[0].after.ver, hash=rr.write_set[0].after.hash, source="view"),)})
    why = RS.unresolve_problems([*w.records, foreign], rr, [RS.RevertEntry(obj=W.S22, expect=rr.write_set[0].after,
                                                                          to=step.expect)], (), _status(w))
    assert why is not None and "touched suppliers:S-22" in why


def test_unresolve_blocked_after_bench_release(applied):
    """Bench runs: once the approver releases a rerun_reheld item, the undo is flag(unresolve_blocked) (by design)."""
    w, dr = applied
    step = ops(dr.plan, "resolve")[0]
    up0, why0 = _undo_plan(w, f"{dr.plan.plan_id}.{step.n}")
    assert why0 is None
    rel = [o for o in bench_releasable(w.records, _status(w)) if o in up0.steps[0].reheld]
    assert rel
    from ks.contracts import CONTROL_TOOL
    from ks.gateway.system import SystemRequest
    from ks.contracts import Control, ControlOp
    w.gateway.system.put(SystemRequest("ks.operator", CONTROL_TOOL, build=lambda gw, t, q: Control(
        control_id=f"k-{q:06d}", op=ControlOp.UNHOLD, target=f"outbox:{rel[0]}", epoch=None, alert_id="a-000001",
        issued_by="ks.operator", auto=False, reason="operator").to_obj()))
    T.tick(w)
    assert _status(w)(rel[0]) in (OutboxStatus.RELEASED, OutboxStatus.DISPATCHED)
    up, why = _undo_plan(w, f"{dr.plan.plan_id}.{step.n}")
    assert why is not None and up.steps[0].op == "flag" and up.steps[0].reason == "unresolve_blocked"


# --- property: a culprit write never survives a resolution -----------------------------------------------------------
@pytest.mark.parametrize("seed", [3, 7, 11, 19])
def test_culprit_write_never_survives(seed, tmp_path, monkeypatch):
    """Over seeds: after the resolver plan is applied, no field the suspect changed on a resolved object still holds
    the suspect's value, and every resolved object equals S* (the honest edit on clean inputs)."""
    monkeypatch.setattr(W, "SEED", seed)
    w = W.run(tmp_path / "x.db", fault="f2plus_x")
    s = W.run(tmp_path / "s.db", fault=None, variant="f2plus_x")
    dr = _dry(w, _plan(w))
    res = ops(dr.plan, "resolve")
    _apply(w, dr.plan)
    for r in res:
        bad = w.store.value_at(r.obj, r.culprit_ver.ver)
        base = w.store.value_at(r.obj, r.to.ver)
        now = w.store.get(r.obj).value
        changed = {k for k in bad if bad.get(k) != base.get(k)}
        assert changed and all(now.get(k) != bad[k] for k in changed), (seed, changed)
        assert w.store.get(r.obj).hash == s.store.get(r.obj).hash
    assert res or conflict_flags(dr.plan)  # either resolved, or still a flag for a person (never silently dropped)
    assert verify(w.rundir.path, log=_q).ok


# --- verify: resolution_invalid --------------------------------------------------------------------------------------
def _forge(w, rec, mutate):
    """A validly signed-looking forged record: new RecoverArgs (side store entry) via ``mutate(step)``. Returns the
    record list with ``rec`` replaced (resolution_pass is record-only; signatures are the record pass's job)."""
    a = RecoverArgs.model_validate(args_from_sidestore(w.rundir.path)(rec))
    na = a.model_copy(update={"step": mutate(a.step)}).to_obj()
    h = args_hash(na)
    e = SideEntry(domain=SideDomain.ARGS, hash=h, value=na, redacted=False)
    p = w.rundir.path / sidestore_relpath(h)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(e.to_canonical())
    env = rec.envelope.model_copy(update={"args_hash": h})
    return rec.model_copy(update={"envelope": env})


def _expect_invalid(w, recs, frag):
    with pytest.raises(Violation) as ei:
        resolution_pass(w.rundir.path, recs)
    assert ei.value.reason == "resolution_invalid" and frag in str(ei.value.detail), ei.value.detail


def _resolve_rec(w):
    return next(r for r in w.records if r.envelope and r.envelope.tool == "ks.recover.resolve")


def test_verify_accepts_valid(applied):
    w, _ = applied
    resolution_pass(w.rundir.path, w.records)


def test_verify_forged_rule(applied):
    w, _ = applied
    rr = _resolve_rec(w)
    f = _forge(w, rr, lambda s: s.model_copy(update={"rule": "ww_magic"}))
    _expect_invalid(w, [f if r.seq == rr.seq else r for r in w.records], "not a known resolver rule")


def test_verify_altered_rebased_hash(applied):
    w, _ = applied
    rr = _resolve_rec(w)
    f = _forge(w, rr, lambda s: s.model_copy(update={"rebased_hash": "0" * 64}))
    _expect_invalid(w, [f if r.seq == rr.seq else r for r in w.records], "sim_clean")


def test_verify_claimed_check_fails(applied):
    """Re-signed resolve whose step claims a field the record does not support (to = the culprit's version)."""
    w, _ = applied
    rr = _resolve_rec(w)
    f = _forge(w, rr, lambda s: s.model_copy(update={"to": s.culprit_ver}))
    _expect_invalid(w, [f if r.seq == rr.seq else r for r in w.records], "field to")


def test_verify_replayed_resolve(applied):
    w, _ = applied
    rr = _resolve_rec(w)
    last = w.records[-1].seq
    _expect_invalid(w, [*w.records, rr.model_copy(update={"seq": last + 1})], "replayed")


def test_verify_resolve_out_of_order(applied):
    w, _ = applied
    rr = _resolve_rec(w)
    plan_asof = RecoverArgs.model_validate(args_from_sidestore(w.rundir.path)(rr))
    P = RecoveryPlan.from_canonical((w.rundir.path / "plans" / f"{plan_asof.plan_id}.json").read_bytes())
    early = rr.model_copy(update={"seq": P.as_of_seq})
    _expect_invalid(w, [early if r.seq == rr.seq else r for r in w.records], "out of order")


def test_verify_resolve_before_its_restore(applied, monkeypatch):
    """Order: a restore the checks depend on (seed_objs) must run before the resolve. F2+x has none, so the
    eligibility is patched to name the IBAN restore, and the resolve is moved before it."""
    w, _ = applied
    rr = _resolve_rec(w)
    real = RS.eligible
    monkeypatch.setattr(RS, "eligible", lambda *a, **k: (lambda e: type(e)(**{**e.__dict__, "seed_objs": (W.IBAN,)}))(real(*a, **k)))
    restore = next(r for r in w.records if r.envelope and r.envelope.tool == "ks.recover.restore")
    recs = [r for r in w.records if r.seq not in (rr.seq, restore.seq)]
    recs += [rr.model_copy(update={"seq": restore.seq}), restore.model_copy(update={"seq": rr.seq})]
    _expect_invalid(w, sorted(recs, key=lambda r: r.seq), "out of order: restore")


def test_verify_resolve_after_unresolve_and_double_undo(applied):
    w, dr = applied
    step = ops(dr.plan, "resolve")[0]
    up, _ = _undo_plan(w, f"{dr.plan.plan_id}.{step.n}")
    _apply(w, up)
    assert verify(w.rundir.path, log=_q).ok
    rr = _resolve_rec(w)
    ur = next(r for r in w.records if r.envelope and r.envelope.tool == "ks.recover.unresolve")
    last = w.records[-1].seq
    # a replayed / re-planned resolve of the same (O, H) after the undo
    _expect_invalid(w, [*w.records, rr.model_copy(update={"seq": last + 1})], "replayed")
    # a second undo of the same resolution
    _expect_invalid(w, [*w.records, ur.model_copy(update={"seq": last + 1})], "undone twice")
    # an undo naming no executed resolution
    _expect_invalid(w, [r for r in w.records if r.seq != rr.seq], "names no executed resolution")


def test_verify_end_to_end_gateway_skipped_hash_check(tmp_path, monkeypatch):
    """A compromised gateway that lands a resolve whose value is not the approved rebased_hash: ks verify TAMPER
    resolution_invalid (the full verify, chain and signatures intact)."""
    w = W.run(tmp_path / "x.db", fault="f2plus_x")
    dr = _dry(w, _plan(w))
    step = ops(dr.plan, "resolve")[0]
    forged = RecoveryPlan.model_validate({**dr.plan.to_obj(), "steps": [
        (s.model_copy(update={"rebased_hash": "1" * 64}) if s.n == step.n else s).to_obj() for s in dr.plan.steps]})
    monkeypatch.setattr(RecoveryService, "_hash_ok", staticmethod(lambda h, s: True))
    _apply(w, forged)
    monkeypatch.undo()
    rep = verify(w.rundir.path, log=_q)
    assert (rep.ok, rep.reason) == (False, "resolution_invalid")
    assert rep.first_bad == _resolve_rec(w).seq


def test_score_keys_only_with_resolver_on(tmp_path):
    from ks.score.score import RESOLVER_KEYS, resolver_summary
    w = W.run(tmp_path / "x.db", fault="f2plus_x")
    dr = _dry(w, _plan(w))
    _apply(w, dr.plan)
    s = resolver_summary(w.rundir.path)
    assert tuple(s) == RESOLVER_KEYS and s["ww_flags_before"] == 1 and s["ww_flags_after"] == 0
    assert [(x["obj"], x["rebased_agent"], x["undone_by_seq"]) for x in s["resolutions"]] == [(W.S22, "triage", None)]


def test_real_alert_root_candidates_resolve(fx):
    """S4-13 finding + maya ruling (ADR-05a rev 3): the runtime's alert ranks every agent the bounded backward walk
    reaches (ADR-05 §5, H1); on F2+x that is (crm, intake, triage). Only ``[0]`` is refused (with the suspect, the
    evidence writers and taint-origin authors); ``[1..]`` are read-reached hypotheses, so triage's conflict resolves."""
    from ks.taint import root_candidates
    w, _, _ = fx
    rc = root_candidates(w.records, w.alert.evidence_versions)
    assert rc[0] == "crm" and "triage" in rc[1:]
    real = (w.alert.model_copy(update={"root_candidates": rc}),)
    assert "triage" not in RS.refused_agents(RecordIndex(w.records), w.taint.as_of_seq, "crm",
                                             frozenset(w.taint.versions), real)
    pl = _plan(w, alerts=real)
    assert pl.refused == {} and [s.obj for s in ops(pl.plan, "resolve")] == [W.S22]
    assert not conflict_flags(pl.plan)


def test_refuse_candidate1_with_seed_writes(fx):
    """maya ruling: a rogue that is only ``root_candidates[1]`` but authored a taint origin (a tainted version its
    record did not derive from any tainted read, i.e. a seed write) is refused, even though the person's suspect is
    ``[0]``. A rogue must never have its write rebased."""
    w, _, _ = fx
    tri = _triage(w)
    taint = frozenset(w.taint.versions)
    own = next(r for r in w.records if r.seq < tri.seq and r.attributed_agent == "triage" and r.write_set
               and not any((e.obj, e.ver) in taint for e in r.read_set))
    seeded = taint | {(own.write_set[0].obj, own.write_set[0].after.ver)}
    al = (w.alert.model_copy(update={"root_candidates": ("crm", "triage")}),)
    assert eligible(_ctx(w, alerts=al), W.S22, _act(w)).ok  # candidates[1] alone is not refused
    el = eligible(_ctx(w, alerts=al, taint=seeded), W.S22, _act(w))
    assert (el.ok, el.failed) == (False, "honest_deterministic"), el
    ix = RecordIndex(w.records)
    assert "triage" in RS.refused_agents(ix, w.taint.as_of_seq, "crm", seeded, al)


def test_refuse_suspect_choice_and_evidence_writer(fx):
    """The suspect a person picked (here candidates[1]) and any evidence writer (alerts with no sole writer carry
    ``root_candidates=()``) are refused."""
    w, _, _ = fx
    tri = _triage(w)
    al = (w.alert.model_copy(update={"root_candidates": ("crm", "triage")}),)
    el = eligible(_ctx(w, alerts=al, suspect="triage"), W.S22, _act(w))
    assert not el.ok  # the person's suspect never benefits (fails at or before honest_deterministic)
    ev = tri.write_set[0]
    al2 = (w.alert.model_copy(update={"root_candidates": (), "evidence_versions": (
        *w.alert.evidence_versions, type(w.alert.evidence_versions[0])(obj=ev.obj, ver=ev.after.ver))}),)
    el = eligible(_ctx(w, alerts=al2), W.S22, _act(w))
    assert (el.ok, el.failed) == (False, "honest_deterministic"), el


def test_cli_unresolve_writes_plan(applied):
    """``ks recover RUN --unresolve <plan_id>.<n>``: writes the undo plan (approved later with --apply like any plan)."""
    from ks.runtime.recover import cli_unresolve
    w, dr = applied
    step = ops(dr.plan, "resolve")[0]
    res = cli_unresolve(w.rundir.path, f"{dr.plan.plan_id}.{step.n}", store=w.store)
    assert res.path.is_file() and res.plan.steps[0].op == "unresolve"
    assert f"unresolve    {dr.plan.plan_id}.{step.n}: {W.S22} back to v{step.expect.ver}, flag raised again" in res.text
    with pytest.raises(ValueError, match="no executed ks.recover.resolve"):
        cli_unresolve(w.rundir.path, "p-000001.0", store=w.store)
