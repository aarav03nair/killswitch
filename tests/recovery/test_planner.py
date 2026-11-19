"""B3-21: ks.recovery planner (restore, cancel_outbox, flag) and dry-run diff (ADR-05 §6-7, CALL-02 B2/B3/B5/B6)."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from ks.contracts import TOMBSTONE_HASH, ObjVer, OutboxItem, OutboxStatus, RecoveryPlan, RunDir, value_hash
from ks.recovery import (NoPlan, apply_restore, dry_run, plan_recovery, render, restores_to_absent, write_plan)
from ks.state import StaleExpect
from ks.taint import taint_from_alerts

from .fixture import H, IBAN, alert, f2plus, seeded

sys.path.insert(0, str(Path(__file__).parents[1] / "contracts"))
import samples  # noqa: E402

S22 = "suppliers:S-22"
PKG = Path(__file__).parents[2] / "src" / "ks" / "recovery"


def ov(o, v):
    return ObjVer(obj=o, ver=v)


def hero(**kw):
    b, n = f2plus()
    t = taint_from_alerts(b.records, [alert([ov(IBAN, 2)], seq=n["payments"].seq)])
    return b, n, t, plan_recovery(b.records, t, alert_id="a-000001", state=b.store, **kw)


def ops(plan, op):
    return [s for s in plan.steps if s.op == op]


# --- hero F2+ (B2) -------------------------------------------------------------------------------------------------
def test_hero_restores_iban_and_s22_with_expect_crm_after_version():
    b, n, t, pl = hero()
    rs = {s.obj: s for s in ops(pl.plan, "restore")}
    assert set(rs) == {IBAN, S22}
    for obj, rec in ((IBAN, n["crm_iban"]), (S22, n["crm_s22"])):
        w = next(w for w in rec.write_set if w.obj == obj)
        assert rs[obj].expect == w.after and rs[obj].expect.ver == 2  # B6: crm's after-version
        assert rs[obj].to == w.before and rs[obj].to.ver == 1          # last untainted version
        assert b.store.history(obj)[rs[obj].expect.ver - 1].author == "crm"
    assert pl.plan.culprit == "crm" and pl.plan.t0_seq_est == n["crm_iban"].seq


def test_hero_b2_reruns_triage_kept_no_flag():
    b, n, t, pl = hero()
    p = pl.plan
    assert ops(p, "flag") == [] and ops(p, "replan") == []
    reruns = [s.action.seq for s in ops(p, "rerun")]
    want = [n[k].seq for k in ("bill_inv17", "bill_ledger", "comms", "payments", "bill_inv22", "reporter")]
    assert reruns == sorted(want)
    assert {s.action.agent_id for s in ops(p, "rerun")} == {"billing", "payments", "comms", "reporter"}
    # M14: payment/email re-run updates the same outbox:<id> (v+1, back on hold): no cancel
    assert ops(p, "cancel_outbox") == []
    # B3 lanes: triage's risk_note on S-17 kept, no step; independents inventory and docs
    assert [(k.obj, k.author) for k in pl.kept] == [("suppliers:S-17", "triage")]
    assert "triage" not in {s.action.agent_id for s in p.steps if getattr(s, "action", None)}
    assert pl.independent == ("docs", "inventory")
    assert [s.n for s in p.steps] == list(range(len(p.steps)))


def test_no_suspect_no_plan():
    with pytest.raises(NoPlan):
        plan_recovery([], None, alert_id="a-000001")


# --- determinism and plan file -------------------------------------------------------------------------------------
def _rundir(path):
    return RunDir.create(path, samples.run_config(), samples.keyring())


def _tree(root):
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() else None) for p in sorted(root.rglob("*"))}


def test_plan_hash_stable_across_reruns(tmp_path):
    hashes, blobs = set(), set()
    for i in range(2):
        b, n, t, pl = hero()
        d = dry_run(b.store, pl)
        hashes.add(d.plan.content_hash())
        p = write_plan(d.plan, _rundir(tmp_path / f"run{i}"))
        blobs.add(p.read_bytes())
        assert RecoveryPlan.from_canonical(p.read_bytes()) == d.plan
    assert len(hashes) == 1 and len(blobs) == 1


def test_plan_file_in_run_dir_plans_and_nothing_else_changes(tmp_path):
    """maya B3-21 review (2): ADR-05 §7 / CALL-02 C4: ``<run>/plans/<plan_id>.json`` via RunDir.write_plan."""
    b, n, t, pl = hero()
    rd = _rundir(tmp_path / "run")
    before = _tree(rd.path)
    p = write_plan(dry_run(b.store, pl).plan, rd)
    assert p == rd.path / "plans" / f"{pl.plan.plan_id}.json"
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    after = _tree(rd.path)
    assert {k for k in after if after[k] != before.get(k)} == {f"plans/{pl.plan.plan_id}.json"}
    assert set(before) <= set(after)


# --- dry-run -------------------------------------------------------------------------------------------------------
def test_dry_run_diff_and_state_unchanged():
    b, n, t, pl = hero()
    digest, heads = b.store.state_digest(), b.store.heads()
    d = dry_run(b.store, pl)
    assert b.store.state_digest() == digest == d.digest_before == d.digest_after
    assert b.store.heads() == heads
    diff = {e.obj: e for e in d.plan.diff}
    assert set(diff) == {IBAN, S22}
    assert diff[IBAN].current == heads[IBAN] and diff[IBAN].planned_hash == value_hash("DE00S-17")
    assert diff[S22].planned_hash == b.store.history(S22)[0].hash
    text = render(d)
    for needle in ("restore      suppliers:S-17.iban", "restore      suppliers:S-22", "rerun        billing",
                   "pending simulation", "kept         suppliers:S-17 v2 by triage",
                   "independent  docs, inventory", f"diff         {IBAN}", "flags 0", "state digest unchanged"):
        assert needle in text, needle


def test_dry_run_reports_t0_delta():
    """B3-45 option C residual: the plan carries the literal-walk t0 (C5 1.4) and the dry-run reports the delta."""
    b, n, t, pl = hero()
    assert pl.plan.t0_seq_est_literal == n["crm_honest"].seq
    assert pl.plan.t0_delta == n["crm_iban"].seq - n["crm_honest"].seq > 0
    text = render(dry_run(b.store, pl))
    assert f"literal walk {n['crm_honest'].seq}  t0_delta {pl.plan.t0_delta}" in text
    assert "view-only self-reads not followed" in text and "interim" not in text


def test_dry_run_rerunner_seam_rolled_back():
    """B3-24 seam: a rerunner writes inside the simulation; the diff shows it, the live store does not."""
    b, n, t, pl = hero()
    digest = b.store.state_digest()
    seen = []

    def rerunner(store, step, record, seq):
        seen.append(step.action.seq)
        out = []
        for w in record.write_set:
            out.append(store.put(w.obj, {"rerun": step.action.seq}, author=step.action.agent_id, seq=seq,
                                 action_id=step.action.action_id))
        return out

    d = dry_run(b.store, pl, rerunner=rerunner)
    assert seen == [s.action.seq for s in ops(pl.plan, "rerun")]
    assert b.store.state_digest() == digest
    diff = {e.obj: e for e in d.plan.diff}
    assert diff["invoices:INV-0011"].planned_hash == value_hash({"rerun": n["bill_inv17"].seq})
    assert "pending simulation" not in render(d)
    assert d.plan.content_hash() != dry_run(b.store, pl).plan.content_hash()


def test_dry_run_stale_expect_propagates():
    b, n, t, pl = hero()
    with b.store.txn():
        b.store.put(S22, {"name": "S-22", "price": 5, "terms": 30, "risk_note": ""}, author="inventory",
                    seq=b.next_seq + 5, action_id="x")
    digest = b.store.state_digest()
    with pytest.raises(StaleExpect):
        dry_run(b.store, pl)
    assert b.store.state_digest() == digest


# --- conflict, kept blind write, create, redaction, outbox, LLM ----------------------------------------------------
def _crm_fault(b):
    sup = [f"suppliers:{s}" for s in ("S-17", "S-22", "S-31")]
    w1 = b.act("crm", H, reads=[*sup, IBAN], writes={IBAN: "DE99ATTACKER"})
    w2 = b.act("crm", H + 1, reads=[*sup, IBAN], writes={S22: {"name": "S-22", "price": 1000, "terms": 30,
                                                                    "risk_note": ""}})
    return w1, w2


def _plan(b, ev, **kw):
    t = taint_from_alerts(b.records, [alert(ev)])
    return t, plan_recovery(b.records, t, alert_id="a-000001", state=b.store, **kw)


def test_triage_conflict_f2plus_x():
    """B5/F2+x: triage reads crm's S-22 v2 and edits it: exactly one flag(write_write_conflict, S-22, triage)."""
    b = seeded()
    _crm_fault(b)
    tri = b.act("triage", H + 2, reads=[S22], writes={S22: {"name": "S-22", "price": 1000, "terms": 30,
                                                              "risk_note": "check"}})
    rdr = b.act("billing", H + 2, reads=[S22], writes={"invoices:INV-0022": {"supplier": "S-22"}})
    b.suspend("crm", H + 3)
    t, pl = _plan(b, [ov(IBAN, 2)])
    p = pl.plan
    flags = ops(p, "flag")
    assert len(flags) == 1
    f = flags[0]
    assert (f.reason, f.obj, f.action.agent_id, f.action.seq) == ("write_write_conflict", S22, "triage", tri.seq)
    assert [s.obj for s in ops(p, "restore")] == [IBAN]
    assert ops(p, "rerun") == []  # triage and billing read S-22 v2/v3, which no step repairs
    assert {r.action.seq for r in pl.riders} == {tri.seq, rdr.seq}


def test_honest_blind_write_kept():
    """An untainted later head (honest write without reading crm's version) is kept: no restore, no flag."""
    b = seeded()
    _crm_fault(b)
    blind = b.act("inventory", H + 2, reads=[], writes={S22: {"name": "S-22", "price": 90, "terms": 30,
                                                               "risk_note": ""}})
    b.suspend("crm", H + 3)
    t, pl = _plan(b, [ov(IBAN, 2)])
    assert [s.obj for s in ops(pl.plan, "restore")] == [IBAN] and ops(pl.plan, "flag") == []
    assert (S22, 3, "inventory", blind.seq) in {(k.obj, k.ver, k.author, k.seq) for k in pl.kept}


def test_culprit_created_object_restored_to_absent():
    """B3-03 note: restore cannot rewind past v1; a culprit-created object gets a tombstone restore."""
    b = seeded()
    _crm_fault(b)
    b.act("crm", H + 1, reads=[], writes={"suppliers:S-99": {"name": "S-99", "price": 1, "terms": 1,
                                                              "risk_note": ""}})
    b.suspend("crm", H + 3)
    t, pl = _plan(b, [ov(IBAN, 2)])
    st = {s.obj: s for s in ops(pl.plan, "restore")}["suppliers:S-99"]
    assert st.reason == "tainted_create" and restores_to_absent(st) and st.to is None and st.to_absent and st.expect.ver == 1
    digest = b.store.state_digest()
    d = dry_run(b.store, pl)
    assert {e.obj: e.planned_hash for e in d.plan.diff}["suppliers:S-99"] == TOMBSTONE_HASH
    assert b.store.state_digest() == digest
    with b.store.simulate():
        w = apply_restore(b.store, st, seq=b.next_seq + 1, action_id="p.0")
        assert w.after.hash == TOMBSTONE_HASH and b.store.get("suppliers:S-99").value is None


def test_redacted_restore_source_flagged():
    b = seeded()
    _crm_fault(b)
    b.suspend("crm", H + 3)
    with b.store.txn():
        b.store.side.redact(b.store.history(IBAN)[0].hash)
    t, pl = _plan(b, [ov(IBAN, 2)])
    assert IBAN not in {s.obj for s in ops(pl.plan, "restore")}
    assert [(f.reason, f.obj) for f in ops(pl.plan, "flag")] == [("redacted_restore_source", IBAN)]


def test_outbox_dispatched_is_flag_and_queued_is_cancelled():
    b = seeded()
    _crm_fault(b)
    pay = b.act("payments", H + 2, reads=[IBAN], outbox=1, tool="payments.send")
    em = b.act("comms", H + 2, reads=[IBAN], outbox=1, tool="comms.send_email")
    b.suspend("crm", H + 3)
    item = OutboxItem(outbox_id="ob-000001", author="payments", action_id=pay.envelope.action_id,
                      created_seq=pay.seq, sink="payments", action_class="I1", payload_hash=value_hash(1),
                      idempotency_key=value_hash(2), lineage=(), status=OutboxStatus.DISPATCHED, release_tick=0,
                      dispatched_seq=pay.seq + 1)
    with b.store.txn():
        b.store.put("outbox:ob-000001", item.to_obj(), author="ks.gateway", seq=b.next_seq + 1, action_id="d")
    t, pl = _plan(b, [ov(IBAN, 2)], llm_agents=["comms"])
    # comms is replanned (not re-run): its real queued outbox object (B3-23) is cancelled
    assert [s.outbox_id for s in ops(pl.plan, "cancel_outbox")] == ["ob-000002"]
    assert [s.action.seq for s in ops(pl.plan, "replan")] == [em.seq]
    # payments is re-run but its item already left: flagged conservatively (B3-24 compares payload hashes)
    assert [s.action.seq for s in ops(pl.plan, "rerun")] == [pay.seq]
    fl = ops(pl.plan, "flag")
    assert [(f.reason, f.obj, f.action.seq) for f in fl] == [("dispatched_tainted", "outbox:ob-000001", pay.seq)]


def test_llm_reader_replan_and_its_reader_rides():
    b = seeded()
    _crm_fault(b)
    llm = b.act("reporter", H + 2, reads=[IBAN], writes={"docs:RPT-1": {"t": "x"}})
    nxt = b.act("billing", H + 3, reads=["docs:RPT-1"], writes={"invoices:INV-9": {"t": "y"}})
    b.suspend("crm", H + 4)
    t, pl = _plan(b, [ov(IBAN, 2)], llm_agents=["reporter"])
    assert [s.action.seq for s in ops(pl.plan, "replan")] == [llm.seq]
    assert ops(pl.plan, "rerun") == []
    assert [r.action.seq for r in pl.riders] == [nxt.seq]


# --- A3 -------------------------------------------------------------------------------------------------------------
def test_ast_guard_tcb_blind():
    banned_mods = ("ks.contracts.rundir", "ks.world", "ks.score", "ks.oracle", "ks.inject")
    files = sorted(PKG.glob("*.py"))
    assert files
    for f in files:
        for node in ast.walk(ast.parse(f.read_text(), filename=str(f))):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith(banned_mods), (f.name, node.module)
                assert all(a.name != "RunConfig" for a in node.names), f.name
            elif isinstance(node, ast.Import):
                assert not any(a.name.startswith(banned_mods) for a in node.names), f.name
            elif isinstance(node, ast.Name):
                assert node.id != "RunConfig", f.name
            elif isinstance(node, ast.Attribute):
                assert node.attr not in ("fault", "fault_tick", "tcb_view", "RunConfig"), (f.name, node.attr)
                if node.attr == "culprit":  # only the C5 plan's own field, read back for display
                    assert isinstance(node.value, ast.Name) and node.value.id == "p", f.name
