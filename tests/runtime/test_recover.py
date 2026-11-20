"""B3-30: recovery apply via c-0, approval-bound (ADR-05 §6-8, CALL-02 G6/F5/B2, C5).

On the real ks.world F2+ run driven through the real Gateway (tests/recovery/world.py): plan -> dry-run ->
``ks.approve`` (ks.operator) -> one ``ks.recover.<op>`` record per step (ks.recovery, c-0) -> state equals S*.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading

import pytest

from ks.contracts import (APPROVE_TOOL, SYSTEM_CONN, Alert, AlertKind, ControlOp, Decision,
                          ObjVer, OutboxStatus, Reason, RecoverArgs, RunAnchor, RunDir, sidestore_relpath)
from ks.gateway.system import SystemRequest
from ks.recovery import ToolRerunner, args_from_sidestore, dry_run, plan_recovery, write_plan
from ks.runtime.operator import OperatorServer, parse_request
from ks.runtime.recover import REHELD_REASON, RecoveryService, approved_steps, bench_releasable, cli_apply
from ks.verify import verify
from ks.world.tools import WorldDispatcher

from tests.recovery import world as W


def _q(_s):
    pass


def _side(w, h):
    return json.loads((w.rundir.path / sidestore_relpath(h)).read_text())["value"]


def setup(w, *, fault_plan=None):
    """Plan + dry-run + plan file; install the RecoveryService and the operator/recovery signers (as ks.runtime)."""
    pl = fault_plan or plan_recovery(w.records, w.taint, alert_id="a-000001", state=w.store)
    dr = dry_run(w.store, pl, rerunner=ToolRerunner(WorldDispatcher(), args_from_sidestore(w.rundir.path)),
                 on_stale="halt")
    write_plan(dr.plan, w.rundir)
    g = w.gateway
    g.system._signers.update({p: w.keys.signer(p) for p in ("ks.operator", "ks.recovery", "ks.monitor")})
    g.recovery = RecoveryService(w.rundir.path, w.keys.signer("ks.recovery"), dispatcher=g.dispatcher)
    return dr


def approve(w, plan, steps=None):
    out = []
    steps = approved_steps(plan) if steps is None else steps
    w.gateway.system.put(SystemRequest("ks.operator", APPROVE_TOOL, build=lambda gw, t, q: plan.approval(steps).to_obj(),
                                       done=out.append))
    return out


def recover(w, plan, steps=None):
    out = []
    steps = approved_steps(plan) if steps is None else steps
    for r in w.gateway.recovery.requests({"op": "recover", "plan_id": plan.plan_id, "plan_hash": plan.content_hash(),
                                          "steps": list(steps)}):
        r.done = out.append
        w.gateway.system.put(r)
    return out


def tick(w):
    W._tick(w, w.last_tick + 1, lambda a, f: None)


def heads(w):
    return {o: r.hash for o, r in w.store.heads().items() if not o.startswith("outbox:")}


@pytest.fixture(scope="module")
def hero(tmp_path_factory):
    d = tmp_path_factory.mktemp("b330")
    w = W.run(d / "f2plus.db")
    s = W.run(d / "sstar.db", fault=None)
    dr = setup(w)
    a = approve(w, dr.plan)
    r = recover(w, dr.plan)
    tick(w)
    return w, s, dr, a, r


# --- acceptance 1: approval and step records ---------------------------------------------------------------------
def test_approve_and_every_step_recorded_with_recover_args(hero):
    w, s, dr, a, r = hero
    p = dr.plan
    (ap,) = a
    assert (ap.record.envelope.agent_id, ap.record.conn_id, ap.record.decision) == ("ks.operator", SYSTEM_CONN,
                                                                                      Decision.EXEC)
    assert _side(w, ap.record.envelope.args_hash) == p.approval(approved_steps(p)).to_obj()
    env_steps = [x for x in p.steps if x.op in ("restore", "rerun", "cancel_outbox")]
    assert len(r) == len(env_steps) and all(not isinstance(x, Exception) for x in r)
    for x, adm in zip(env_steps, r):
        rec = adm.record
        assert (rec.envelope.agent_id, rec.envelope.tool, rec.envelope.action_id, rec.conn_id, rec.decision) == (
            "ks.recovery", f"ks.recover.{x.op}", f"{p.plan_id}.{x.n}", SYSTEM_CONN, Decision.EXEC)
        args = RecoverArgs.model_validate(_side(w, rec.envelope.args_hash))
        assert (args.plan_id, args.plan_hash, args.n, args.step) == (p.plan_id, p.content_hash(), x.n, x)
        assert rec.seq > ap.record.seq
    assert w.gateway.recovery.halts == {}


def test_hero_apply_equals_sstar_and_dry_run(hero):
    """After apply every non-outbox object equals S* by hash, and equals the dry-run's planned hash."""
    w, s, dr, a, r = hero
    assert heads(w) == heads(s)
    for e in dr.plan.diff:
        if not e.obj.startswith("outbox:"):
            assert w.store.get(e.obj).hash == e.planned_hash, e.obj
    assert w.store.get(W.IBAN).author == "ks.recovery"


def test_reheld_items_get_a_recovery_hold_record_and_s_star_payloads(hero):
    """ADR-03 §7: every item a re-run re-held has a ks.control hold by ks.recovery (rerun_reheld) after the re-run
    record; status held; payload = S* payload of the same action (M14)."""
    w, s, dr, a, r = hero
    reheld = {oid: adm.record.seq for adm in r for oid in adm.record.outbox_ids}
    assert set(reheld) == set(w.taint.outbox_ids) == set(dr.reheld)
    holds = {rec.control.target[7:]: rec for rec in w.records if rec.control is not None
             and rec.control.issued_by == "ks.recovery"}
    for oid, seq in reheld.items():
        h = holds[oid]
        assert h.seq > seq and h.control.op == ControlOp.HOLD and h.control.reason == REHELD_REASON
        assert not h.control.auto and [x.obj for x in h.write_set] == [f"outbox:{oid}"]
        it = w.gateway.outbox.get(oid).item
        assert it.status == OutboxStatus.HELD and it.payload_hash == s.payloads[it.action_id]


def test_repairs_recorded_when_rerun_value_equals_head(hero):
    """A re-run whose value equals the head writes no version by itself; apply records a repair version (same
    hash, original author) so the head is no longer the tainted version."""
    w, s, dr, a, r = hero
    rep = {}
    for adm in r:
        if adm.record.envelope.tool == "ks.recover.rerun":
            v = _side(w, adm.record.result_hash)
            for o in v["repaired"]:
                rep[o] = (adm.record, v)
    assert rep  # e.g. ledger rows and compliance findings on the hero
    for o, (rec, v) in rep.items():
        h = w.store.history(o)
        assert h[-1].hash == h[-2].hash and h[-1].author == v["agent_id"] and h[-1].seq == rec.seq
        assert not w.taint.is_tainted(o, h[-1].ver)


def test_hero_apply_verifies(hero):
    w = hero[0]
    rep = verify(w.rundir.path, log=_q)
    assert rep.ok, rep


def test_bench_releases_reheld_items_and_they_dispatch_with_sstar_payload(tmp_path):
    """X4 + kabir B3-23: an unhold of a re-held item passes the release-phase provenance check (the re-run record is
    its creating record) and dispatches; verify still OK."""
    w = W.run(tmp_path / "f2.db")
    s = W.run(tmp_path / "s.db", fault=None)
    dr = setup(w)
    approve(w, dr.plan)
    recover(w, dr.plan)
    tick(w)
    g = w.gateway
    rel = bench_releasable(w.records, lambda o: g.outbox.get(o).item.status)
    assert set(rel) == set(dr.reheld)
    for oid in rel:
        g.system.put(parse_request({"op": "unhold", "target": f"outbox:{oid}", "reason": "bench"}, W.AGENT_IDS))
    tick(w)
    tick(w)
    for oid in rel:
        it = g.outbox.get(oid).item
        assert it.status == OutboxStatus.DISPATCHED, oid
        assert it.payload_hash == s.payloads[it.action_id]
    assert not [r for r in w.records if r.control is not None and r.control.reason == "unrecorded_item"]
    assert verify(w.rundir.path, log=_q).ok


def test_bench_never_releases_rider_items_f2plus_x(tmp_path):
    """B3-48 / ADR-05 §6.1 amended: F2+x rider items stay held under lineage_hold; the bench approver skips them."""
    w = W.run(tmp_path / "x.db", fault="f2plus_x")
    dr = setup(w)
    held = {h.outbox_id for h in dr.held}
    assert held
    approve(w, dr.plan)
    recover(w, dr.plan)
    tick(w)
    g = w.gateway
    rel = set(bench_releasable(w.records, lambda o: g.outbox.get(o).item.status))
    assert not rel & held
    assert all(g.outbox.get(o).item.status == OutboxStatus.HELD for o in held)
    assert verify(w.rundir.path, log=_q).ok


# --- acceptance 2: binding ---------------------------------------------------------------------------------------
def test_no_approval_is_denied_and_halts(tmp_path):
    w = W.run(tmp_path / "f2.db")
    dr = setup(w)
    before = heads(w)
    r = recover(w, dr.plan)  # no ks.approve
    tick(w)
    first, rest = r[0], r[1:]
    assert (first.record.decision, first.record.reason) == (Decision.DENY, Reason.OUT_OF_SCOPE)
    assert all(isinstance(x, Exception) for x in rest)  # halted: refused before any record
    assert heads(w) == before
    assert verify(w.rundir.path, log=_q).ok  # a denied step executed nothing


def test_unapproved_step_is_denied(tmp_path):
    w = W.run(tmp_path / "f2.db")
    dr = setup(w)
    approve(w, dr.plan, steps=(0,))
    r = recover(w, dr.plan, steps=(0, 1))
    tick(w)
    assert r[0].record.decision == Decision.EXEC
    assert (r[1].record.decision, r[1].record.reason) == (Decision.DENY, Reason.OUT_OF_SCOPE)


def test_verify_rejects_recovery_without_approval(tmp_path, monkeypatch):
    """A gateway that skipped the binding check would leave an exec ks.recover.* with no ks.approve: TAMPER."""
    w = W.run(tmp_path / "f2.db")
    dr = setup(w)
    monkeypatch.setattr(RecoveryService, "_unbound", lambda self, records, args: None)
    r = recover(w, dr.plan, steps=(0,))
    tick(w)
    assert r[0].record.decision == Decision.EXEC
    rep = verify(w.rundir.path, log=_q)
    assert (rep.ok, rep.reason, rep.first_bad) == (False, "recovery_unbound", r[0].record.seq)


def test_edited_plan_file_detected(tmp_path):
    w = W.run(tmp_path / "f2.db")
    dr = setup(w)
    approve(w, dr.plan)
    recover(w, dr.plan, steps=(0,))
    tick(w)
    assert verify(w.rundir.path, log=_q).ok
    p = w.rundir.path / "plans" / f"{dr.plan.plan_id}.json"
    edited = dr.plan.model_copy(update={"culprit": "triage"})
    p.write_bytes(edited.to_canonical())
    rep = verify(w.rundir.path, log=_q)
    assert (rep.ok, rep.reason) == (False, "recovery_unbound")
    # and the gateway refuses to run further steps of the edited plan
    with pytest.raises(ValueError, match="edited"):
        w.gateway.recovery.requests({"op": "recover", "plan_id": dr.plan.plan_id,
                                     "plan_hash": dr.plan.content_hash(), "steps": [1]})


def test_double_apply_adds_nothing(tmp_path):
    w = W.run(tmp_path / "f2.db")
    dr = setup(w)
    approve(w, dr.plan)
    recover(w, dr.plan)
    tick(w)
    after = heads(w)
    r2 = recover(w, dr.plan)
    tick(w)
    assert (r2[0].record.decision, r2[0].record.reason) == (Decision.DENY, Reason.NONCE_REUSED)
    assert heads(w) == after and verify(w.rundir.path, log=_q).ok


# --- acceptance 3: freeze, stale -----------------------------------------------------------------------------------
def test_frozen_by_tamper_alert_is_recovery_frozen(tmp_path):
    w = W.run(tmp_path / "f2.db")
    dr = setup(w)
    approve(w, dr.plan)
    seq = w.gateway.recorder.seq
    al = Alert(alert_id="a-000002", tick=w.last_tick + 1, seq=seq, detector="tamper.record_edit",
               kind=AlertKind.TAMPER, hard=False, evidence_seqs=(seq,), evidence_versions=(), root_candidates=(),
               conn_id=None)
    w.gateway.system.put(SystemRequest("ks.monitor", "ks.alert", build=lambda gw, t, q: al.to_obj()))
    before = heads(w)
    r = recover(w, dr.plan)
    tick(w)
    assert (r[0].record.decision, r[0].record.reason) == (Decision.DENY, Reason.RECOVERY_FROZEN)
    assert all(isinstance(x, Exception) for x in r[1:]) and heads(w) == before


def test_honest_write_between_dry_run_and_apply_holds_stale_and_halts(tmp_path):
    """M8 in the apply txn: an honest write lands on an object a re-run wrote; that step is hold/stale_plan, the
    restores before it stay applied, nothing after it runs."""
    w = W.run(tmp_path / "f2.db")
    dr = setup(w)
    inv = w.log[(W.H + 1, "billing")]
    late = W.extra_tick(w, "billing", "billing.draft_invoice", {**_side(w, inv.envelope.args_hash), "qty": 6})
    assert [x.obj for x in late.write_set] == ["invoices:INV-0031"]  # honest, through the gateway
    approve(w, dr.plan)
    r = recover(w, dr.plan)
    tick(w)
    recs = [x for x in r if not isinstance(x, Exception)]
    stale = recs[-1].record
    assert (stale.decision, stale.reason) == (Decision.HOLD, Reason.STALE_PLAN)
    assert stale.envelope.tool == "ks.recover.rerun" and not stale.write_set
    assert all(x.record.decision == Decision.EXEC for x in recs[:-1])
    assert all(isinstance(x, Exception) for x in r[len(recs):]) and len(r) > len(recs)
    assert w.store.get(W.IBAN).author == "ks.recovery"  # applied steps stay (append-only)
    assert verify(w.rundir.path, log=_q).ok


# --- operator socket + CLI -----------------------------------------------------------------------------------------
def test_ks_recover_apply_over_the_operator_socket(tmp_path):
    w = W.run(tmp_path / "f2.db")
    s = W.run(tmp_path / "s.db", fault=None)
    dr = setup(w)
    srv = OperatorServer(w.rundir.path, w.gateway.system, W.AGENT_IDS, recover=w.gateway.recovery.requests).start()
    box = []
    try:
        t = threading.Thread(target=lambda: box.append(cli_apply(w.rundir.path, dr.plan.plan_id)))
        t.start()
        while t.is_alive():
            if len(w.gateway.system):
                tick(w)
            t.join(0.02)
    finally:
        srv.close()
    plan, a, r = box[0]
    assert a["ok"] and r["ok"] and len(r["steps"]) == len([x for x in plan.steps if x.op != "flag"])
    assert heads(w) == heads(s) and verify(w.rundir.path, log=_q).ok


def test_ks_recover_dry_run_cli_writes_plan(tmp_path, capsys):
    from ks.cli import main
    w = W.run(tmp_path / "f2.db")
    w.gateway.system._signers["ks.monitor"] = w.keys.signer("ks.monitor")
    w.gateway.system.put(SystemRequest("ks.monitor", "ks.alert", build=lambda gw, t, q: w.alert.to_obj()))
    tick(w)
    with open(w.rundir.path / "alerts.jsonl", "ab") as f:  # the monitor's copy (F6), as ks.containment writes it
        f.write(w.alert.to_canonical() + b"\n")
    w.store.close()
    assert main(["recover", str(w.rundir.path), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "restore      suppliers:S-17.iban" in out and "--apply p-" in out
    (pf,) = (w.rundir.path / "plans").glob("p-*.json")
    assert re.search(r"--apply (p-\d+)", out).group(1) == pf.stem


# --- R3: ks run --decisions end to end ----------------------------------------------------------------------------
def test_ks_run_decisions_replays_anchored_source(tmp_path):
    """kabir B3-20: ks run --decisions SRC --decisions-head ANCHOR sets decisions_from = anchor hash and replays the
    source's operator Controls at their ticks; verify_replay is OK."""
    from tests.runtime.test_operator import _popen_run, _wait_line
    from tests.skeleton.conftest import ENV, REPO, ks
    from ks.verify.decisions import anchor_hash, load_decisions, verify_replay
    import os
    import shutil
    import tempfile
    from pathlib import Path

    base = Path(tempfile.mkdtemp(prefix="ks-b330-", dir="/tmp"))
    os.chmod(base, 0o711)
    try:
        src = base / "src"
        p = _popen_run(src, "--ticks", "8", "--pause-at", "4")
        try:
            _wait_line(p, "paused before tick 4")
            assert ks("contain", "suspend", "agent:crm", src).returncode == 0
            out, err = p.communicate(timeout=120)
            assert p.returncode == 0, err
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
        line = out.split("RunAnchor (copy into ks verify --head):")[1].strip().splitlines()[0]
        anchor = RunAnchor.from_canonical(line.encode())
        dst = base / "dst"
        q = subprocess.run([sys.executable, "-m", "ks", "run", "--scenario", "world", "--seed", "7", "--ticks", "8",
                            "--out", str(dst), "--decisions", str(src), "--decisions-head", line],
                           cwd=REPO, env=ENV, capture_output=True, text=True, timeout=180)
        assert q.returncode == 0, q.stderr
        cfg = RunDir(dst).config()
        assert cfg.decisions_from == anchor_hash(anchor)
        ctl = [(r.tick, r.control.op.value, r.control.target) for r in RunDir(dst).records()
               if r.control is not None and r.envelope.agent_id == "ks.operator"]
        assert ctl == [(4, "suspend", "agent:crm")]
        rep = verify_replay(dst, load_decisions(src, anchor))
        assert rep.ok, rep
        # a run without the anchor is refused (USAGE), nothing created
        bad = subprocess.run([sys.executable, "-m", "ks", "run", "--scenario", "world", "--seed", "7", "--ticks", "2",
                              "--out", str(base / "x"), "--decisions", str(src)], cwd=REPO, env=ENV,
                             capture_output=True, text=True, timeout=60)
        assert bad.returncode == 64 and not (base / "x").exists()
    finally:
        shutil.rmtree(base, ignore_errors=True)
