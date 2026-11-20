"""B3-28: static incident console + live/paced terminal view on a real world run dir."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ks.cli import main
from ks.console import BEATS, build_model, frame, render_html, run_live
from ks.console.live import beat_frame
from ks.contracts import Exit


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    out = tmp_path_factory.mktemp("c") / "run"
    p = subprocess.run([sys.executable, "-m", "ks", "run", "--scenario", "world", "--ticks", "40", "--out", str(out)],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return out


def _tree(d: Path) -> dict:
    return {str(p.relative_to(d)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.rglob("*")) if p.is_file()}


def test_html_deterministic_offline_and_readonly(run, tmp_path):
    before = _tree(run)
    a, b = render_html(run), render_html(run)
    assert a == b and _tree(run) == before
    assert not re.search(r"(src|href)\s*=\s*[\"']?(https?:)?//", a) and "http://" not in a and "https://" not in a
    assert "fetch(" not in a and "XMLHttpRequest" not in a
    assert main(["console", str(run), "--html", str(tmp_path / "o.html")]) == Exit.OK
    assert (tmp_path / "o.html").read_text() == a


def test_degraded_banner_and_verify_always_present(run):
    m = build_model(run)
    kinds = {b["kind"] for b in m["banners"]}
    cfg_iso = m["config"]["isolation"]
    assert ("isolation" in kinds) == (cfg_iso == "degraded")
    html = render_html(run)
    assert "last witnessed head" in html and "last witnessed head" in frame(run)
    if cfg_iso == "degraded":
        assert "attribution is VOID" in html and "VOID" in frame(run)
    else:  # per_agent_uid: the per-agent banner, no VOID anywhere
        assert cfg_iso == "per_agent_uid"
        assert "VOID" not in html and "VOID" not in frame(run)


def test_five_beats_in_order_and_pending_marked(run):
    m = build_model(run)
    assert [b["id"] for b in m["beats"]] == [b[0] for b in BEATS] == ["break", "identify", "contain", "recover", "audit"]
    for b in m["beats"]:
        if b["status"] == "pending":
            assert b["lines"][0].startswith("PENDING")
    assert m["beats"][4]["status"] == "live" and "stale" in m["beats"][4]["lines"][2]
    assert sum(m["beat_seconds"]) == 300


def test_edited_record_fails_audit_beat(run, tmp_path):
    bad = tmp_path / "bad"
    shutil.copytree(run, bad)
    lines = (bad / "record.jsonl").read_text().splitlines()
    lines[5] = lines[5].replace('"decision":"exec"', '"decision":"deny"', 1) if '"decision":"exec"' in lines[5] else lines[5][:-2] + "x}"
    (bad / "record.jsonl").write_text("\n".join(lines) + "\n")
    m = build_model(bad)
    assert not m["verify"]["ok"] and m["beats"][4]["status"] == "fail"
    assert any(b["kind"] == "verify" for b in m["banners"])


def _hero(tmp_path, *, alert=True, plan=True):
    """Real ks.world F2+ run (tests/recovery/world.py: real gateway, suspend, outbox holds) plus a chained ks.alert
    signed by ks.monitor, vikram's hero plan from plan_recovery + dry_run written to plans/."""
    from ks.contracts import Alert, AlertKind, ObjVer, SideDomain, CONTROL_TOOL, Envelope, Decision, Reason, ActionClass, SYSTEM_CONN
    from ks.contracts.hashing import args_hash
    from ks.identity import KeyStore, sign_hex
    from ks.contracts import SYSTEM_PRINCIPALS
    from ks.recovery import plan_recovery
    from ks.recovery.dryrun import dry_run, write_plan
    from ks.world.agents import AGENT_IDS
    from tests.recovery import world as W
    w = W.run(tmp_path / "s.db")
    if alert:
        keys = KeyStore.create(sorted(SYSTEM_PRINCIPALS | set(AGENT_IDS)), key_mode="repro", seed=W.SEED, secret=W.SECRET)
        g = w.gateway
        ev = ObjVer(obj=W.IBAN, ver=w.store.history(W.IBAN)[-1].ver)
        bad = next(r for r in w.records if r.write_set and any(x.obj == W.IBAN for x in r.write_set)
                   and r.envelope.agent_id == "crm")
        al = Alert(alert_id="a-000001", tick=bad.tick, seq=bad.seq, detector="inv.iban_checksum", kind=AlertKind.INVARIANT,
                   hard=True, evidence_seqs=(bad.seq,), evidence_versions=(ev,), root_candidates=("crm",), conn_id=None)
        body = al.to_obj()
        from ks.gateway.system import admit_system, system_envelope
        from ks.contracts import WitnessHead
        t = w.last_tick
        env = system_envelope("ks.monitor", "ks.alert", body, action_id="alert-1", tick=t, sign=keys.signer("ks.monitor"))
        adm = admit_system(g, env)  # through the gateway: signature, expiry, nonce, scope, then recorded
        assert adm.record.decision == Decision.EXEC and adm.record.sig_ok
        (w.rundir.path / "alerts.jsonl").write_bytes(al.to_canonical() + b"\n")  # the copy ks verify compares (F6)
        w.witness.push(WitnessHead(seq=g.recorder.seq, head=g.recorder.head, tick=t))
    if plan:
        pl = plan_recovery(w.records, w.taint, alert_id="a-000001", state=w.store)
        write_plan(dry_run(w.store, pl).plan, w.rundir)
    return w.rundir.path


@pytest.fixture(scope="module")
def hero(tmp_path_factory):
    return _hero(tmp_path_factory.mktemp("h"))


def test_alerts_from_chained_records_only(hero, tmp_path):
    d = tmp_path / "x"
    shutil.copytree(hero, d)
    (d / "alerts.jsonl").write_text(json.dumps({  # forged unauthenticated copy must never show
        "alert_id": "a-999999", "tick": 1, "seq": 1, "detector": "forged", "kind": "invariant", "hard": True,
        "evidence_seqs": [1], "root_candidates": ["docs"]}) + "\n")
    m = build_model(d)
    assert [a["alert_id"] for a in m["alerts"]] == ["a-000001"]
    assert "root candidates: crm" in m["beats"][1]["lines"] and "forged" not in render_html(d) and "a-999999" not in render_html(d)
    # no chained ks.alert (alerts.jsonl only) -> identify stays PENDING
    n = _hero(tmp_path / "n", alert=False, plan=False) if (tmp_path / "n").mkdir() is None else None
    (n / "alerts.jsonl").write_text((d / "alerts.jsonl").read_text())
    assert build_model(n)["alerts"] == [] and build_model(n)["beats"][1]["status"] == "pending"


def test_hero_beats_derived_from_record_and_plan(hero):
    from ks.console import model as M
    assert M._verify(hero)["ok"]  # the fixture now verifies (witnessed, alert through the gateway)
    m = build_model(hero)
    b = {x["id"]: x for x in m["beats"]}
    # held count comes from ks.control hold records on outbox:* objects (B3-23), not decision == hold
    assert len(m["held"]) >= 1 and all(h["outbox"].startswith("ob-") for h in m["held"])
    assert f"held items: {len(m['held'])}" in b["contain"]["lines"][1] and "held items: 0" not in b["contain"]["lines"][1]
    assert all(x["status"] == "live" for x in m["beats"][:4])
    assert {h["reason"] for h in m["held"]} <= {"lineage_hold", "sensitive_field"}
    ln = b["recover"]["lanes"]
    assert any("suppliers:S-17.iban" in x for x in ln["restore"]) and any("suppliers:S-22" in x for x in ln["restore"])
    assert {"billing", "payments", "comms", "reporter"} <= set(ln["rerun"])
    assert ln["kept"] == ["triage: risk note of S-17"] and "triage" not in ln["rerun"]
    assert ln["flags"] == 1
    assert "dry-run file, not in the record" in b["recover"]["lines"][0]
    assert b["break"]["lines"][0].startswith("crm changed bank account (IBAN) of S-17")
    # no hard-coded claims: the old fixture sentences appear only in PENDING beats
    for x in m["beats"]:
        if x["status"] != "pending":
            t = " ".join(x["lines"])
            assert "inventory and docs are independent" not in t
            assert "we kept its edit and restored only the bank account" not in t
    assert b["break"]["lines"][-1].startswith("read afterwards by: ")


def test_verify_failure_no_beat_live(hero, tmp_path):
    bad = tmp_path / "bad"
    shutil.copytree(hero, bad)
    lines = (bad / "record.jsonl").read_text().splitlines()
    k = next(i for i, x in enumerate(lines) if '"decision":"exec"' in x and i > 5)
    lines[k] = lines[k].replace('"decision":"exec"', '"decision":"deny"', 1)
    (bad / "record.jsonl").write_text("\n".join(lines) + "\n")
    m = build_model(bad)
    assert not m["verify"]["ok"] and any(x["kind"] == "verify" for x in m["banners"])
    assert not [x for x in m["beats"] if x["status"] == "live"]
    data = [x for x in m["beats"] if x["id"] in ("break", "identify", "contain", "recover")]
    assert all(x["status"] in ("unverified", "pending") for x in data)
    assert any(x["status"] == "unverified" and x["lines"][0].startswith("UNTRUSTED") for x in data)
    assert "LIVE" not in "".join(beat_frame(m, i) for i in range(5))
    assert "VERIFY FAILED" in render_html(bad)


def test_unwitnessed_records_marked(hero):
    m = build_model(hero)
    lw = m["verify"]["last_witnessed_seq"]
    assert all(r["unwitnessed"] == (lw is None or r["seq"] > lw) for r in m["records"])


def test_pace_stops_at_each_beat(run, tmp_path):
    prompts, out = [], []

    class W:
        def write(self, s): out.append(s)
    assert run_live(run, pace=True, out=W(), wait=prompts.append) == 0
    assert len(prompts) == 4 and "Beat 5/5 AUDIT" in "".join(out)


def test_cli_console_modes(run, capsys):
    assert main(["console", str(run), "--live", "--once"]) == Exit.OK
    assert "(read-only)" in capsys.readouterr().out
    assert main(["console", str(run), "--once", "--html", "x"]) == Exit.USAGE
    assert main(["console", str(run), "--html", "x", "--pace"]) == Exit.USAGE
    assert main(["console", str(run) + "-missing", "--html", "x"]) == Exit.IO


def _score(**kw):
    s = {"hold": 3, "tti_detect": 2, "tti_attribute": 0, "ttc": 1, "R": {"n": 0, "d": 5}, "C": {"n": 0, "d": 9},
         "irreversible_tainted_released": 0, "clean": {"unavailable": "invariants_ok not computed"},
         "baseline_oracle_assisted": False}
    return s | kw


def test_dry_run_diff_lists_plan_steps_and_t0(hero):
    from ks.console.live import beat_frame
    m = build_model(hero)
    rec = m["beats"][3]
    ops = [s["op"] for s in rec["plan"]["steps"]]
    assert {"restore", "rerun", "flag"} <= set(ops)  # the hero plan holds restore, re-run and one flag
    assert all(s["text"] and s["n"] == i for i, s in enumerate(rec["plan"]["steps"]))
    assert rec["plan"]["diff"] and all(len(d["planned_hash"]) == 16 for d in rec["plan"]["diff"])
    assert rec["plan"]["applied_records"] == 0 and any(x == "applied: nothing yet" for x in rec["lines"])
    assert any(x.startswith("t0 estimate: seq ") for x in rec["lines"])
    f = beat_frame(m, 3)
    assert "plan steps:" in f and "dry-run diff (hashes only):" in f and "restore bank account (IBAN) of S-17" in f
    assert "dry-run file, not in the record" in rec["lines"][0] and not rec["approved"]
    h = render_html(hero)
    assert "Dry-run diff (hashes only)" in h and "Scorecard" in h


def test_scorecard_unavailable_never_zero_and_not_run(hero, tmp_path):
    d = tmp_path / "s"
    shutil.copytree(hero, d)
    assert build_model(d)["scorecard"] is None and "not run (no score.json" in beat_frame(build_model(d), 3)
    (d / "score.json").write_text(json.dumps(_score(ttc={"unavailable": "no_alert"})))
    (d / "baselines" / "snapshot").mkdir(parents=True)
    (d / "baselines" / "snapshot" / "score.json").write_text(json.dumps(_score(R={"n": 3, "d": 5}, baseline="snapshot",
                                                                                baseline_oracle_assisted=True)))
    sc = build_model(d)["scorecard"]
    assert sc["columns"] == ["system", "snapshot", "revert_culprit_only"]
    row = {r["key"]: r["cells"] for r in sc["rows"]}
    assert row["ttc"][0] == "unavailable (no_alert)" and row["clean"][0].startswith("unavailable")
    assert row["R"] == ["0/5", "3/5", "not run"] and row["tti_attribute"][0] == "0"  # a real 0 stays 0
    assert row["ttc"][1] == "1" and row["ttc"][2] == "not run" and sc["oracle_assisted"] == ["snapshot"]
    assert sc["hold_note"] is None
    assert "unavailable (no_alert)" in beat_frame(build_model(d), 3) and "unavailable (no_alert)" in render_html(d)


def test_hold_zero_shows_escaped_payment_as_residual(hero, tmp_path):
    d = tmp_path / "h0"
    shutil.copytree(hero, d)
    (d / "score.json").write_text(json.dumps(_score(hold=0, R={"n": 1, "d": 5}, irreversible_tainted_released=1)))
    note = build_model(d)["scorecard"]["hold_note"]
    assert "H=0" in note and "1 tainted irreversible effect(s) escaped" in note and "R = 1/5" in note
    assert "H=0" in beat_frame(build_model(d), 3) and "H=0" in render_html(d)


def test_approved_label_needs_matching_ks_approve(hero):
    m = build_model(hero)
    assert all(not p["_approved"] for p in m["plans"]) and m["approvals"] == []


def test_audit_beat_names_first_bad_index_and_reason(run, tmp_path):
    bad = tmp_path / "bad"
    shutil.copytree(run, bad)
    lines = (bad / "record.jsonl").read_text().splitlines()
    k = next(i for i, x in enumerate(lines) if '"decision":"exec"' in x and i > 5)
    lines[k] = lines[k].replace('"decision":"exec"', '"decision":"deny"', 1)  # the one-line edit
    (bad / "record.jsonl").write_text("\n".join(lines) + "\n")
    m = build_model(bad)
    a = m["beats"][4]
    assert a["status"] == "fail" and a["first_bad"] == m["verify"]["first_bad"] and a["reason"] == m["verify"]["reason"]
    assert a["first_bad"] is not None and f"first bad seq {a['first_bad']}" in a["lines"][0]
    assert f"first bad index: {a['first_bad']} ({a['reason']})" in beat_frame(m, 4)
    assert "first bad index" in render_html(bad)
    ok = build_model(run)["beats"][4]
    assert ok["first_bad"] is None and "first bad index" not in beat_frame(build_model(run), 4)


def test_failed_verify_tamper_shows_real_first_bad_no_unwitnessed_claim(hero, tmp_path):
    bad = tmp_path / "bad"
    shutil.copytree(hero, bad)
    lines = (bad / "record.jsonl").read_text().splitlines()
    k = next(i for i, x in enumerate(lines) if '"decision":"exec"' in x and i > 5)
    lines[k] = lines[k].replace('"decision":"exec"', '"decision":"deny"', 1)
    (bad / "record.jsonl").write_text("\n".join(lines) + "\n")
    m = build_model(bad)
    v, a = m["verify"], m["beats"][4]
    assert not v["ok"] and v["first_bad"] is not None
    txt = " ".join(a["lines"])
    assert f"first bad seq {v['first_bad']}" in txt and v["reason"] in txt
    assert "tamper-evident up to" not in txt and "unwitnessed" not in txt
    assert not any(r["unwitnessed"] for r in m["records"])


def test_unwitnessed_tail_counts_only_beyond_last_witnessed_seq(hero, tmp_path):
    t = tmp_path / "tail"
    shutil.copytree(hero, t)
    w = t / "witness.jsonl"
    ls = w.read_text().splitlines()
    assert len(ls) > 2
    w.write_text("\n".join(ls[:-1]) + "\n")  # the newest witnessed head is gone: its records are the unwitnessed tail
    m = build_model(t)
    v = m["verify"]
    assert v["ok"], v
    lw = v["last_witnessed_seq"]
    tail = [r["seq"] for r in m["records"] if r["unwitnessed"]]
    assert tail and all(s_ > lw for s_ in tail) and len(tail) == sum(1 for r in m["records"] if r["seq"] > lw)
    assert not any(r["unwitnessed"] for r in m["records"] if r["seq"] <= lw)
    txt = " ".join(m["beats"][4]["lines"])
    assert f"{len(tail)} record(s) after the last witnessed head (seq {lw}) are unwitnessed" in txt
    assert "tamper-evident up to the last witnessed head" in txt


def test_truncated_record_fails_with_real_first_bad_not_unwitnessed(hero, tmp_path):
    t = tmp_path / "trunc"
    shutil.copytree(hero, t)
    r = t / "record.jsonl"
    ls = r.read_text().splitlines()
    r.write_text("\n".join(ls[:-3]) + "\n")  # records cut below the witnessed head
    m = build_model(t)
    v, a = m["verify"], m["beats"][4]
    assert not v["ok"] and v["first_bad"] is not None
    txt = " ".join(a["lines"])
    assert f"first bad seq {v['first_bad']}" in txt and v["reason"] in txt
    assert "unwitnessed" not in txt and "tamper-evident up to" not in txt


def _copy(run, tmp_path):
    bad = tmp_path / "bad"
    shutil.copytree(run, bad)
    return bad


def _assert_fail_page(bad, capsys=None):
    m = build_model(bad)
    assert not m["verify"]["ok"] and m["beats"][4]["status"] == "fail"
    assert all(b["status"] != "live" for b in m["beats"])
    assert m["beats"][4]["reason"] and "verify FAILED" in " ".join(m["beats"][4]["lines"])
    assert frame(bad) and any(b["kind"] == "verify" for b in m["banners"])
    return m


def test_malformed_record_line_renders_fail_page(run, tmp_path):
    bad = _copy(run, tmp_path)
    lines = (bad / "record.jsonl").read_text().splitlines()
    lines[3] = lines[3][:20] + "{{not json"
    (bad / "record.jsonl").write_text("\n".join(lines) + "\n")
    m = _assert_fail_page(bad)
    assert m["verify"]["reason"] == "parse_error" and m["beats"][4]["first_bad"] == m["verify"]["first_bad"] is not None
    out = tmp_path / "o.html"
    main(["console", str(bad), "--html", str(out)])
    assert out.is_file() and "parse_error" in out.read_text()


def test_truncated_record_renders_fail_page(run, tmp_path):
    bad = _copy(run, tmp_path)
    b = (bad / "record.jsonl").read_bytes()
    (bad / "record.jsonl").write_bytes(b[: len(b) // 2])
    _assert_fail_page(bad)
    (bad / "record.jsonl").write_bytes(b"")
    build_model(bad)
    render_html(bad)


def test_malformed_score_alerts_plan_witness_do_not_crash(hero, tmp_path):
    bad = tmp_path / "bad"
    shutil.copytree(hero, bad)
    (bad / "score.json").write_text("{not json")
    for p in (bad / "plans").glob("*.json"):
        p.write_text("[[")
    if (bad / "alerts.jsonl").exists():
        (bad / "alerts.jsonl").write_text("garbage\n")
    for p in bad.glob("witness*"):
        if p.is_file():
            p.write_text("garbage")
    m = build_model(bad)
    assert m["score"] is None and m["scorecard"] is None
    assert m["beats"][3]["status"] == "pending"
    assert render_html(bad) and frame(bad)


def test_no_lineage_hold_contrast_banner(run, tmp_path):
    """B3-51 / contracts 1.6: a `--hold 0 --no-lineage-hold` run carries RunConfig.lineage_hold = false; the page and
    the live view show the NO-LINEAGE-HOLD banner; a normal run shows none."""
    from ks.contracts import NO_LINEAGE_HOLD_BANNER
    assert not any(b["kind"] == "contrast" for b in build_model(run)["banners"])
    out = tmp_path / "contrast"
    p = subprocess.run([sys.executable, "-m", "ks", "run", "--scenario", "world", "--ticks", "8", "--hold", "0",
                        "--no-lineage-hold", "--out", str(out)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    m = build_model(out)
    assert m["config"]["lineage_hold"] is False and m["verify"]["ok"] and m["verify"]["lineage_hold"] is False
    assert {"kind": "contrast", "text": NO_LINEAGE_HOLD_BANNER} in m["banners"]
    assert "NO-LINEAGE-HOLD contrast run" in render_html(out) and "NO-LINEAGE-HOLD contrast run" in frame(out)
