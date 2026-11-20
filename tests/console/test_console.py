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
        g.recorder.put_side(SideDomain.ARGS, args_hash(body), body)
        env = Envelope(agent_id="ks.monitor", action_id="alert-1", parent_action_id=None, act_chain=(), tool="ks.alert",
                       args=body, nonce="2" * 32, expiry_tick=w.records[-1].tick, epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)
        env = env.with_sig(sign_hex(keys.private("ks.monitor"), env.signing_bytes()))
        cfg = g.config
        g.recorder.append(tick=w.records[-1].tick, ts_us=cfg.start_ts_us + w.records[-1].tick * cfg.tick_us, conn_id=SYSTEM_CONN,
                          envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=True, decision=Decision.EXEC,
                          reason=Reason.OK, policy_rule=None, action_class=ActionClass.R, read_set=(), write_set=(),
                          outbox_ids=(), result_hash=None, control=None, reexec_of=None)
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


def test_hero_beats_derived_from_record_and_plan(hero, monkeypatch):
    # the in-process world fixture has no witness (verify cannot pass); pin an OK verify to read the live lines
    from ks.console import model as M
    real = M._verify(hero)
    monkeypatch.setattr(M, "_verify", lambda run: real | {"ok": True, "reason": "ok", "first_bad": None})
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
