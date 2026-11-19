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
    assert "last witnessed head" in html and "attribution is VOID" in html
    assert "last witnessed head" in frame(run)
    if cfg_iso == "degraded":
        assert "VOID" in frame(run)


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


def _hero(run, tmp_path):
    """Run dir plus a hand-written alert, suspend record, hold and plan shaped like the contracts."""
    d = tmp_path / "hero"
    shutil.copytree(run, d)
    recs = [json.loads(x) for x in (d / "record.jsonl").read_text().splitlines()]
    crm = next(r for r in recs if r["envelope"]["agent_id"] == "crm")
    (d / "alerts.jsonl").write_text(json.dumps({
        "alert_id": "a-000001", "tick": crm["tick"], "seq": crm["seq"], "detector": "inv.iban_checksum", "kind": "invariant",
        "hard": True, "evidence_seqs": [crm["seq"]], "root_candidates": ["crm"]}) + "\n")
    plan = {"plan_id": "p-000001", "alert_id": "a-000001", "culprit": "crm", "t0_seq_est": crm["seq"] - 1, "as_of_seq": 203,
            "taint_set": {"actions": [{"seq": 100, "agent_id": "billing", "action_id": "x"}], "versions": [], "outbox_ids": []},
            "steps": [{"n": 0, "op": "restore", "reason": "tainted_write", "obj": "suppliers:S-17.iban"},
                      {"n": 1, "op": "rerun", "reason": "tainted_read", "action": {"seq": 100, "agent_id": "billing", "action_id": "x"}}],
            "diff": []}
    (d / "plans").mkdir(exist_ok=True)
    (d / "plans" / "p-000001.json").write_text(json.dumps(plan))
    return d


def test_alert_and_plan_render_live_with_lanes(run, tmp_path):
    d = _hero(run, tmp_path)
    m = build_model(d)
    ident, rec = m["beats"][1], m["beats"][3]
    assert ident["status"] == "live" and "crm" in ident["lines"][1]
    assert rec["status"] == "live" and set(rec["lanes"]) >= {"restore", "rerun", "kept", "independent"}
    assert rec["lanes"]["rerun"] == ["billing"] and rec["lanes"]["flags"] == 0
    assert "bank account (IBAN)" in rec["lanes"]["restore"][0]


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
