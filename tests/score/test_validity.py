"""S4-22: a run that is not a security run (VOID) or that missed tick deadlines (DEGRADED) says so in score.json
and in the console, and `python -m ks.validity` refuses it (the finale script's gate)."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ks.cli import main
from ks.console import build_model, frame, render_html
from ks.validity import VALIDITY_KEY, run_validity, score_entry


@pytest.fixture(scope="module")
def scored(tmp_path_factory):
    """A real F2+ hero run, scored. Native = degraded isolation; in the container (root) = per_agent_uid."""
    out = tmp_path_factory.mktemp("v") / "hero"
    main(["run", "--scenario", "world", "--fault", "F2+", "--seed", "2", "--ticks", "40", "--out", str(out)])
    assert main(["score", str(out)]) == 0
    return out


def _score(run: Path) -> dict:
    return json.loads((run / "score.json").read_text())


def _validity_cli(run: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "ks.validity", str(run)], capture_output=True, text=True)


def test_native_run_void_in_score_and_console(scored):
    v = run_validity(scored)
    s = _score(scored)
    if v["isolation"] == "degraded":  # native run
        assert v["verdict"] == "VOID" and not v["headline"] and "isolation_degraded" in v["reasons"]
        assert s[VALIDITY_KEY]["verdict"] == "VOID"
        assert "VOID" in render_html(scored) and "NOT THE HEADLINE" in frame(scored)
        p = _validity_cli(scored)
        assert p.returncode == 1 and "VOID" in p.stdout
    else:  # container: a clean run keeps the pre-S4-22 score.json bytes (no key) and is the headline
        assert v["isolation"] == "per_agent_uid" and v["key_mode"] == "fresh"
        assert (VALIDITY_KEY in s) == (not v["headline"])
    assert isinstance(s.get(VALIDITY_KEY, {"deadline_misses": 0})["deadline_misses"], int)
    assert f"deadline misses: {v['deadline_misses']}" in build_model(scored)["validity_line"]


def test_injected_deadline_miss_is_flagged(scored, tmp_path):
    d = tmp_path / "miss"
    shutil.copytree(scored, d)
    rows = [json.loads(x) for x in (d / "timing.jsonl").read_text().splitlines() if x]
    rows[5]["missed"] = ["c-3"]
    (d / "timing.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    v = run_validity(d)
    assert v["deadline_misses"] == 1 and v["missed_ticks"] == [rows[5]["tick"]] and not v["headline"]
    assert "deadline_missed" in v["reasons"] and v["verdict"] in ("VOID", "DEGRADED")
    assert main(["score", str(d)]) == 0  # S* is reused from the copied oracle/s-star
    s = _score(d)
    assert s[VALIDITY_KEY]["deadline_misses"] == 1
    m = build_model(d)
    assert any(b["kind"] == "deadline" and "1 tick deadline misses" in b["text"] for b in m["banners"])
    assert "DEGRADED RUN" in render_html(d) and "deadline misses: 1" in frame(d)
    assert _validity_cli(d).returncode == 1


def _fake(tmp_path: Path, *, isolation="per_agent_uid", key_mode="fresh", missed=(), timing=True) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "config.json").write_text(json.dumps({"isolation": isolation, "key_mode": key_mode}))
    if timing:
        (tmp_path / "timing.jsonl").write_text("".join(
            json.dumps({"tick": t, "wall_us": 1, "missed": ["c-1"] if t in missed else [], "witness_ack": True}) + "\n"
            for t in range(10)))
    return tmp_path


def test_verdicts(tmp_path):
    ok = run_validity(_fake(tmp_path / "ok"))
    assert ok["verdict"] == "OK" and ok["headline"] and score_entry(tmp_path / "ok") is None
    assert _validity_cli(tmp_path / "ok").returncode == 0
    deg = run_validity(_fake(tmp_path / "deg", missed=(3, 7)))
    assert deg["verdict"] == "DEGRADED" and deg["deadline_misses"] == 2 and deg["missed_ticks"] == [3, 7]
    assert run_validity(_fake(tmp_path / "rep", key_mode="repro"))["verdict"] == "VOID"
    assert run_validity(_fake(tmp_path / "iso", isolation="degraded"))["verdict"] == "VOID"
    nt = run_validity(_fake(tmp_path / "nt", timing=False))
    assert nt["verdict"] == "DEGRADED" and nt["deadline_misses"] is None and "no_timing" in nt["reasons"]
    assert run_validity(tmp_path / "nothing") is None and score_entry(tmp_path / "nothing") is None


def test_finale_script_gates():
    root = Path(__file__).resolve().parents[2]
    if not (root / "scripts" / "finale.sh").exists():
        pytest.skip("host-side script; the container image copies only src/ and tests/")
    sh = (root / "scripts" / "finale.sh").read_text()
    for needle in ("make smoke", "per_agent_uid", "anchored", "python -m ks.validity", "KS_MAX_LOAD_PER_CPU",
                   'FAULT="F2+x" RESOLVER="$F2X_RESOLVER"', 'F2X_RESOLVER="ww_rebase/1"', "exit 3"):
        assert needle in sh, needle
    assert "finale:" in (root / "Makefile").read_text()
    assert subprocess.run(["bash", "-n", str(root / "scripts" / "finale.sh")]).returncode == 0
