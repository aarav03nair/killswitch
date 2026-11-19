"""B3-46 additivity regression (kabir's blocker): a world run written by contracts 1.3.0 must still verify under 1.4.

Fixture ``fixtures/run-1.3-world-s0`` was built from commit 5c711d3 (contracts 1.3.0) with
``ks run --scenario world --ticks 8 --seed 0``; its read sets are non-empty and carry no ``source`` field. If a new
field's default ever leaks into the canonical form again, the record bytes stop being canonical and verify fails
(``parse_error``). Empty run-dir subdirectories are not tracked by git, so the test recreates them.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ks.contracts import CONTRACTS_VERSION, Record, canonical
from ks.verify import verify

FIXTURE = Path(__file__).with_name("fixtures") / "run-1.3-world-s0"


def _copy(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    for d in ("baselines", "oracle", "plans"):
        (run / d).mkdir(exist_ok=True)
    for p in run.rglob("*"):
        p.chmod(0o700 if p.is_dir() else 0o600)
    return run


def test_fixture_is_a_13_run_with_reads():
    cfg = json.loads((FIXTURE / "config.json").read_bytes())
    assert cfg["contracts_version"] == "1.3.0" and CONTRACTS_VERSION != "1.3.0"
    lines = (FIXTURE / "record.jsonl").read_bytes().splitlines()
    recs = [Record.from_canonical(line) for line in lines]  # strict parse under 1.4: bytes are still canonical
    assert sum(1 for r in recs if r.read_set) >= 5
    assert all(e.source == "tool" for r in recs for e in r.read_set)
    assert all(r.to_canonical() == line for r, line in zip(recs, lines))
    assert b'"source"' not in b"".join(lines)
    canonical.loads(lines[0])


def test_13_world_run_verifies_under_14(tmp_path):
    rep = verify(_copy(tmp_path), log=lambda s: None)
    assert rep.ok and rep.exit == 0, rep
    assert rep.first_bad is None
