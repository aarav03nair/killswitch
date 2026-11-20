"""Contracts 1.5.0 (B3-47, kabir's B3-20 ruling): verify reason ``replay_mismatch`` (DIVERGED, not TAMPER), additive only.

A decisions-replay mismatch is not a broken hash chain, so reporting it as ``hash_mismatch`` misleads the reader.
Additivity: no field changed, so 1.3 and 1.4 runs must still verify. ``fixtures/run-1.4-world-s0`` was built from
commit 894b5f5 (contracts 1.4.0) with ``ks run --scenario world --ticks 8 --seed 0``; it carries ``source: "view"``
read entries, the 1.4 non-default field. (The 1.3 fixture is covered by ``test_additive_13_run.py``.)
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ks import contracts as C
from ks.contracts import VERIFY_REASONS, Exit, Record, VerifyReport
from ks.verify import verify

SRC = Path(C.__file__).resolve().parent
FIXTURE_14 = Path(__file__).with_name("fixtures") / "run-1.4-world-s0"


def test_version_and_readme():
    assert tuple(map(int, C.CONTRACTS_VERSION.split("."))) >= (1, 5, 0)
    readme = (SRC / "README.md").read_text(encoding="utf-8")
    assert "### 1.5.0" in readme and "`replay_mismatch`" in readme


def test_replay_mismatch_is_diverged_not_tamper():
    assert VERIFY_REASONS["replay_mismatch"] is Exit.DIVERGED
    base = dict(ok=False, reason="replay_mismatch", first_bad=3, last_witnessed_seq=2, anchored=False,
                unanchored_reason="no_anchor")
    rep = VerifyReport(exit=int(Exit.DIVERGED), **base)
    assert VerifyReport.from_canonical(rep.to_canonical()) == rep
    for wrong in (Exit.TAMPER, Exit.WITNESS):
        with pytest.raises(ValueError, match="implies exit DIVERGED"):
            VerifyReport(exit=int(wrong), **base)


def test_hash_mismatch_unchanged():
    assert VERIFY_REASONS["hash_mismatch"] is Exit.TAMPER


def _copy(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    shutil.copytree(FIXTURE_14, run)
    for d in ("baselines", "oracle", "plans"):
        (run / d).mkdir(exist_ok=True)
    for p in run.rglob("*"):
        p.chmod(0o700 if p.is_dir() else 0o600)
    return run


def test_fixture_is_a_14_run_with_view_reads():
    cfg = json.loads((FIXTURE_14 / "config.json").read_bytes())
    assert cfg["contracts_version"] == "1.4.0" and C.CONTRACTS_VERSION != "1.4.0"
    lines = (FIXTURE_14 / "record.jsonl").read_bytes().splitlines()
    recs = [Record.from_canonical(line) for line in lines]  # strict parse: 1.4 bytes are still canonical
    assert all(r.to_canonical() == line for r, line in zip(recs, lines))
    assert sum(1 for r in recs for e in r.read_set if e.source == "view") >= 5


def test_14_world_run_verifies_under_15(tmp_path):
    rep = verify(_copy(tmp_path), log=lambda s: None)
    assert rep.ok and rep.exit == 0, rep
    assert rep.first_bad is None
