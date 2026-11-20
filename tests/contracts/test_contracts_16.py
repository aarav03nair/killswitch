"""Contracts 1.6.0 (B3-51, kabir's ruling; ADR-04 §7 amended): ``RunConfig.lineage_hold`` and its echo
``VerifyReport.lineage_hold``, additive only.

``lineage_hold = False`` marks the D10 NO-LINEAGE-HOLD contrast run (``ks run --hold 0 --no-lineage-hold``) in
config.json and so in config_hash. It is omitted from the canonical bytes at the default ``True`` (the additive
rule), so 1.3, 1.4 and 1.5 runs keep their bytes and still verify. ``fixtures/run-1.5-world-s0`` was built from the
1.5.0 tree (B3-51 work, before this bump) with ``ks run --scenario world --ticks 8 --seed 0 --run-id world-s0``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ks import contracts as C
from ks.contracts import NO_LINEAGE_HOLD_BANNER, NonCanonicalError, RunConfig, VerifyReport
from ks.verify import verify

from samples import samples

SRC = Path(C.__file__).resolve().parent
FIX = Path(__file__).with_name("fixtures")


def test_version_and_readme():
    assert tuple(map(int, C.CONTRACTS_VERSION.split("."))) >= (1, 6, 0)
    readme = (SRC / "README.md").read_text(encoding="utf-8")
    assert "### 1.6.0" in readme and "`lineage_hold`" in readme
    assert "NO-LINEAGE-HOLD contrast run" in NO_LINEAGE_HOLD_BANNER


def _cfg(**kw) -> RunConfig:
    base = samples()["run_config"].to_obj()
    return RunConfig.model_validate({**base, "hold_window_ticks": 0, **kw})


def test_default_is_omitted_and_hash_unchanged():
    c = _cfg()
    assert c.lineage_hold is True and "lineage_hold" not in c.to_obj()
    assert b"lineage_hold" not in c.to_canonical()
    # explicit default in the bytes is not canonical (strict parse stays strict)
    raw = json.loads(c.to_canonical())
    raw["lineage_hold"] = True
    with pytest.raises(NonCanonicalError):
        RunConfig.from_canonical(C.canonical.dumps(raw))


def test_contrast_is_serialized_and_moves_config_hash():
    c, x = _cfg(), _cfg(lineage_hold=False)
    assert x.to_obj()["lineage_hold"] is False
    assert RunConfig.from_canonical(x.to_canonical()) == x
    assert x.content_hash() != c.content_hash()  # the record cannot hide that it was a contrast run
    assert x.tcb_view().lineage_hold is False      # not scorer-only: the gateway must see it


def test_contrast_needs_hold_zero():
    with pytest.raises(ValueError, match="needs hold_window_ticks == 0"):
        _cfg(hold_window_ticks=6, lineage_hold=False)
    assert _cfg(hold_window_ticks=6).lineage_hold is True


def test_verify_report_echo():
    base = dict(ok=True, exit=0, first_bad=None, reason="ok", last_witnessed_seq=3, anchored=False,
                unanchored_reason="no_anchor", isolation="degraded")
    r = VerifyReport(**base)
    assert "lineage_hold" not in r.to_obj()
    x = VerifyReport(**base, lineage_hold=False)
    assert x.to_obj()["lineage_hold"] is False and VerifyReport.from_canonical(x.to_canonical()) == x


def _copy(src: Path, tmp_path: Path) -> Path:
    run = tmp_path / src.name
    shutil.copytree(src, run)
    for d in ("baselines", "oracle", "plans"):
        (run / d).mkdir(exist_ok=True)
    for p in run.rglob("*"):
        p.chmod(0o700 if p.is_dir() else 0o600)
    return run


@pytest.mark.parametrize("name,ver", [("run-1.3-world-s0", "1.3.0"), ("run-1.4-world-s0", "1.4.0"),
                                      ("run-1.5-world-s0", "1.5.0")])
def test_old_runs_verify_under_16(name, ver, tmp_path):
    cfg = json.loads((FIX / name / "config.json").read_bytes())
    assert cfg["contracts_version"] == ver and "lineage_hold" not in cfg
    rep = verify(_copy(FIX / name, tmp_path), log=lambda s: None)
    assert rep.ok and rep.exit == 0 and rep.lineage_hold is True, rep
    assert "lineage_hold" not in rep.to_obj()
