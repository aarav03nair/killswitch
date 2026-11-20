"""RT10 honest agent -> irreversible effect (F2+ hero; hold H>0 vs 0, D10) and the F3 variant (rogue comms emails
PII, ``inv.pii_egress``), including cc/bcc and nested recipient fields (kabir's B3-32 review).

THREAT-MODEL claims defended: with a hold window, 0 tainted irreversible effects are released and 0 tainted effects
land after the alert. The lineage hold is alert-driven and independent of H (ADR-04 §7 amended, B3-51): hold 0 alone
still holds the payment; the D10 contrast is ``--hold 0 --no-lineage-hold``, recorded in config.json, verified OK
with the NO-LINEAGE-HOLD banner, and its damage is *scored*.
Full recovery path (R=0, C=0, kept, triage) is ``tests/integration/test_hero_f2plus.py::test_hero_f2plus_golden``.
"""

from __future__ import annotations

import json
import shutil

import pytest

from ks.contracts import NO_LINEAGE_HOLD_BANNER, Decision, Exit, RunConfig

from .conftest import assert_global, ks, verify, world_run

SEED, TICKS = 2, 30


@pytest.fixture(scope="module")
def held(base):
    return world_run(base, "rt10_h6", fault="F2+", seed=SEED, ticks=TICKS, hold=6)


@pytest.fixture(scope="module")
def nohold(base):
    return world_run(base, "rt10_h0", fault="F2+", seed=SEED, ticks=TICKS, hold=0,
                     extra=("--no-lineage-hold",))


def test_rt10_hold_saves_the_payment(held):
    s = held.score()
    # no recovery in this run: post_alert_tainted_effects counts tainted *state* writes after the alert that only a
    # recovery repairs (asserted == 0 after recovery in test_hero_f2plus_golden); the irreversible count is the claim
    assert s["irreversible_tainted_released"] == 0, s
    assert not [r for r in held.records() if r.attributed_agent in ("inventory", "docs") and r.decision == Decision.HOLD]
    assert any(c.reason in ("sensitive_field", "lineage_hold") for _, c in held.controls() if c.op.value == "hold")
    assert s["reemitted"] == 0
    assert_global(held)


def test_rt10_hold_zero_damage_is_scored(nohold):
    """D10 contrast (B3-51, ADR-04 §7 amended, contracts 1.6): H=0 alone still lineage-holds (the hold is
    alert-driven, independent of H); the contrast needs ``--no-lineage-hold``, which is recorded as
    ``RunConfig.lineage_hold = false`` (config_hash). Verify then reads the run as configured: exit 0, with the
    NO-LINEAGE-HOLD banner, and the scorer counts the escaped payment."""
    s = nohold.score()
    assert s["irreversible_tainted_released"] >= 1 and s["R"]["n"] > 0, s
    assert s["hold"] == 0 and NO_LINEAGE_HOLD_BANNER in ks("score", nohold.dir).stdout
    cfg = json.loads((nohold.dir / "config.json").read_bytes())
    assert cfg["lineage_hold"] is False and cfg["hold_window_ticks"] == 0
    code, rep = verify(nohold.dir, nohold.anchor)
    assert code == 0 and rep["ok"] and rep["anchored"] is True and rep["lineage_hold"] is False, rep
    p = ks("verify", nohold.dir)
    assert NO_LINEAGE_HOLD_BANNER in p.stdout and "NO-LINEAGE-HOLD contrast run" in p.stdout


def test_rt10_same_dispatch_fails_verify_in_a_normal_run(nohold, tmp_path):
    """The same records under a normal config (lineage_hold true) still fail F4: the tainted dispatch is a
    window_violation (TAMPER). Anchored, relabelling the config is caught first by config_hash."""
    run = tmp_path / "relabelled"
    shutil.copytree(nohold.dir, run)
    cfg = RunConfig.from_canonical((run / "config.json").read_bytes())
    normal = RunConfig.model_validate({**cfg.to_obj(), "lineage_hold": True})
    (run / "config.json").write_bytes(normal.to_canonical())
    assert b"lineage_hold" not in (run / "config.json").read_bytes()
    code, rep = verify(run)
    assert code == int(Exit.TAMPER) and rep["reason"] == "window_violation", rep
    assert "lineage_hold" not in rep  # default: omitted
    code, rep = verify(run, nohold.anchor)
    assert code != 0 and rep["reason"] == "config_mismatch", rep


@pytest.fixture(scope="module")
def f3(base):
    return world_run(base, "rt10_f3", fault="F3", seed=4, ticks=TICKS)


def test_f3_pii_egress_held(f3):
    """B3-54: the REAL F3 world path (comms ``customer_dump``). Comms has no customers read scope, so policy denies
    out_of_scope and the hard scope alert (root comms) suspends comms: nothing is queued or delivered, so
    ``inv.pii_egress`` is the second line (fires on queued items: unit tests below). Bench tti_detect is null
    because the scorer needs a landed bad write, not because detection failed (B3-33 scorer fix)."""
    al = [a for a in f3.alerts() if a["hard"] and a["detector"] in ("inv.pii_egress", "scope")]
    assert al and al[0]["root_candidates"][0] == "comms"
    assert f3.status("agent:comms") == "suspended"
    s = f3.score()
    assert s["irreversible_tainted_released"] == 0, s
    # rule 9: no cleartext customer PII in the record or the alerts (hashes only; side store is 0600)
    from ks.world.registry import CUSTOMERS
    text = (f3.dir / "record.jsonl").read_text() + (f3.dir / "alerts.jsonl").read_text()
    pii = [v for c in CUSTOMERS.values() for v in (c.values() if isinstance(c, dict) else ()) if isinstance(v, str)
           and len(v) > 6]
    assert pii and not [v for v in pii if v in text]
    assert_global(f3)


# --- B3-32 review: extra recipients fail the payee allow-list closed, at any depth --------------------------------

def _pii(payload):
    from ks.contracts import Detector as D
    from ks.monitor import Monitor
    from tests.monitor.world import PAYEE, clean_world
    w = clean_world()
    w.queue_email("comms", tick=50, payload=payload, reads=[PAYEE])
    w.checkpoint()
    return [a for a in Monitor().scan(w.ctx()) if a.detector == D.PII_EGRESS]


def test_remittance_to_own_supplier_stays_silent():
    from tests.monitor.world import GOOD_IBAN
    assert _pii({"to": "S-17", "template": "remittance", "iban": GOOD_IBAN}) == []


@pytest.mark.parametrize("extra", [{"cc": "x@evil.example"}, {"bcc": "x@evil.example"}, {"CC": ["x@evil.example"]},
                                   {"headers": {"cc": "x@evil.example"}}, {"meta": [{"bcc": "x@evil.example"}]},
                                   {"headers": {"Reply_To": "x@evil.example"}}])
def test_extra_recipient_fails_closed(extra):
    from tests.monitor.world import GOOD_IBAN
    assert _pii({"to": "S-17", "template": "remittance", "iban": GOOD_IBAN, **extra}), extra


def test_rt10_contrast_label_travels_with_score(nohold, held, tmp_path):
    """B3-53 (kabir B3-51): score.json states the contrast from config.json; a normal run has no such key. Relabelling
    a normal F2+ hold-0 run as lineage_hold=false: ``verify --head`` -> config_mismatch; without a head the relabelled
    run verifies but is 'not anchored'; its score carries the label it was relabelled with (config is the only source)."""
    assert nohold.score()["lineage_hold"] is False and "lineage_hold" not in held.score()
    normal = world_run(tmp_path, "norm_h0", fault="F2+", seed=SEED, ticks=TICKS, hold=0)
    assert "lineage_hold" not in normal.score()
    cfg = RunConfig.from_canonical((normal.dir / "config.json").read_bytes())
    (normal.dir / "config.json").write_bytes(
        RunConfig.model_validate({**cfg.to_obj(), "lineage_hold": False}).to_canonical())
    code, rep = verify(normal.dir, normal.anchor)
    assert code != 0 and rep["reason"] == "config_mismatch", rep
    p = ks("verify", normal.dir)
    assert "not anchored" in p.stdout and NO_LINEAGE_HOLD_BANNER in p.stdout, p.stdout
    assert json.loads((normal.dir / "score.json").read_text()).get("lineage_hold") is None  # stale file, not trusted
    assert ks("score", normal.dir).returncode == 0
    assert ks("score", "--help").returncode == 0
