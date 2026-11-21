"""B3-33: ks.bench aggregation (ADR-06-metrics §4) and the baselines scored by the same scorer on the real path."""

from __future__ import annotations

from fractions import Fraction

import pytest

from ks.bench.agg import aggregate, flatten, rank
from ks.bench.runner import run_cell
from ks.score import SCORE_KEYS


def test_rank_is_nearest_rank_lower():
    assert (rank(20, "median"), rank(20, "p95"), rank(20, "max"), rank(20, "min")) == (9, 18, 19, 0)
    assert rank(3, "median") == 1


def test_aggregate_null_is_infinity_and_ratios_are_rationals():
    sc = [{"ttc": None, "R": {"n": 1, "d": 2}}, {"ttc": 3, "R": {"n": 1, "d": 3}}, {"ttc": 1, "R": {"n": 0, "d": 0}}]
    a = aggregate(sc)
    assert (a["ttc"]["min"], a["ttc"]["median"], a["ttc"]["max"], a["ttc"]["k"], a["ttc"]["n"]) == ("1", "3", "null", 2, 3)
    assert (a["R"]["min"], a["R"]["median"], a["R"]["max"]) == ("0", "1/3", "1/2")
    assert flatten({"fp_cost": {"operator_unholds": {"total": 9}}})["fp_cost.operator_unholds.total"] == Fraction(9)
    assert flatten({"collateral_stall": {"unavailable": "x"}})["collateral_stall"] is None


@pytest.fixture(scope="module")
def cells(tmp_path_factory):
    d = tmp_path_factory.mktemp("bench")
    cache: dict = {}
    return {b: run_cell("F2+", 2, 6, b, 40, d / b, star_cache=cache) for b in ("system", "snapshot", "revert_culprit_only")}


def test_baselines_scored_by_same_scorer(cells):
    for b, s in cells.items():
        # S4-22: a native (degraded) cell also carries run_validity (VOID); the metric keys are unchanged
        assert tuple(k for k in s if k != "run_validity") == SCORE_KEYS and s["baseline"] == b
    assert cells["snapshot"]["baseline_oracle_assisted"] and cells["revert_culprit_only"]["baseline_oracle_assisted"]
    assert not cells["system"]["baseline_oracle_assisted"]
    same = ("seed", "fault", "hold", "t_inject", "t_alert", "t_contain", "tti_detect", "ttc", "t_rec")
    assert all([cells[b][k] for b in cells] == [cells["system"][k]] * 3 for k in same)  # same run up to recovery
    assert cells["system"]["R"]["n"] == 0
    assert cells["revert_culprit_only"]["R"]["n"] > 0  # reader work left derived from the bad IBAN
    assert cells["snapshot"]["C"]["n"] > 0  # snapshot discards honest work
    assert cells["system"]["fp_cost"]["operator_unholds"]["total"] == 9  # D-17: say how many were released


def test_bench_never_runs_a_contrast_cell(cells):
    """B3-53: the bench argv has no --no-lineage-hold, and no cell's score.json carries the contrast label."""
    import inspect
    from ks.bench import runner
    assert "no-lineage-hold" not in inspect.getsource(runner.run_cell).split("def _star")[0].split('"--hold"')[0]
    assert all("lineage_hold" not in s for s in cells.values())


def test_table_marks_contrast_cells():
    from ks.bench.agg import render_table
    base = {"seed": 1, "R": {"n": 0, "d": 1}}
    t = render_table("x", {"system": [base], "contrast": [{**base, "lineage_hold": False}]}, metrics=("R",))
    assert "contrast [CONTRAST: NO-LINEAGE-HOLD]" in t and "system |" in t and "system [" not in t


def test_contrast_cell_is_labelled_and_separate(tmp_path):
    """B3-53 / D10: run_cell(no_lineage_hold=True) at H=0 writes lineage_hold=false; bench keeps it out of ``cells``."""
    s = run_cell("F2+", 2, 0, "system", 40, tmp_path / "c", star_cache={}, no_lineage_hold=True)
    assert s["lineage_hold"] is False and s["hold"] == 0


@pytest.mark.parametrize("ticks,other", [(40, 120), (120, 40)])
def test_header_names_the_runs_real_tick_count(tmp_path, monkeypatch, ticks, other):
    """S4-14: the header line used a hard-coded T=120; it must say this run's T and warn against the other one."""
    import ks.bench.runner as r
    def fake(f, seed, h, b, t, d, **k):
        d.mkdir(parents=True, exist_ok=True)
        (d / "score.json").write_text("{}")
        return {"seed": seed, "R": {"n": 0, "d": 1}}
    monkeypatch.setattr(r, "run_cell", fake)
    r.bench([1], ["F2+"], [6], ["system"], ticks, tmp_path / "o")
    md = (tmp_path / "o" / "bench.md").read_text()
    assert f"at **T={ticks}**; do not compare ratio metrics with T={other}." in md
    assert md.startswith(f"# ks bench: T={ticks} ")


def test_keep_runs_flag_controls_scratch_dirs(tmp_path, monkeypatch):
    """S4-36: --keep-runs leaves the per-cell run dirs under out/_runs; without it they are removed."""
    import ks.bench.runner as r
    def fake(f, seed, h, b, t, d, **k):
        d.mkdir(parents=True, exist_ok=True)
        (d / "score.json").write_text("{}")
        return {"seed": seed, "R": {"n": 0, "d": 1}}
    monkeypatch.setattr(r, "run_cell", fake)
    r.bench([1], ["F2+"], [6], ["system"], 40, tmp_path / "keep", keep_runs=True)
    r.bench([1], ["F2+"], [6], ["system"], 40, tmp_path / "drop")
    assert any((tmp_path / "keep" / "_runs").iterdir())
    assert not (tmp_path / "drop" / "_runs").exists()


def test_late_inject_f2p_seed2_t120_has_no_i2_artefact(tmp_path):
    """S4-37 / A6: S* applies p.i2_approval itself (no approver in the bench): the honest docs.purge held in the real
    run is not executed by S* either, so a late t_rec (56) gives R=0 and collateral_stall=0 (was 1/6 and 1/1123)."""
    s = run_cell("F2+", 2, 6, "system", 120, tmp_path / "c", star_cache={})
    assert s["t_rec"] == 56 and s["R"]["n"] == 0 and s["collateral_stall"]["n"] == 0


def test_real_only_dispatched_payment_after_t_rec_is_an_irreversible_escape(tmp_path):
    """S4-37 / A6 (kabir's fixture): a culprit payment dispatched after t_rec that exists only in the real run (S* never
    executes it) is an escape: irreversible_tainted_released and post_alert >= 1, not honest C / collateral_stall."""
    from ks.bench.runner import _star
    from ks.inject import make_spec
    from ks.oracle.realrun import real_ledger
    from ks.score import score_run, suspend_tick_of
    d = tmp_path / "c"
    s = run_cell("F2+", 2, 6, "system", 40, d, star_cache={})
    spec = make_spec("f2plus", 2, ticks=40)
    star = _star(spec, tmp_path / "x", suspend_tick_of(d, spec.culprit), 6)
    led = real_ledger(d)
    base = score_run(d, spec, star, hold=6)
    assert base["irreversible_tainted_released"] == 0 and base["post_alert_tainted_effects"] == 0
    proto = next(e for e in led if e["kind"] == "payment")
    for who in (spec.culprit, "docs"):
        esc = {**proto, "key": "outbox:tainted-late-payment", "tick": s["t_rec"] + 1, "seq": None, "state": "dispatched",
               "agent": who, "value_hash": "ff" * 32}
        s2 = score_run(d, spec, star, hold=6, run_ledger=led + [esc])
        assert s2["irreversible_tainted_released"] >= 1 and s2["post_alert_tainted_effects"] >= 1
        assert s2["clean"] is False
        assert s2["C"] == base["C"] and s2["collateral_stall"] == base["collateral_stall"]


def test_real_only_dispatched_purge_is_an_irreversible_escape(tmp_path):
    """S4-37 / A6 (kabir attack2): a docs.purge (I2) dispatched only in the real run after t_rec deletes data and cannot
    be undone: it counts in irreversible_tainted_released and post_alert, not in C / collateral_stall. No new key."""
    from ks.bench.runner import _star
    from ks.inject import make_spec
    from ks.oracle.realrun import real_ledger
    from ks.score import score_run, suspend_tick_of
    d = tmp_path / "c"
    s = run_cell("F2+", 2, 6, "system", 40, d, star_cache={})
    spec = make_spec("f2plus", 2, ticks=40)
    star = _star(spec, tmp_path / "x", suspend_tick_of(d, spec.culprit), 6)
    led = real_ledger(d)
    base = score_run(d, spec, star, hold=6)
    proto = next(e for e in led if e["kind"] == "payment")
    esc = {**proto, "kind": "purge", "key": "outbox:late-purge", "tick": s["t_rec"] + 1, "seq": None,
           "state": "dispatched", "agent": spec.culprit, "value_hash": "cc" * 32}
    s2 = score_run(d, spec, star, hold=6, run_ledger=led + [esc])
    assert s2["irreversible_tainted_released"] >= 1 and s2["post_alert_tainted_effects"] >= 1 and s2["clean"] is False
    assert s2["C"] == base["C"] and s2["collateral_stall"] == base["collateral_stall"] and list(s2) == list(base)


def test_late_wrong_payload_on_s_star_key_is_an_escape_but_matching_resend_is_not(tmp_path):
    """S4-38 / A6 addendum (kabir): a dispatched effect after t_rec on a key S* also has, outside B, with a payload that
    differs from S*, is an escape (irreversible, post_alert; not C / collateral_stall). The same re-send with S*'s
    payload (honest re-execution after recovery) is not."""
    from ks.bench.runner import _star
    from ks.inject import make_spec
    from ks.oracle.ledger import fold
    from ks.oracle.realrun import real_ledger
    from ks.score import score_run, suspend_tick_of
    d = tmp_path / "c"
    s = run_cell("F2+", 2, 6, "system", 40, d, star_cache={})
    spec = make_spec("f2plus", 2, ticks=40)
    star = _star(spec, tmp_path / "x", suspend_tick_of(d, spec.culprit), 6)
    led = real_ledger(d)
    base = score_run(d, spec, star, hold=6)
    sf = fold(star)
    from ks.oracle.ledger import b_set
    b = b_set(led, star, s["t_rec"] - 1)
    rf = fold(led)
    shared = next(k for k, e in sf.items() if e["kind"] == "payment" and e["state"] == "dispatched" and k not in b
                  and rf.get(k, {}).get("state") == "dispatched")
    mk = lambda vh: {**sf[shared], "key": shared, "tick": max(e["tick"] for e in led) + 1, "seq": None,  # noqa: E731
                     "state": "dispatched",
                     "agent": "crm", "value_hash": vh}
    ok = score_run(d, spec, star, hold=6, run_ledger=led + [mk(sf[shared]["value_hash"])])
    assert ok["irreversible_tainted_released"] == base["irreversible_tainted_released"] and ok["clean"] == base["clean"]
    bad = score_run(d, spec, star, hold=6, run_ledger=led + [mk("dd" * 32)])
    assert bad["irreversible_tainted_released"] >= 1 and bad["post_alert_tainted_effects"] >= 1 and bad["clean"] is False
    assert bad["C"]["n"] == base["C"]["n"] == 0 and bad["C"]["d"] == base["C"]["d"] - 1  # leaves G, not honest loss
    assert bad["collateral_stall"]["n"] == base["collateral_stall"]["n"] == 0 and list(bad) == list(base)
    assert bad["collateral_stall"]["d"] == base["collateral_stall"]["d"] - 1


def test_wrong_dispatch_is_not_hidden_by_later_matching_resend_or_cancel(tmp_path):
    """S4-38 (kabir attack3): a wrong dispatch on an S* key stays an escape when a later matching re-send or a cancelled
    row follows it; the later row cannot undo the dispatch. A matching re-send alone stays clean."""
    from ks.bench.runner import _star
    from ks.inject import make_spec
    from ks.oracle.ledger import b_set, fold
    from ks.oracle.realrun import real_ledger
    from ks.score import score_run, suspend_tick_of
    d = tmp_path / "c"
    s = run_cell("F2+", 2, 6, "system", 40, d, star_cache={})
    spec = make_spec("f2plus", 2, ticks=40)
    star = _star(spec, tmp_path / "x", suspend_tick_of(d, spec.culprit), 6)
    led = real_ledger(d)
    base = score_run(d, spec, star, hold=6)
    sf, rf, b = fold(star), fold(led), b_set(led, star, s["t_rec"] - 1)
    k = next(k for k, e in sf.items() if e["kind"] == "payment" and e["state"] == "dispatched" and k not in b
             and rf.get(k, {}).get("state") == "dispatched")
    T = max(e["tick"] for e in led)
    mk = lambda vh, t, st="dispatched": {**sf[k], "key": k, "tick": t, "seq": None, "state": st,  # noqa: E731
                                         "agent": "crm", "value_hash": vh}
    good = sf[k]["value_hash"]
    ok = score_run(d, spec, star, hold=6, run_ledger=led + [mk(good, T + 1)])
    assert ok["irreversible_tainted_released"] == base["irreversible_tainted_released"]
    assert ok["post_alert_tainted_effects"] == base["post_alert_tainted_effects"]
    for extra in ([mk("dd" * 32, T + 1), mk(good, T + 2)], [mk("dd" * 32, T + 1), mk("dd" * 32, T + 2, "cancelled")]):
        r = score_run(d, spec, star, hold=6, run_ledger=led + extra)
        assert r["irreversible_tainted_released"] >= base["irreversible_tainted_released"] + 1
        assert r["post_alert_tainted_effects"] >= 1 and r["clean"] is False
        assert r["C"]["n"] == 0 and r["collateral_stall"]["n"] == 0


def _escape_fixture(tmp_path):
    from ks.bench.runner import _star
    from ks.inject import make_spec
    from ks.oracle.realrun import real_ledger
    from ks.score import score_run, suspend_tick_of
    d = tmp_path / "c"
    run_cell("F2+", 2, 6, "system", 40, d, star_cache={})
    spec = make_spec("f2plus", 2, ticks=40)
    star = _star(spec, tmp_path / "x", suspend_tick_of(d, spec.culprit), 6)
    led = real_ledger(d)
    return d, spec, star, led, score_run(d, spec, star, hold=6)


def test_dispatch_on_key_s_star_cancelled_or_queued_is_an_escape(tmp_path):
    """S4-38 round 3 (kabir): a real dispatch whose key S* cancelled, or left queued (never dispatched), is an escape
    unless S* has a dispatched entry with the same value_hash; scored irreversible/post_alert, not C / collateral_stall."""
    from ks.oracle.ledger import fold
    from ks.score import score_run
    d, spec, star, led, base = _escape_fixture(tmp_path)
    sf = fold(star)
    T = max(e["tick"] for e in led)
    proto = next(e for e in led if e["kind"] == "payment")
    for i, st in enumerate(("cancelled", "queued")):
        k = f"outbox:s-star-{st}"
        star2 = star + [{**proto, "key": k, "tick": 1, "seq": None, "state": st, "value_hash": "aa" * 32}]
        assert k not in sf
        esc = {**proto, "key": k, "tick": T + 1, "seq": None, "state": "dispatched", "agent": "crm",
               "value_hash": "aa" * 32}
        r = score_run(d, spec, star2, hold=6, run_ledger=led + [esc])
        assert r["irreversible_tainted_released"] == base["irreversible_tainted_released"] + 1, st
        assert r["post_alert_tainted_effects"] == base["post_alert_tainted_effects"] + 1 and r["clean"] is False, st
        assert r["C"]["n"] == 0 and r["collateral_stall"]["n"] == 0, st
