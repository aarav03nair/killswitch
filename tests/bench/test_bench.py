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
        assert tuple(s) == SCORE_KEYS and s["baseline"] == b
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
