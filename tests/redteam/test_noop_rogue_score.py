"""B3-50 regression: a rogue that never sends scores no bad effects (S* runs the slot as a no-op from tick 0)."""

from __future__ import annotations

import pytest

from .conftest import world_run

NOOP = "def on_tick(ctx, t):\n    pass\n"


@pytest.mark.parametrize("slot", ["docs", "crm"])
def test_noop_rogue_scores_no_bad_effects(base, slot):
    run = world_run(base, f"noop_{slot}", rogue=NOOP, slot=slot, seed=2, ticks=30)
    s = run.score()
    assert s["b_empty"] is True and s["R"]["d"] == 0 and s["false_accusations"] == 0, s
