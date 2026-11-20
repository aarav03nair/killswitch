"""B3-12: ks.runtime.RunOptions replaces CLI signature introspection."""
import dataclasses

import pytest

from ks.runtime import RunOptions, run
from ks.runtime.options import SERVED


def test_frozen_and_default_requests_nothing():
    o = RunOptions()
    assert o.requested() == () and o.unserved() == ()
    with pytest.raises(dataclasses.FrozenInstanceError):
        o.fault = "F2+"  # type: ignore[misc]


def test_field_names_are_the_contract():
    assert [f.name for f in dataclasses.fields(RunOptions)] == [
        "fault", "culprit", "hold", "pause_at", "step", "rogue", "slot", "decisions", "decisions_head", "monitor",
        "pause_on_alert", "no_lineage_hold", "with_baselines"]


def test_hold_zero_is_requested_and_pause_at_is_a_tuple():
    o = RunOptions(hold=0, pause_at=[3, 5])
    assert o.requested() == ("hold", "pause_at") and o.pause_at == (3, 5)


@pytest.mark.parametrize("kw", [dict(pause_at=(1,), step=True), dict(rogue="r.py", fault="F2+"), dict(slot="docs"),
                                dict(culprit="crm"), dict(hold=-1), dict(hold=True), dict(pause_at=(-1,)),
                                dict(decisions_head="{}"), dict(pause_on_alert=True)])
def test_invalid_combinations_raise_value_error(kw):
    with pytest.raises(ValueError):
        RunOptions(**kw)


@pytest.mark.parametrize("kw", [dict(with_baselines=True)])
def test_unserved_fields_raise_before_anything_is_created(tmp_path, kw):
    assert not set(RunOptions(**kw).requested()) & SERVED
    out = tmp_path / "run"
    with pytest.raises(NotImplementedError, match="does not serve"):
        run(agents=1, ticks=1, seed=1, key_mode="fresh", out=out, options=RunOptions(**kw))
    assert not out.exists()


def test_options_must_be_run_options(tmp_path):
    with pytest.raises(TypeError):
        run(agents=1, ticks=1, seed=1, key_mode="fresh", out=tmp_path / "run", options={"fault": "F2+"})


def test_decisions_served_and_refused_before_anything_is_created(tmp_path):
    """B3-30: decisions is served; a source with no anchor is refused (ValueError) before the run dir exists."""
    assert {"decisions", "decisions_head"} <= SERVED
    out = tmp_path / "run"
    with pytest.raises(ValueError, match="no_anchor"):
        run(agents=1, ticks=1, seed=1, key_mode="fresh", out=out, options=RunOptions(decisions=str(tmp_path)))
    assert not out.exists()


def test_fault_on_the_skeleton_is_refused_before_anything_is_created(tmp_path):
    """B3-27: fault/culprit/hold are served, for the world scenario only."""
    assert {"fault", "culprit", "hold", "pause_on_alert"} <= SERVED
    out = tmp_path / "run"
    with pytest.raises(ValueError, match="world"):
        run(agents=1, ticks=4, seed=1, key_mode="fresh", out=out, options=RunOptions(fault="F2+"))
    assert not out.exists()
    with pytest.raises(ValueError, match="committed by"):
        run(agents=None, ticks=40, seed=1, key_mode="fresh", out=out, scenario="world",
            options=RunOptions(fault="F2+", culprit="docs"))
    assert not out.exists()


def test_config_fault_ids():
    from ks.runtime.run import _config_fault
    assert [_config_fault(f) for f in ("f2plus", "f2plus_x", "f2plus_c", "f1")] == ["F2+", "F2+x", "F2+c", "F1"]


def test_rogue_served_and_refused_before_anything_is_created(tmp_path):
    """B3-35: --rogue is served for the world only, fresh keys only, a known slot only; refusals create nothing."""
    assert {"rogue", "slot"} <= SERVED
    f = tmp_path / "r.py"
    f.write_text("def on_tick(ctx, t):\n    pass\n")
    for kw, scen in ((dict(rogue=str(f), slot="docs"), "skeleton"), (dict(rogue=str(f), slot="nobody"), "world")):
        out = tmp_path / f"run-{scen}"
        with pytest.raises(ValueError):
            run(agents=None, ticks=1, seed=1, key_mode="fresh", out=out, scenario=scen, options=RunOptions(**kw))
        assert not out.exists()
