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
        "with_baselines"]


def test_hold_zero_is_requested_and_pause_at_is_a_tuple():
    o = RunOptions(hold=0, pause_at=[3, 5])
    assert o.requested() == ("hold", "pause_at") and o.pause_at == (3, 5)


@pytest.mark.parametrize("kw", [dict(pause_at=(1,), step=True), dict(rogue="r.py", fault="F2+"), dict(slot="docs"),
                                dict(culprit="crm"), dict(hold=-1), dict(hold=True), dict(pause_at=(-1,)),
                                dict(decisions_head="{}")])
def test_invalid_combinations_raise_value_error(kw):
    with pytest.raises(ValueError):
        RunOptions(**kw)


@pytest.mark.parametrize("kw", [dict(fault="F2+", culprit="crm"), dict(hold=0),
                                dict(rogue="r.py", slot="docs"), dict(with_baselines=True)])
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
