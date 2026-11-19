"""B3-21 on the real ks.world F2+ run (tests/recovery/world.py, real outbox objects): the B2 plan shape holds."""

from __future__ import annotations

import pytest

from ks.recovery import plan_recovery

from . import world as W


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    return W.run(tmp_path_factory.mktemp("w") / "s.db")


def _plan(w):
    return plan_recovery(w.records, w.taint, alert_id="a-000001", state=w.store).plan


def test_world_hero_plan_b2(world):
    p = _plan(world)
    assert {s.obj for s in p.steps if s.op == "restore"} == {W.IBAN, W.S22}
    assert all(s.expect.ver == 2 and s.to.ver == 1 for s in p.steps if s.op == "restore")
    assert [s for s in p.steps if s.op in ("replan", "cancel_outbox")] == []
    # open (test_rerun.test_hero_zero_flags): view-tainted class-C billing.issue_credit has no compensator
    assert [(s.reason, s.action.action_id) for s in p.steps if s.op == "flag"] == [("no_compensator", f"billing-t{W.H + 4}")]
    rerun = {s.action.agent_id for s in p.steps if s.op == "rerun"}
    assert {"billing", "payments", "comms", "reporter"} <= rerun
    assert not rerun & {"triage", "inventory", "docs", "intake", "crm"}
    assert p.content_hash() == _plan(world).content_hash()


def test_world_outbox_without_state_fails_closed(world):
    """B3-23: outbox ids are real objects; without a readable object the planner flags, never assumes held."""
    p = plan_recovery(world.records, world.taint, alert_id="a-000001").plan
    fl = [s for s in p.steps if s.op == "flag"]
    assert fl and {s.reason for s in fl} == {"outbox_missing", "no_compensator"} and not [s for s in p.steps if s.op == "cancel_outbox"]
