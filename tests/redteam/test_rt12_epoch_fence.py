"""RT4/RT5/RT12 audit side (kabir's B3-49 attack cases, B3-35): a record the gateway should have refused, written
into the chain by a misbehaving gateway, fails ``ks verify`` (TAMPER, ``epoch_regression``, first_bad = that seq).

THREAT-MODEL claim defended: "tamper-evident up to the last witnessed head" also covers *admission* tampering:
an agent record admitted while its principal (or an act_chain ancestor) was suspended or revoked, or under an
epoch the Control fold does not give, is caught by ``verify``'s epoch fence, not only by the live gateway.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import samples as S  # noqa: E402
from test_contracts_13 import _seal  # noqa: E402

from ks.contracts import (CONTROL_TOOL, ActionClass, ActLink, Control, ControlOp, Decision, Envelope, Exit,  # noqa: E402
                          Reason, Record)
from tests.verify.test_record_rules import _verify  # noqa: E402


def _agent(seq, epoch, tick=None, agent="crm", decision=Decision.EXEC, chain=None):
    tick = 10 + seq if tick is None else tick
    kw = {} if chain is None else dict(act_chain=chain, parent_action_id=chain[-1].action_id if chain else None)
    env = S.envelope(agent=agent, action_id=f"{agent}-{seq}", epoch=epoch, expiry_tick=tick, nonce=f"{seq:032x}", **kw)
    reason = Reason.OK if decision == Decision.EXEC else Reason.SENSITIVE_FIELD
    return Record.seal(prev_hash="0" * 64, seq=seq, tick=tick, ts_us=1_000_000_000 + tick * 1000 + seq,
                       record_id=f"r-{seq:06d}", conn_id="c-3", envelope=env.header(), envelope_hash=env.content_hash(),
                       sig_ok=True, decision=decision, reason=reason, policy_rule=None,
                       action_class=ActionClass.R, read_set=(), write_set=(), outbox_ids=(), result_hash=None,
                       control=None, reexec_of=None)


def _ctl(seq, op, epoch, target="agent:crm", tick=None):
    tick = 10 + seq if tick is None else tick
    c = Control(control_id=f"k-{seq:06d}", op=ControlOp(op), target=target, epoch=epoch, alert_id=None,
                issued_by="ks.operator", auto=False, reason="operator")
    env = Envelope(agent_id="ks.operator", action_id=f"k-{seq:06d}", parent_action_id=None, act_chain=(),
                   tool=CONTROL_TOOL, args=c.to_obj(), nonce=f"{seq:032x}", expiry_tick=tick, epoch=0,
                   claimed_ts_us=None, claimed_seq=None, sig=None)
    env = env.with_sig(S.sign("ks.operator", env.signing_bytes()))
    return Record.seal(prev_hash="0" * 64, seq=seq, tick=tick, ts_us=1_000_000_000 + tick * 1000 + seq,
                       record_id=f"r-{seq:06d}", conn_id="c-0", envelope=env.header(), envelope_hash=env.content_hash(),
                       sig_ok=True, decision=Decision.EXEC, reason=Reason.OK, policy_rule=None,
                       action_class=ActionClass.R, read_set=(), write_set=(), outbox_ids=(), result_hash=None,
                       control=c, reexec_of=None)


def _bad(tmp_path, first_bad, *recs):
    rep = _verify(tmp_path, *recs)
    assert (rep.exit, rep.reason, rep.first_bad) == (Exit.TAMPER, "epoch_regression", first_bad), rep


def test_honest_suspend_release_resuspend_revoke_verifies(tmp_path):
    rep = _verify(tmp_path, _seal(), _agent(2, 0), _ctl(3, "suspend", 1), _ctl(4, "release", 2), _agent(5, 2),
                  _ctl(6, "suspend", 3), _ctl(7, "release", 4), _agent(8, 4))
    assert rep.reason == "ok", rep


@pytest.mark.parametrize("epoch", [0, 1], ids=["old_epoch", "new_epoch"])
def test_same_tick_after_suspend(tmp_path, epoch):
    _bad(tmp_path, 3, _seal(), _ctl(2, "suspend", 1, tick=13), _agent(3, epoch, tick=13))


@pytest.mark.parametrize("epoch", [2, 3], ids=["released_epoch", "suspend_epoch"])
def test_release_then_resuspend(tmp_path, epoch):
    _bad(tmp_path, 5, _seal(), _ctl(2, "suspend", 1), _ctl(3, "release", 2), _ctl(4, "suspend", 3), _agent(5, epoch))


@pytest.mark.parametrize("epoch", [0, 1], ids=["old_epoch", "revoke_epoch"])
def test_after_revoke(tmp_path, epoch):
    _bad(tmp_path, 3, _seal(), _ctl(2, "revoke", 1), _agent(3, epoch))


def test_future_epoch_without_controls(tmp_path):
    _bad(tmp_path, 2, _seal(), _agent(2, 5))


def test_future_epoch_after_release(tmp_path):
    _bad(tmp_path, 4, _seal(), _ctl(2, "suspend", 1), _ctl(3, "release", 2), _agent(4, 3))


def test_hold_decision_is_fenced(tmp_path):
    """kabir follow-up (1): a HOLD for a suspended principal is gateway misbehaviour too (steps 8-9 deny first)."""
    _bad(tmp_path, 3, _seal(), _ctl(2, "suspend", 1), _agent(3, 1, decision=Decision.HOLD))


@pytest.mark.parametrize("op", ["suspend", "revoke"])
def test_admitted_with_dead_act_chain_ancestor(tmp_path, op):
    """kabir follow-up (3): an act_chain ancestor suspended/revoked at admission must have been revoked_ancestor."""
    chain = (ActLink(principal="intake", action_id="T-3"),)
    ok = _verify(tmp_path / "ok", _seal(), _agent(2, 0, chain=chain))
    assert ok.reason == "ok", ok
    _bad(tmp_path / "bad", 3, _seal(), _ctl(2, op, 1, target="agent:intake"), _agent(3, 0, chain=chain))


def test_other_agent_unaffected(tmp_path):
    rep = _verify(tmp_path, _seal(), _ctl(2, "suspend", 1), _agent(3, 0, agent="billing",
                                                                   chain=()))
    assert rep.reason == "ok", rep
