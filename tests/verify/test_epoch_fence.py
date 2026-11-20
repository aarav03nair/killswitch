"""B3-49: epoch fence. Every admitted agent record carries the agent's folded epoch; none while suspended."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import samples as S  # noqa: E402
from test_contracts_13 import _rechain, _run, _seal  # noqa: E402
from .test_record_rules import _ctl, _verify  # noqa: E402

from ks.contracts import CONTROL_TOOL, ActionClass, Control, ControlOp, Decision, Exit, Reason, Record  # noqa: E402
from ks.verify import verify  # noqa: E402


def _agent(seq, epoch, tick=13, reexec_of=None, agent="crm"):
    env = S.envelope(agent=agent, action_id=f"{agent}-{seq}", epoch=epoch, expiry_tick=tick, nonce=f"{seq:032x}")
    return Record.seal(prev_hash="0" * 64, seq=seq, tick=tick, ts_us=1_000_000_000 + tick * 1000 + seq,
                       record_id=f"r-{seq:06d}", conn_id="c-3", envelope=env.header(), envelope_hash=env.content_hash(),
                       sig_ok=True, decision=Decision.EXEC, reason=Reason.OK, policy_rule=None,
                       action_class=ActionClass.R, read_set=(), write_set=(), outbox_ids=(), result_hash=None,
                       control=None, reexec_of=reexec_of)


def _release(seq, epoch, tick=13):
    c = Control(control_id="k-000002", op=ControlOp.RELEASE, target="agent:crm", epoch=epoch, alert_id=None,
                issued_by="ks.operator", auto=False, reason="operator")
    from ks.contracts import Envelope
    env = Envelope(agent_id="ks.operator", action_id="k-000002", parent_action_id=None, act_chain=(),
                   tool=CONTROL_TOOL, args=c.to_obj(), nonce=f"{2:032x}", expiry_tick=tick, epoch=0,
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


def test_honest_suspend_release_verifies(tmp_path):
    assert _verify(tmp_path, _seal(), _agent(2, 0, tick=10), _ctl(3, 1), _release(4, 2), _agent(5, 2, tick=14)).reason == "ok"


def test_forged_admit_after_suspend(tmp_path):
    _bad(tmp_path, 4, _seal(), _agent(2, 0, tick=10), _ctl(3, 1), _agent(4, 1))


def test_old_epoch_record_after_release(tmp_path):
    _bad(tmp_path, 5, _seal(), _ctl(2, 1), _release(3, 2), _agent(4, 2), _agent(5, 0))


def test_reexec_under_stale_epoch(tmp_path):
    _bad(tmp_path, 4, _seal(), _ctl(2, 1), _release(3, 2), _agent(4, 0, reexec_of=1))


def test_deny_after_suspend_is_fine(tmp_path):
    from tests.verify.test_reexec import replace
    d = replace(_agent(4, 0), decision=Decision.DENY, reason=Reason.SUSPENDED)
    assert _verify(tmp_path, _seal(), _agent(2, 0, tick=10), _ctl(3, 1), d).reason == "ok"
