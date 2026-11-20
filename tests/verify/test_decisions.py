"""B3-20: anchored decisions replay."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import samples as S  # noqa: E402
from test_contracts_13 import _rechain, _run, _seal  # noqa: E402

from ks.contracts import (CONTROL_TOOL, ActionClass, Control, ControlOp, Envelope, Record, RunAnchor,  # noqa: E402
                          RunConfig, RunDir)
from ks.runtime.options import RunOptions  # noqa: E402
from ks.verify import decisions as D  # noqa: E402
from ks.verify import verify  # noqa: E402
from ks.contracts import VERIFY_REASONS, Decision, Reason  # noqa: E402


def _ctl(seq, epoch, *, issuer="ks.operator", tick=12, cid=1):
    manual = issuer == "ks.operator"
    c = Control(control_id=f"k-{cid:06d}", op=ControlOp.SUSPEND, target="agent:crm", epoch=epoch, alert_id=None,
                issued_by=issuer, auto=not manual, reason="operator" if manual else "hard_alert")
    env = Envelope(agent_id=issuer, action_id=f"k-{cid:06d}", parent_action_id=None, act_chain=(), tool=CONTROL_TOOL,
                   args=c.to_obj(), nonce=f"{cid:032x}", expiry_tick=tick, epoch=0, claimed_ts_us=None,
                   claimed_seq=None, sig=None)
    env = env.with_sig(S.sign(issuer, env.signing_bytes()))
    return Record.seal(prev_hash="0" * 64, seq=seq, tick=tick, ts_us=1_000_000_000 + tick * 1000,
                       record_id=f"r-{seq:06d}", conn_id="c-0", envelope=env.header(), envelope_hash=env.content_hash(),
                       sig_ok=True, decision=Decision.EXEC, reason=Reason.OK, policy_rule="operator",
                       action_class=ActionClass.R, read_set=(), write_set=(), outbox_ids=(), result_hash=None,
                       control=c, reexec_of=None)


def _src(tmp_path, issuer="ks.operator"):
    recs = _rechain(_seal(), _ctl(2, 1, issuer=issuer))
    run = _run(tmp_path, recs)
    cfg = RunConfig.from_canonical((run / "config.json").read_bytes())
    kr = S.keyring()
    last = S.witness(recs[-1], count=2)
    return run, RunAnchor.of(last, kr, cfg)


def test_no_anchor_refused(tmp_path):
    run, _ = _src(tmp_path)
    with pytest.raises(D.DecisionsRefused) as e:
        D.load_decisions(run, None)
    assert e.value.reason == "no_anchor"


def test_wrong_anchor_refused(tmp_path):
    run, a = _src(tmp_path)
    bad = a.model_copy(update=dict(head="1" * 64))
    with pytest.raises(D.DecisionsRefused):
        D.load_decisions(run, bad)


def test_operator_controls_only(tmp_path):
    run, a = _src(tmp_path)
    src = D.load_decisions(run, a)
    assert [c.control.issued_by for c in src.controls] == ["ks.operator"] and src.anchor_hash == D.anchor_hash(a)


def test_monitor_controls_not_replayed(tmp_path):
    run, a = _src(tmp_path, issuer="ks.monitor")
    assert D.load_decisions(run, a).controls == ()


def _replay(tmp_path, src, *, ctl=True, from_=None, epoch=1):
    from ks.contracts import GENESIS_HASH  # noqa: F401
    recs = _rechain(*([_seal()] + ([_ctl(2, epoch)] if ctl else [])))
    cfg = S.run_config(decisions_from=from_ or src.anchor_hash)
    rd = RunDir.create(tmp_path / "replay", cfg, S.keyring())
    from ks.world.scenario import open_world_store, seed_state
    store = open_world_store(rd.path / "workspace" / "state.db")
    with store.txn():
        seed_state(store, seq=1)
    store.close()
    for i, r in enumerate(recs, start=1):
        rd.append(r)
        rd.append(S.witness(r, count=i))
    return rd.path


def test_replay_matches(tmp_path):
    run, a = _src(tmp_path)
    src = D.load_decisions(run, a)
    assert D.verify_replay(_replay(tmp_path, src), src).reason == "ok"


def test_replay_missing_decision_is_failure(tmp_path):
    run, a = _src(tmp_path)
    src = D.load_decisions(run, a)
    rep = D.verify_replay(_replay(tmp_path, src, ctl=False), src)
    assert (not rep.ok) and rep.first_bad == 2


def test_replay_differs_is_failure(tmp_path):
    run, a = _src(tmp_path)
    src = D.load_decisions(run, a)
    rep = D.verify_replay(_replay(tmp_path, src, epoch=2), src)
    assert (not rep.ok) and rep.first_bad == 2 and rep.reason == "replay_mismatch" and rep.exit == int(VERIFY_REASONS["replay_mismatch"])


def test_replay_wrong_decisions_from(tmp_path):
    run, a = _src(tmp_path)
    src = D.load_decisions(run, a)
    assert D.verify_replay(_replay(tmp_path, src, from_="9" * 64), src).reason == "replay_mismatch"


def test_stale_plan_hold():
    assert D.approval_verdict("a" * 64, "b" * 64) == (Decision.HOLD, Reason.STALE_PLAN)
    assert D.approval_verdict("a" * 64, "a" * 64) == (Decision.EXEC, Reason.OK)


def test_rogue_refused():
    with pytest.raises(ValueError):
        RunOptions(decisions="x", rogue="r.py")
    with pytest.raises(D.DecisionsRefused):
        D.refuse_with_rogue("x", "r.py")


def test_repro_refused(tmp_path):
    rd = RunDir.create(tmp_path / "r", S.run_config(key_mode="repro"), S.keyring())
    with pytest.raises(D.DecisionsRefused) as e:
        D.load_decisions(rd.path, S.run_config().__class__ and RunAnchor(seq=1, head="1" * 64, tick=0, count=1,
                         keyring_hash="2" * 64, config_hash="3" * 64))
    assert e.value.reason == "repro_keys"


def test_unwitnessed_tail_is_not_replayed(tmp_path):
    """B3-20 (kabir): operator Controls after the anchor's seq are never loaded."""
    from test_contracts_13 import _rechain, _seal
    from ks.contracts import RunAnchor, RunConfig, RunDir
    from ks.world.scenario import open_world_store, seed_state
    import samples as S
    recs = _rechain(_seal(), _ctl(2, 1), _ctl(3, 2, cid=2, tick=13))
    rd = RunDir.create(tmp_path / "run", S.run_config(), S.keyring())
    st = open_world_store(rd.path / "workspace" / "state.db")
    with st.txn():
        seed_state(st, seq=1)
    st.close()
    for i, r in enumerate(recs, start=1):
        rd.append(r)
        if i <= 2:
            rd.append(S.witness(r, count=i))
    cfg = RunConfig.from_canonical((rd.path / "config.json").read_bytes())
    a = RunAnchor.of(S.witness(recs[1], count=2), S.keyring(), cfg)
    src = D.load_decisions(rd.path, a)
    assert all(c.seq <= a.seq for c in src.controls) and len(src.controls) <= 1
