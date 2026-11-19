"""B3-15: ks.verify per-record rules, isolation echo, seed-from-config, state.db value-vs-hash."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import samples as S  # noqa: E402
from test_contracts_13 import _env, _rechain, _run, _seal, _tool_error  # noqa: E402

from ks.contracts import (CONTROL_TOOL, ActionClass, Control, ControlOp, Decision, Envelope, Exit, Reason, Record,  # noqa: E402
                          RunDir)
from ks.verify import verify  # noqa: E402

QUIET = dict(log=lambda s: None)


def _ctl(seq: int, epoch: int, *, tick: int = 12, ts_us: int | None = None, cid: int = 1, issuer: str = "ks.monitor",
         conn: str = "c-0", expiry: int | None = None) -> Record:
    c = Control(control_id=f"k-{cid:06d}", op=ControlOp.SUSPEND, target="agent:crm", epoch=epoch, alert_id="a-000001",
                issued_by=issuer, auto=True, reason="hard_alert")
    env = Envelope(agent_id=issuer, action_id=f"k-{cid:06d}", parent_action_id=None, act_chain=(), tool=CONTROL_TOOL,
                   args=c.to_obj(), nonce=f"{cid:032x}", expiry_tick=tick if expiry is None else expiry, epoch=0,
                   claimed_ts_us=None, claimed_seq=None, sig=None)
    env = env.with_sig(S.sign(issuer, env.signing_bytes()))
    return Record.seal(prev_hash="0" * 64, seq=seq, tick=tick, ts_us=1_000_000_000 + tick * 1000 if ts_us is None else ts_us,
                       record_id=f"r-{seq:06d}", conn_id=conn, envelope=env.header(), envelope_hash=env.content_hash(),
                       sig_ok=True, decision=Decision.EXEC, reason=Reason.OK, policy_rule="hard_alert_suspend",
                       action_class=ActionClass.R, read_set=(), write_set=(), outbox_ids=(), result_hash=None,
                       control=c, reexec_of=None)


def _verify(tmp_path, *recs):
    return verify(_run(tmp_path, _rechain(*recs)), **QUIET)


def test_clean_seed_plus_control_verifies(tmp_path):
    assert _verify(tmp_path, _seal(), _ctl(2, 1)).reason == "ok"


def test_ts_us_formula_violation_is_tamper_with_first_bad(tmp_path):
    rep = _verify(tmp_path, _seal(), _ctl(2, 1, ts_us=1_000_012_000 + 5000))
    assert (rep.exit, rep.first_bad) == (Exit.TAMPER, 2)


def test_ts_us_must_increase_within_a_tick(tmp_path):
    rep = _verify(tmp_path, _seal(), _ctl(2, 1), _ctl(3, 2, cid=2))
    assert (rep.exit, rep.first_bad) == (Exit.TAMPER, 3)


def test_epoch_regression_is_tamper(tmp_path):
    rep = _verify(tmp_path, _seal(), _ctl(2, 3), _ctl(3, 2, cid=2, ts_us=1_000_012_001))
    assert (rep.exit, rep.reason, rep.first_bad) == (Exit.TAMPER, "epoch_regression", 3)


def test_unverified_unknown_agent_claim_is_just_a_denial(tmp_path):
    env = S.envelope(agent="ghost", signer="ghost", expiry_tick=12)
    r = Record.seal(prev_hash="0" * 64, seq=2, tick=10, ts_us=1_000_010_000, record_id="r-000002", conn_id="c-3",
                    envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=False, decision=Decision.DENY,
                    reason=Reason.BAD_SIG, policy_rule=None, action_class=ActionClass.R, read_set=(), write_set=(),
                    outbox_ids=(), result_hash=None, control=None, reexec_of=None)
    assert _verify(tmp_path, _seal(), r).reason == "ok"  # unverified claim: just a denial, not an attribution


@pytest.mark.parametrize("old, new", [
    (b'"conn_id":"c-0"', b'"conn_id":"c-3"'),          # ks.control executed off c-0
    (b'"issued_by":"ks.monitor"', b'"issued_by":"ks.operator"'),  # issued_by != envelope.agent_id
    (b'"expiry_tick":12', b'"expiry_tick":1'),         # expired when admitted
])
def test_raw_edits_of_control_records_are_tamper_at_that_line(tmp_path, old, new):
    run = _run(tmp_path, _rechain(_seal(), _ctl(2, 1)))
    p = run / "record.jsonl"
    lines = p.read_bytes().split(b"\n")
    assert old in lines[1]
    lines[1] = lines[1].replace(old, new)
    p.write_bytes(b"\n".join(lines))
    rep = verify(run, **QUIET)
    assert (rep.exit, rep.first_bad) == (Exit.TAMPER, 2)


def test_isolation_is_echoed_and_degraded_says_void(tmp_path):
    msgs: list[str] = []
    rep = verify(_run(tmp_path, _rechain(_seal())), log=msgs.append)
    assert rep.isolation == "degraded" and any("per-agent attribution VOID" in m for m in msgs)


# --- seed (kabir B3-43) ---------------------------------------------------------------------------
def test_seq_1_must_be_the_seed(tmp_path):
    rep = _verify(tmp_path, _tool_error(seq=1, record_id="r-000001"))
    assert (rep.exit, rep.reason, rep.first_bad) == (Exit.TAMPER, "seed_invalid", 1)


def test_missing_first_record_of_a_one_three_run_with_a_dispatch_first_fails(tmp_path):
    env = _env(tool="ks.dispatch")
    rep = _verify(tmp_path, _seal(env=env, write_set=()))
    assert (rep.reason, rep.first_bad) == ("seed_invalid", 1)


def test_seed_args_must_match_the_runs_own_scenario(tmp_path):
    other = Envelope(agent_id="ks.gateway", action_id="seed", parent_action_id=None, act_chain=(), tool="ks.seed",
                     args={"seed": "not-this-run"}, nonce="0" * 32, expiry_tick=0, epoch=0, claimed_ts_us=None,
                     claimed_seq=None, sig=None)
    other = other.with_sig(S.sign("ks.gateway", other.signing_bytes()))
    rep = _verify(tmp_path, _seal(env=other))
    assert (rep.reason, rep.first_bad) == ("seed_invalid", 1)


def test_skeleton_scenario_has_no_seed_record(tmp_path):
    rd = RunDir.create(tmp_path / "run", S.run_config(scenario="skeleton"), S.keyring())
    assert verify(rd.path, **QUIET).reason == "ok"  # empty record, no state, nothing to seed


# --- reconcile: value vs hash ----------------------------------------------------------------------
def _clean(tmp_path) -> Path:
    run = _run(tmp_path, _rechain(_seal()))
    assert verify(run, **QUIET).reason == "ok"
    return run


def _sql(run: Path, stmt: str) -> None:
    c = sqlite3.connect(run / "workspace" / "state.db", isolation_level=None)
    try:
        c.execute("DROP TRIGGER IF EXISTS versions_no_update")
        c.execute(stmt)
    finally:
        c.close()


def test_edited_head_value_in_state_db_is_reconcile_mismatch(tmp_path):
    run = _clean(tmp_path)
    c = sqlite3.connect(run / "workspace" / "state.db", isolation_level=None)
    obj, = c.execute("SELECT obj FROM objects WHERE head_value IS NOT NULL ORDER BY obj LIMIT 1").fetchone()
    c.close()
    _sql(run, f"UPDATE objects SET head_value = '{{\"evil\":1}}' WHERE obj = '{obj}'")
    rep = verify(run, **QUIET)
    assert (rep.exit, rep.reason) == (Exit.RECONCILE, "reconcile_mismatch")


def test_edited_side_value_in_state_db_is_reconcile_mismatch(tmp_path):
    run = _clean(tmp_path)
    _sql(run, "UPDATE side SET value = '{\"evil\":1}' WHERE hash = (SELECT MIN(hash) FROM side WHERE redacted = 0)")
    assert verify(run, **QUIET).reason == "reconcile_mismatch"


def test_missing_state_with_seed_writes_is_no_state(tmp_path):
    run = _clean(tmp_path)
    (run / "workspace" / "state.db").unlink()
    assert verify(run, **QUIET).reason == "no_state"


# --- skeleton label must not dodge the seed rule (Kabir's B3-15 probe) -------------------------------
def test_skeleton_label_with_state_writes_is_not_an_exemption(tmp_path):
    from ks.world.scenario import open_world_store, seed_state
    rd = RunDir.create(tmp_path / "run", S.run_config(scenario="skeleton"), S.keyring())
    st = open_world_store(rd.path / "workspace" / "state.db")
    with st.txn():
        seed_state(st, seq=1)
    st.close()
    for i, r in enumerate(_rechain(_seal(env=_env(tool="ks.dispatch"), policy_rule=None)), start=1):
        rd.append(r)
        rd.append(S.witness(r, count=i))
    rep = verify(rd.path, **QUIET)
    assert (rep.ok, rep.exit, rep.reason, rep.first_bad) == (False, Exit.TAMPER, "seed_invalid", 1)


def test_skeleton_label_with_a_state_db_but_no_writes_is_no_state(tmp_path):
    from ks.world.scenario import open_world_store
    rd = RunDir.create(tmp_path / "run", S.run_config(scenario="skeleton"), S.keyring())
    open_world_store(rd.path / "workspace" / "state.db").close()
    rep = verify(rd.path, **QUIET)
    assert (rep.ok, rep.reason) == (False, "no_state")
