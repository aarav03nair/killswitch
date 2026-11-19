"""Contracts 1.3.0 (B3-43, additive): ``ks.seed`` system tool (D-15, amends CALL-02 G1) with its verify rule
(``seed_invalid``), and deny reason ``tool_error`` (B3-11 finding 3, rule 11: a dispatcher that raises is still
recorded)."""

import json
from pathlib import Path

import jsonschema
import pytest

import ks.contracts as C
from ks.contracts import (GENESIS_HASH, REASONS_FOR, SEED_TOOL, SYSTEM_CONN, SYSTEM_TOOLS, VERIFY_REASONS,
                          ActionClass, Decision, Envelope, Exit, ReadEntry, Reason, Record, RunDir, canonical,
                          record_id_for, result_hash, system_tool_signers)
from ks.contracts.schema_gen import SCHEMA_DIR
from ks.verify import verify
from ks.verify.core import expected_seed_writes

import samples as S

SRC = Path(__file__).resolve().parents[2] / "src" / "ks"
RECORD_SCHEMA = json.loads((SCHEMA_DIR / "c2.record.schema.json").read_text(encoding="utf-8"))


def _env(agent="ks.gateway", tool=SEED_TOOL, nonce="0" * 32, expiry_tick=0) -> Envelope:
    e = Envelope(agent_id=agent, action_id="seed", parent_action_id=None, act_chain=(), tool=tool,
                 args={"seed": "acme"}, nonce=nonce, expiry_tick=expiry_tick, epoch=0, claimed_ts_us=None,
                 claimed_seq=None, sig=None)
    return e.with_sig(S.sign(agent, e.signing_bytes()))


def _fields(env: Envelope, **over) -> dict:
    f = dict(tick=0, ts_us=1_000_000_000 + 1000 * over.get("tick", 0), conn_id=SYSTEM_CONN, envelope=env.header(), envelope_hash=env.content_hash(),
             sig_ok=True, decision=Decision.EXEC, reason=Reason.OK, policy_rule="gateway.seed",
             action_class=ActionClass.R, read_set=(), write_set=expected_seed_writes(), outbox_ids=(),
             result_hash=result_hash({"seeded": 22}), control=None, reexec_of=None)
    f.update(over)
    return f


def _seal(seq=1, prev=GENESIS_HASH, env=None, **over) -> Record:
    f = _fields(env or _env(), **over)
    r = Record.seal(prev_hash=prev, seq=seq, record_id=record_id_for(seq), **f)
    return r.with_gw_sig(S.sign("ks.gateway", r.signing_bytes()))


def _tool_error(**over) -> Record:
    env = S.envelope(expiry_tick=12)
    f = dict(prev_hash=GENESIS_HASH, seq=2, record_id=record_id_for(2), tick=10, ts_us=1_000_010_000, conn_id="c-3",
             envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=True, decision=Decision.DENY,
             reason=Reason.TOOL_ERROR, policy_rule=None, action_class=ActionClass.R, read_set=(), write_set=(),
             outbox_ids=(), result_hash=None, control=None, reexec_of=None)
    f.update(over)
    return Record.seal(**f)


# --- version, catalogue ---------------------------------------------------------------------------
def test_version_is_1_3_0():
    assert C.CONTRACTS_VERSION == "1.3.0"
    readme = (SRC / "contracts" / "README.md").read_text(encoding="utf-8")
    assert "### 1.3.0" in readme and "`ks.seed`" in readme and "`tool_error`" in readme
    assert S.run_config().contracts_version == "1.3.0"


def test_ks_seed_is_a_gateway_only_system_tool():
    assert SEED_TOOL == "ks.seed" and "SEED_TOOL" in C.__all__
    assert SYSTEM_TOOLS[SEED_TOOL] == frozenset({"ks.gateway"})
    assert system_tool_signers("ks.seed") == frozenset({"ks.gateway"})
    # every 1.2 system tool is unchanged (additive)
    assert {"ks.control", "ks.dispatch", "ks.alert", "ks.approve"} < set(SYSTEM_TOOLS)
    assert SYSTEM_TOOLS["ks.dispatch"] == frozenset({"ks.gateway"})


def test_other_system_principals_cannot_execute_ks_seed():
    with pytest.raises(ValueError, match="may not execute ks.seed"):
        _seal(env=_env(agent="ks.monitor"))


# --- seed record: canonical, schema, structural rule -----------------------------------------------
def test_seed_record_roundtrips_and_validates():
    r = _seal()
    assert r.seed_problems() == []
    assert Record.from_canonical(r.to_canonical()) == r
    assert canonical.dumps(canonical.loads(r.to_canonical())) == r.to_canonical()
    jsonschema.Draft202012Validator(RECORD_SCHEMA).validate(canonical.loads(r.to_canonical()))
    assert len(r.write_set) == 22 and all(w.before is None for w in r.write_set)


@pytest.mark.parametrize("over, seq, why", [
    ({}, 2, "seq 2"),
    ({"tick": 1}, 1, "tick 1"),
    ({"read_set": (ReadEntry(obj="docs:D-0000", ver=1, hash=S.H_OLD),)}, 1, "no read set"),
    ({"decision": Decision.HOLD, "reason": Reason.NEEDS_APPROVAL, "write_set": (), "result_hash": None,
      "expiry_tick": None}, 1, "never hold"),
])
def test_seed_structural_rule(over, seq, why):
    over = dict(over)
    env = _env(expiry_tick=over.pop("expiry_tick", None) or over.get("tick", 0))
    prev = GENESIS_HASH if seq == 1 else S.record_exec().hash
    r = _seal(seq=seq, prev=prev, env=env, **over)
    assert any(why in p for p in r.seed_problems()), r.seed_problems()


def test_denied_ks_seed_is_an_ordinary_denial():
    """An agent submitting ks.seed is denied out_of_scope and recorded (rule 11); not a seed violation."""
    env = S.envelope(tool="ks.seed", args={"seed": "evil"})
    r = Record.seal(prev_hash=GENESIS_HASH, seq=5, record_id=record_id_for(5), tick=7, ts_us=7000, conn_id="c-3",
                    envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=True, decision=Decision.DENY,
                    reason=Reason.OUT_OF_SCOPE, policy_rule=None, action_class=ActionClass.R, read_set=(),
                    write_set=(), outbox_ids=(), result_hash=None, control=None, reexec_of=None)
    assert r.seed_problems() == []


# --- tool_error (B3-11 finding 3) ----------------------------------------------------------------
def test_tool_error_is_a_deny_reason_and_roundtrips():
    assert Reason.TOOL_ERROR == "tool_error" and Reason.TOOL_ERROR in REASONS_FOR[Decision.DENY]
    assert Reason.TOOL_ERROR not in REASONS_FOR[Decision.EXEC] | REASONS_FOR[Decision.HOLD]
    r = _tool_error()
    assert Record.from_canonical(r.to_canonical()) == r
    jsonschema.Draft202012Validator(RECORD_SCHEMA).validate(canonical.loads(r.to_canonical()))
    assert r.attributed_agent == "crm"


@pytest.mark.parametrize("over, msg", [
    ({"write_set": S.record_exec().write_set}, "only executed records"),
    ({"result_hash": result_hash({"ok": True})}, "only executed records"),
    ({"read_set": S.record_exec().read_set}, "no read set"),
    ({"sig_ok": False}, "sig_ok is false exactly"),
    ({"decision": Decision.HOLD}, "not allowed with decision"),
])
def test_tool_error_has_no_effects_and_is_admitted(over, msg):
    with pytest.raises(ValueError, match=msg):
        _tool_error(**over)


# --- verify rule (seed_invalid) --------------------------------------------------------------------
def test_seed_invalid_is_tamper():
    assert VERIFY_REASONS["seed_invalid"] is Exit.TAMPER


def _run(tmp_path, records: list[Record], seed_state: bool = True) -> Path:
    from ks.world.scenario import open_world_store, seed_state as seed
    rd = RunDir.create(tmp_path / "run", S.run_config(), S.keyring())
    if seed_state:
        store = open_world_store(rd.path / "workspace" / "state.db")
        with store.txn():
            seed(store, seq=1)
        store.close()
    for i, r in enumerate(records, start=1):
        rd.append(r)
        rd.append(S.witness(r, count=i))
    return rd.path


def _rechain(*recs: Record) -> list[Record]:
    """Re-seal ``recs`` as seq 1.. with a valid chain (fields kept)."""
    out, prev = [], GENESIS_HASH
    for i, r in enumerate(recs, start=1):
        f = {k: v for k, v in r.__dict__.items() if k not in ("seq", "record_id", "prev_hash", "hash", "gw_sig",
                                                              "contract")}
        n = Record.seal(prev_hash=prev, seq=i, record_id=record_id_for(i), **f)
        n = n.with_gw_sig(S.sign("ks.gateway", n.signing_bytes()))
        out.append(n)
        prev = n.hash
    return out


def test_verify_accepts_the_seed_record(tmp_path):
    rep = verify(_run(tmp_path, [_seal()]), log=lambda s: None)
    assert (rep.ok, rep.reason) == (True, "ok"), rep


def test_verify_rejects_seed_with_wrong_write_set(tmp_path):
    r = _seal(write_set=expected_seed_writes()[1:])
    rep = verify(_run(tmp_path, [r]), log=lambda s: None)
    assert (rep.exit, rep.reason, rep.first_bad) == (Exit.TAMPER, "seed_invalid", 1)


def test_verify_rejects_seed_off_tick_0(tmp_path):
    r = _seal(env=_env(expiry_tick=1), tick=1)
    rep = verify(_run(tmp_path, [r]), log=lambda s: None)
    assert (rep.reason, rep.first_bad) == ("seed_invalid", 1)


def test_verify_rejects_seed_not_at_seq_1(tmp_path):
    first = _tool_error(seq=1, record_id=record_id_for(1))
    second = _seal(seq=2, env=_env(nonce="1" * 32))
    rep = verify(_run(tmp_path, _rechain(first, second)), log=lambda s: None)
    assert (rep.exit, rep.reason, rep.first_bad) == (Exit.TAMPER, "seed_invalid", 1)  # seq 1 must be the seed


def test_verify_rejects_a_second_seed(tmp_path):
    rep = verify(_run(tmp_path, _rechain(_seal(), _seal(env=_env(nonce="2" * 32), write_set=(), ts_us=1_000_000_001))),
                 log=lambda s: None)
    assert (rep.reason, rep.first_bad) == ("seed_invalid", 2)
