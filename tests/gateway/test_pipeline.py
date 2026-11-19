"""B3-11: the full admission pipeline (ADR-03 §1 steps 1-14) in one canonical order, state txn and re-check."""

from __future__ import annotations

import hashlib

import pytest

from ks.contracts import (CONTRACTS_VERSION, SEED_TOOL, MAX_EXPIRY_TICKS, SYSTEM_CONN, SYSTEM_PRINCIPALS, ActionClass,
                          ActLink, Decision, Envelope, Reason, RunConfig, RunDir, SubmitFrame, encode_frame)
from ks.gateway import Gateway, StaticControl, Verdict
from ks.identity import KeyStore, sign_hex, verify_hex
from ks.recorder import GatewayHooks, Recorder
from ks.world.agents import AGENT_IDS
from ks.world.registry import SENSITIVE_FIELDS
from ks.world.scenario import open_world_store, seed_state
from ks.world.tools import WorldDispatcher

A, B = "triage", "crm"  # triage may set ticket priority; crm is a second principal


def build(tmp_path, *, world=True, hooks=None, policy=None, seed=None):
    cfg = RunConfig(run_id="b311", contracts_version=CONTRACTS_VERSION, seed=1, scenario="world", fault=None,
                    culprit=None, fault_tick=None, key_mode="fresh", decision_latency_ticks=0, ticks=40,
                    tick_us=1000, start_ts_us=0, hold_window_ticks=0, sensitive_fields=SENSITIVE_FIELDS,
                    agents=AGENT_IDS)
    keys = KeyStore.create(sorted(SYSTEM_PRINCIPALS | set(AGENT_IDS)), key_mode="fresh", seed=1)
    ring = keys.keyring({})
    rec = Recorder(RunDir.create(tmp_path / "run", cfg, ring), keys.signer("ks.gateway"))
    ctl = StaticControl({a: 0 for a in AGENT_IDS})
    store = open_world_store(tmp_path / "state.db")
    g = Gateway(cfg, ring, rec, dispatcher=WorldDispatcher(), control=ctl, store=store, hooks=hooks, policy=policy,
                seed=seed or (lambda s, q: seed_state(s, seq=q)), sign=keys.signer("ks.gateway"))
    g.bind("c-1", A)  # B3-42: an unbound connection is denied, so direct admit() tests bind c-1
    return g, keys, ctl, store, ring


def frame(keys, *, agent=A, signer=None, tool="ticket.set_priority", tick=1, action="a-1", nonce=None, expiry=None,
          epoch=0, chain=(), args=None):
    args = {"id": "T-0000", "priority": "high"} if args is None else args
    nonce = nonce or hashlib.sha256(f"{agent}/{action}".encode()).hexdigest()[:32]
    env = Envelope(agent_id=agent, action_id=action, parent_action_id=chain[-1].action_id if chain else None,
                   act_chain=chain, tool=tool, args=args, nonce=nonce,
                   expiry_tick=tick + 2 if expiry is None else expiry, epoch=epoch, claimed_ts_us=None,
                   claimed_seq=None, sig=None)
    return encode_frame(SubmitFrame(tick=tick, envelope=env.with_sig(sign_hex(keys.private(signer or agent),
                                                                              env.signing_bytes()))))


def test_seed_record_is_seq_1_and_views_see_it(tmp_path):
    g, keys, ctl, store, ring = build(tmp_path)
    opened = g.open(0, AGENT_IDS)
    recs = list(g.recorder.rundir.records())
    assert len(recs) == 1 and recs[0].seq == 1
    r = recs[0]
    assert (r.conn_id, r.tick, r.decision, r.envelope.agent_id) == (SYSTEM_CONN, 0, Decision.EXEC, "ks.gateway")
    assert r.sig_ok and verify_hex(ring.pub("ks.gateway"), r.envelope.sig, r.envelope.signing_bytes())
    heads = store.heads()
    assert {w.obj for w in r.write_set} == set(heads) and all(w.after.ver == 1 and w.before is None for w in r.write_set)
    assert {w.obj: w.after.hash for w in r.write_set} == {o: v.hash for o, v in heads.items()}
    assert not r.integrity_problems()
    assert opened[A].view  # the seed is visible at tick 0: visible_to = 2
    g.open(1, AGENT_IDS)  # no second seed
    assert g.recorder.seq == 1


def test_world_action_takes_seq_2_and_is_invisible_in_its_own_tick(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    adm = g.admit("c-1", frame(keys))
    assert (adm.record.seq, adm.record.decision) == (2, Decision.EXEC)
    [w] = adm.record.write_set
    assert w.obj == "tickets:T-0000" and w.after.ver == 2
    assert store.history("tickets:T-0000")[-1].seq == 2
    # tick 2 view is built with visible_to = 3, tick 1's was 2: the write shows only from tick 2
    v1 = {e.obj: e.ver for e in g.delivered[A]}
    v2 = {e.obj: e.ver for e in g.open(2, AGENT_IDS)[A].view}
    assert v1["tickets:T-0000"] == 1 and v2["tickets:T-0000"] == 2


def test_view_rejects_visible_to_none(tmp_path):
    from types import SimpleNamespace as NS
    _, _, _, store, _ = build(tmp_path)
    with pytest.raises(TypeError, match="visible_to"):
        WorldDispatcher().view(A, 1, NS(store=store, visible_to=None))


# --- acceptance 1: first failing step wins, canonical order ------------------------------------------------------
def test_first_failing_step_decides_the_reason(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    ctl.conns["c-1"] = Reason.REVOKED
    ctl.agents[B] = Reason.REVOKED
    ctl.epochs[A] = 5  # agent epoch moved on: envelopes at epoch 0 are stale
    kw = dict(tool="ks.control", epoch=0)  # fails scope (10) and class U (11); epoch (8) stale
    chain = (ActLink(principal=B, action_id="p-1"),)
    # each frame fails its own step and every later one; the first one must win
    table = [
        (b"\xff not json\n", Reason.SCHEMA),                                                              # 1 decode
        (b'{"type":"submit","tick":1,"x":1}\n', Reason.SCHEMA),                                           # 2 schema
        (frame(keys, signer=B, action="s", tick=0, expiry=0, chain=chain, **kw), Reason.BAD_SIG),         # 3 signature
        (frame(keys, action="l", tick=0, expiry=0, chain=chain, **kw), Reason.LATE_FRAME),                # 4 late
        (frame(keys, action="e", expiry=1 + MAX_EXPIRY_TICKS + 1, chain=chain, **kw), Reason.EXPIRED),    # 5 expiry
        (frame(keys, action="n", nonce="a" * 32, chain=chain, **kw), None),                               # seeds nonce
        (frame(keys, action="n2", nonce="a" * 32, chain=chain, **kw), Reason.NONCE_REUSED),               # 6 nonce
        (frame(keys, action="n", nonce="d" * 32, chain=chain, **kw), Reason.NONCE_REUSED),                # 6 action_id
        (frame(keys, action="c", chain=chain, **kw), Reason.REVOKED),                                     # 7 conn
    ]
    for line, want in table:
        adm = g.admit("c-1", line)
        if want is not None:
            assert adm.record.reason == want, (line[:40], adm.record.reason)
    ctl.conns.clear()
    ctl.agents[A] = Reason.SUSPENDED
    assert g.admit("c-1", frame(keys, action="st", chain=chain, **kw)).record.reason == Reason.SUSPENDED   # 8 status
    del ctl.agents[A]
    assert g.admit("c-1", frame(keys, action="ep", chain=chain, **kw)).record.reason == Reason.STALE_EPOCH  # 8 epoch
    ctl.epochs[A] = 0
    assert g.admit("c-1", frame(keys, action="an", chain=chain, **kw)).record.reason == Reason.REVOKED_ANCESTOR  # 9
    ctl.agents.clear()
    assert g.admit("c-1", frame(keys, action="ks", chain=chain, **kw)).record.reason == Reason.OUT_OF_SCOPE  # 10
    last = g.admit("c-1", frame(keys, action="u", tool="crm.drop_all"))
    assert (last.record.reason, last.record.action_class) == (Reason.CLASS_U, ActionClass.U)                  # 11
    g.policy = type("P", (), {"decide": lambda s, e, c: Verdict(Decision.HOLD, Reason.NEEDS_APPROVAL, "p.test")})()
    hold = g.admit("c-1", frame(keys, action="h")).record
    assert (hold.decision, hold.reason, hold.policy_rule, hold.write_set) == \
        (Decision.HOLD, Reason.NEEDS_APPROVAL, "p.test", ())                                                  # 12
    g.policy = type("P", (), {"decide": lambda s, e, c: None})()
    ok = g.admit("c-1", frame(keys, action="ok")).record
    assert (ok.decision, ok.reason) == (Decision.EXEC, Reason.OK)                                             # 13/14
    recs = list(g.recorder.rundir.records())
    assert [r.seq for r in recs] == list(range(1, len(recs) + 1))  # every envelope recorded, no gap (rule 11)
    assert len(store.history("tickets:T-0000")) == 2  # only the admitted action wrote (seed + 1)


# --- acceptance 2: nonce pruning, action_id kept for the run ----------------------------------------------------
def test_action_id_reuse(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    assert g.admit("c-1", frame(keys, action="dup", nonce="b" * 32)).record.decision == Decision.EXEC
    assert ("triage", "b" * 32) in g._nonces
    for t in range(2, 22):
        g.open(t, AGENT_IDS)
    assert ("triage", "b" * 32) not in g._nonces  # pruned past MAX_EXPIRY_TICKS
    assert len(g._nonces) == 0
    adm = g.admit("c-1", frame(keys, action="dup", tick=21, nonce="c" * 32))  # fresh nonce, reused action_id
    assert (adm.record.decision, adm.record.reason) == (Decision.DENY, Reason.NONCE_REUSED)  # test_action_id_reuse
    assert g.admit("c-1", frame(keys, action="new", tick=21, nonce="b" * 32)).record.decision == Decision.EXEC


# --- acceptance 3: RT5 unit, the txn re-reads control ----------------------------------------------------------
@pytest.mark.parametrize("how, reason", [("suspend", Reason.SUSPENDED), ("epoch", Reason.STALE_EPOCH),
                                         ("conn", Reason.REVOKED), ("ancestor", Reason.REVOKED_ANCESTOR)])
def test_rt5_unit_suspend_between_check_and_txn(tmp_path, how, reason):
    class Inject(GatewayHooks):
        def between_check_and_txn(self, env):
            if how == "suspend":
                ctl.agents[A] = Reason.SUSPENDED
            elif how == "epoch":
                ctl.epochs[A] = 1
            elif how == "conn":
                ctl.conns["c-1"] = Reason.REVOKED
            else:
                ctl.agents[B] = Reason.REVOKED

    g, keys, ctl, store, _ = build(tmp_path, hooks=Inject())
    g.open(1, AGENT_IDS)
    chain = (ActLink(principal=B, action_id="p"),) if how == "ancestor" else ()
    adm = g.admit("c-1", frame(keys, chain=chain))
    r = adm.record
    assert (r.decision, r.reason, r.write_set, r.read_set) == (Decision.DENY, reason, (), ())
    assert r.seq == 2 and g.recorder.seq == 2          # the txn's seq became the denial's: no gap
    assert len(store.history("tickets:T-0000")) == 1   # 0 exec: the txn rolled back, nothing landed
    assert not store.conn.in_transaction
    ctl.agents.clear(); ctl.conns.clear(); ctl.epochs[A] = 0
    assert g.admit("c-1", frame(keys, action="next")).record.seq == 3  # the connection state is clean


def test_tool_exception_rolls_back_and_records_tool_error_deny(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)

    class Boom(WorldDispatcher):
        def execute(self, env, txn):
            super().execute(env, txn)  # writes, then fails
            raise RuntimeError("tool crashed")

    g.dispatcher = Boom()
    r = g.admit("c-1", frame(keys)).record  # B3-43: no raise; a recorded deny consumes seq 2 (no gap)
    assert (r.seq, r.decision, r.reason, r.sig_ok) == (2, Decision.DENY, Reason.TOOL_ERROR, True)
    assert not (r.read_set or r.write_set or r.outbox_ids) and r.result_hash is None
    assert len(store.history("tickets:T-0000")) == 1 and not store.conn.in_transaction
    g.dispatcher = WorldDispatcher()
    adm = g.admit("c-1", frame(keys, action="again"))
    assert (adm.record.seq, adm.record.decision) == (3, Decision.EXEC)


def test_writes_at_is_the_stores_own_write_set(tmp_path):
    from ks.gateway import writes_at
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    rec = g.admit("c-1", frame(keys)).record
    assert writes_at(store, rec.seq) == rec.write_set


def _assert_clean_failure(g, keys, store, seq_before):
    assert len(store.history("tickets:T-0000")) == 1 and not store.conn.in_transaction  # no state change
    assert g.recorder.seq == seq_before                                                 # seq released
    assert g.admit("c-1", frame(keys, action="next")).record.seq == seq_before + 1      # the next admit works


def test_unhashable_result_rolls_back_before_commit(tmp_path):
    from ks.contracts import CanonicalError
    from ks.gateway import Execution
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    inner = WorldDispatcher()

    class Floaty(WorldDispatcher):
        def execute(self, env, txn):
            ex = inner.execute(env, txn)  # the write lands in the txn
            return Execution(1.5, ex.read_set, ex.write_set, ex.outbox)  # a float is not canonical

    g.dispatcher = Floaty()
    r = g.admit("c-1", frame(keys)).record  # B3-41: a recorded deny, the write rolled back
    assert (r.seq, r.decision, r.reason) == (2, Decision.DENY, Reason.TOOL_ERROR)
    g.dispatcher = WorldDispatcher()
    assert len(store.history("tickets:T-0000")) == 1 and not store.conn.in_transaction
    assert g.admit("c-1", frame(keys, action="next")).record.seq == 3


def test_database_locked_at_begin_releases_seq(tmp_path):
    import sqlite3
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    real = store.conn

    class Locked:
        def __getattr__(self, n):
            return getattr(real, n)

        def execute(self, sql, *a):
            if sql == "BEGIN IMMEDIATE":
                raise sqlite3.OperationalError("database is locked")
            return real.execute(sql, *a)

    store.conn = Locked()
    with pytest.raises(sqlite3.OperationalError):
        g.admit("c-1", frame(keys))
    store.conn = real
    _assert_clean_failure(g, keys, store, 1)


# --- B3-43: ks.seed record, dispatcher raise = recorded tool_error deny -----------------------------------------
def test_seed_record_uses_seed_tool_and_run_verifies(tmp_path):
    from ks.verify import verify
    g, keys, ctl, store, ring = build(tmp_path)
    g.open(0, AGENT_IDS)
    [r] = list(g.recorder.rundir.records())
    assert r.envelope.tool == SEED_TOOL == "ks.seed" and r.policy_rule is None
    assert (r.seq, r.tick, r.conn_id, r.read_set) == (1, 0, SYSTEM_CONN, ())
    assert not r.seed_problems()
    g.open(1, AGENT_IDS)
    g.admit("c-1", frame(keys))
    rep = verify(tmp_path / "run", log=lambda s: None)
    assert rep.reason != "seed_invalid", rep


def test_seed_with_wrong_write_set_is_seed_invalid(tmp_path):
    from ks.verify import verify

    def extra_seed(store, seq):  # a gateway that seeds differently from seed_state: signed, chained, but wrong
        seed_state(store, seq=seq)
        store.write_row("docs:D-0001", {"title": "extra"}, author="ks.gateway", seq=seq, action_id="seed-x")

    g, keys, ctl, store, ring = build(tmp_path, seed=extra_seed)
    g.open(0, AGENT_IDS)
    rep = verify(tmp_path / "run", log=lambda s: None)
    assert rep.reason == "seed_invalid" and rep.first_bad == 1, rep
