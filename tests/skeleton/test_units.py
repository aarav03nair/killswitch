"""SKEL-01: gateway stub admission, signer refusals and the tick barrier, in-process (no subprocesses)."""

import socket

import pytest

from ks.contracts import (CONTRACTS_VERSION, SYSTEM_PRINCIPALS, ActionClass, Decision, Envelope, Reason, RunConfig,
                          RunDir, SignRequest, SubmitFrame, encode_frame)
from ks.gateway import Gateway
from ks.identity import KeyStore, SignerService, sign_hex
from ks.recorder import Recorder
from ks.runtime.barrier import AgentConn, TickBarrier

AGENTS = ("agent_00", "agent_01")


@pytest.fixture
def gw(tmp_path):
    cfg = RunConfig(run_id="unit", contracts_version=CONTRACTS_VERSION, seed=1, scenario="skeleton", fault=None,
                    culprit=None, fault_tick=None, key_mode="fresh", decision_latency_ticks=0, ticks=4, tick_us=1000,
                    start_ts_us=0, hold_window_ticks=0, sensitive_fields=(), agents=AGENTS)
    keys = KeyStore.create(sorted(SYSTEM_PRINCIPALS | set(AGENTS)), key_mode="fresh", seed=1)
    ring = keys.keyring({})
    g = Gateway(cfg, ring, Recorder(RunDir.create(tmp_path / "run", cfg, ring), keys.signer("ks.gateway")),
                {a: 0 for a in AGENTS}.get)
    g.begin_tick(1)
    return g, keys


def _frame(keys, *, agent="agent_00", signer=None, tool="skel.echo", tick=1, action="a-1", nonce="0" * 32):
    env = Envelope(agent_id=agent, action_id=action, parent_action_id=None, act_chain=(), tool=tool, args={"x": 1},
                   nonce=nonce, expiry_tick=tick + 2, epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)
    env = env.with_sig(sign_hex(keys.private(signer or agent), env.signing_bytes()))
    return encode_frame(SubmitFrame(tick=tick, envelope=env))


def test_admission_paths(gw):
    g, keys = gw
    cases = [
        (_frame(keys), Decision.EXEC, Reason.OK),
        (_frame(keys), Decision.DENY, Reason.NONCE_REUSED),                            # exact replay
        (_frame(keys, nonce="1" * 32), Decision.DENY, Reason.NONCE_REUSED),            # same action_id
        (b'{"type":"submit"}\n', Decision.DENY, Reason.SCHEMA),
        (_frame(keys, signer="agent_01", action="a-2"), Decision.DENY, Reason.BAD_SIG),   # framing attempt
        (_frame(keys, tick=0, action="a-3", nonce="3" * 32), Decision.DENY, Reason.LATE_FRAME),
        (_frame(keys, tool="crm.delete_all", action="a-4", nonce="4" * 32), Decision.DENY, Reason.CLASS_U),
        (_frame(keys, tool="ks.control", action="a-5", nonce="5" * 32), Decision.DENY, Reason.OUT_OF_SCOPE),
    ]
    for i, (line, decision, reason) in enumerate(cases, start=1):
        rec = g.admit("c-1", line).record
        assert (rec.seq, rec.decision, rec.reason) == (i, decision, reason), i
        assert rec.ts_us == 1000 + i - 1
    recs = list(g.recorder.rundir.records())
    assert recs[3].envelope is None and recs[3].action_class == ActionClass.U
    assert recs[4].attributed_agent is None and recs[4].claimed_agent == "agent_00"  # never counted against agent_00
    assert g.admit("c-1", b'{"tick":1,"type":"noop"}\n').record is None


def test_signer_refusals(gw):
    _, keys = gw
    s = SignerService({a: keys.private(a) for a in AGENTS}, {"agent_00": 0, "agent_01": None}.get)
    s.begin_tick(1)

    def req(agent="agent_00", tool="skel.echo", action="a"):
        env = Envelope(agent_id=agent, action_id=action, parent_action_id=None, act_chain=(), tool=tool, args={},
                       nonce="0" * 32, expiry_tick=2, epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)
        return encode_frame(SignRequest(header=env.header()))

    assert s.handle("agent_00", req(agent="agent_01")) is None
    assert s.handle("agent_00", req(tool="ks.control")) is None
    assert s.handle("agent_01", req(agent="agent_01")) is None             # suspended principal
    assert s.handle("agent_00", req(action="a1")) and s.handle("agent_00", req(action="a2"))
    assert s.handle("agent_00", req(action="a3")) is None                  # MAX_SIGN_PER_TICK = 2
    assert [r[2] for r in s.refusals] == ["foreign_agent", "system_tool", "suspended", "rate"]


class _NoWitness:
    def push(self, seq, head, tick, timeout_s):
        return None


def test_barrier_missing_frame_is_noop_and_three_misses_close(gw):
    g, keys = gw
    pairs = [socket.socketpair() for _ in range(4)]
    conns = [AgentConn(index=i, agent_id=a, conn_id=f"c-{i + 1}", gw=pairs[2 * i][0], signer=pairs[2 * i + 1][0],
                       proc=None, uid=None) for i, a in enumerate(AGENTS)]
    agent0 = pairs[0][1]
    signer = SignerService({a: keys.private(a) for a in AGENTS}, {a: 0 for a in AGENTS}.get)
    b = TickBarrier(conns, g, signer, _NoWitness(), {a: 0 for a in AGENTS}, deadline_s=0.05)
    for t in range(3):  # agent_00 answers, agent_01 stays silent
        agent0.sendall(_frame(keys, tick=t, action=f"t{t}", nonce=f"{t:032x}"))
        o = b.run_tick(t)
        assert (o.records, o.missed) == (1, ["c-2"])
    assert conns[0].alive and not conns[1].alive  # EOF after 3 misses: an anomaly, no suspend
    # pre-sent frames queue FIFO, one per tick; a frame for the wrong tick is late_frame in its slot
    agent0.sendall(_frame(keys, tick=3, action="t3", nonce=f"{3:032x}")
                   + _frame(keys, tick=3, action="t3b", nonce=f"{33:032x}"))
    assert b.run_tick(3).missed == [] and b.run_tick(4).records == 1
    reasons = [r.reason for r in g.recorder.rundir.records()]
    assert reasons == [Reason.OK] * 4 + [Reason.LATE_FRAME]
