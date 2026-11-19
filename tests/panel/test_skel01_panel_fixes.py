"""B3-36: SKEL-01 Panel fixes M1 (late final ack anchor), M2 (signer flood caps), S3 (agent_id vs connection),
S2 (unprivileged shared uid). Tests that need Linux root are skipped elsewhere, never faked."""

from __future__ import annotations

import os
import socket
import sys
import time

import pytest

from ks.contracts import Decision, Reason, RunAnchor
from ks.identity import SignerService
from ks.identity.signer import MAX_SIGNER_LINES_PER_TICK
from ks.runtime.barrier import AgentConn, TickBarrier
from ks.runtime.spawn import SHARED_AGENT_UID, plan_agent_uids
from ks.verify import verify

from tests.skeleton.test_units import AGENTS, _frame, _NoWitness, gw  # noqa: F401  (fixture)

LINUX_ROOT = sys.platform == "linux" and os.geteuid() == 0


# --- M1 --------------------------------------------------------------------------------------------------------
def test_late_final_ack_anchor_equals_newest_checkpoint_and_head_verifies(tmp_path, monkeypatch):
    import ks.runtime.run as runmod
    real = runmod.WitnessLink.push
    last_tick = 7

    def push(self, seq, head, tick, timeout_s):  # the final tick's ack misses its deadline
        return real(self, seq, head, tick, 0.0 if tick == last_tick else timeout_s)

    monkeypatch.setattr(runmod.WitnessLink, "push", push)
    res = runmod.run(agents=2, ticks=8, seed=5, key_mode="fresh", out=tmp_path / "r", tick_deadline_ms=400,
                     say=lambda s: None)
    cps = list(res.rundir.witness())
    assert cps[-1].tick == last_tick, "the witness did write the final tick (ack was only late)"
    assert res.stalls >= 1
    assert isinstance(res.anchor, RunAnchor)
    assert (res.anchor.seq, res.anchor.head, res.anchor.tick, res.anchor.count) == (
        cps[-1].seq, cps[-1].head, cps[-1].tick, cps[-1].count)
    rep = verify(res.rundir.path, res.anchor)
    assert rep.ok and rep.anchored, rep


# --- M2 --------------------------------------------------------------------------------------------------------
def test_signer_flood_counts_refusals_and_budgets_lines(gw):  # noqa: F811
    _, keys = gw
    s = SignerService({a: keys.private(a) for a in AGENTS}, {a: 0 for a in AGENTS}.get)
    s.begin_tick(1)
    replies = [s.handle("agent_00", b"junk\n") for _ in range(MAX_SIGNER_LINES_PER_TICK + 500)]
    assert replies[:MAX_SIGNER_LINES_PER_TICK] == [replies[0]] * MAX_SIGNER_LINES_PER_TICK and replies[0] is not None
    assert all(r is None for r in replies[MAX_SIGNER_LINES_PER_TICK:])
    assert s.refusals[("agent_00", "schema")] == MAX_SIGNER_LINES_PER_TICK       # counted
    assert s.flooded["agent_00"] == 500
    assert len(s.refusals) == 1 and not hasattr(s.refusals, "append")            # a counter, never a list
    s.begin_tick(2)
    assert s.handle("agent_00", b"junk\n") is not None                            # budget is per tick


def test_signer_flood_closes_the_connection_and_the_tick_stays_bounded(gw):  # noqa: F811
    g, keys = gw
    pairs = [socket.socketpair() for _ in range(4)]
    conns = [AgentConn(index=i, agent_id=a, conn_id=f"c-{i + 1}", gw=pairs[2 * i][0], signer=pairs[2 * i + 1][0],
                       proc=None, uid=None) for i, a in enumerate(AGENTS)]
    signer = SignerService({a: keys.private(a) for a in AGENTS}, {a: 0 for a in AGENTS}.get)
    b = TickBarrier(conns, g, signer, _NoWitness(), deadline_s=1.0)
    rogue_signer, rogue_gw = pairs[1][1], pairs[0][1]
    rogue_signer.setblocking(False)
    flood = b"junk\n" * 12000                                                    # ~60 KB, ~12k lines in one read
    try:
        rogue_signer.send(flood)
    except BlockingIOError:
        pass
    pairs[2][1].sendall(_frame(keys, agent="agent_01", tick=0, action="ok", nonce="1" * 32))  # honest agent_01
    t0 = time.monotonic()
    o = b.run_tick(0)
    assert time.monotonic() - t0 < 0.9, "a flood must not stall the tick up to its deadline"
    assert not conns[0].alive and conns[1].alive                                  # only the flooder is closed
    assert sum(signer.refusals.values()) <= MAX_SIGNER_LINES_PER_TICK
    assert o.records == 1                                                          # agent_01's frame still admitted
    rogue_gw.settimeout(2)
    while rogue_gw.recv(65536):                                                    # drains the TickFrame, then EOF
        pass


# --- S3 --------------------------------------------------------------------------------------------------------
def test_envelope_agent_id_must_match_the_connection(gw):  # noqa: F811
    g, keys = gw
    from ks.gateway import InFrame
    g.open(1, ["agent_00", "agent_01"])
    # agent_01's own validly signed envelope arrives on agent_00's connection (c-1)
    line = _frame(keys, agent="agent_01", tick=1, action="x1")
    (_, reply), = g.tick(1, [InFrame("agent_00", "c-1", line)])
    assert (reply.decision, reply.reason) == (Decision.DENY, Reason.BAD_SIG)
    rec = list(g.recorder.rundir.records())[-1]
    assert rec.sig_ok is False and rec.conn_id == "c-1"
    # the honest path on its own connection still executes
    (_, ok), = g.tick(1, [InFrame("agent_01", "c-2", _frame(keys, agent="agent_01", tick=1, action="x2"))])
    assert (ok.decision, ok.reason) == (Decision.EXEC, Reason.OK)


# --- S2 --------------------------------------------------------------------------------------------------------
def test_uid_plan_never_runs_agents_as_root():
    assert plan_agent_uids(False, False, 3) == [None, None, None]                  # not root: our own uid
    shared = plan_agent_uids(True, False, 3)
    assert shared == [SHARED_AGENT_UID] * 3 and 0 not in shared                    # --shared-uid as root
    sep = plan_agent_uids(True, True, 3)
    assert len(set(sep)) == 3 and 0 not in sep


@pytest.mark.skipif(not LINUX_ROOT, reason="needs Linux root: real uids")
def test_shared_uid_run_as_root_uses_one_unprivileged_uid(tmp_path):
    """UNEXECUTED on macOS (container only)."""
    import ks.runtime.run as runmod
    out = []
    res = runmod.run(agents=2, ticks=4, seed=1, key_mode="fresh", out=tmp_path / "r", separate_uids=False,
                     say=out.append)
    uids = set(res.isolation.agent_uids.values())
    assert uids == {SHARED_AGENT_UID} and 0 not in uids
    assert any("DEGRADED" in l for l in out) and any("per-agent attribution is VOID" in l for l in out)
    assert verify(res.rundir.path, res.anchor).ok


# --- B3-42 -----------------------------------------------------------------------------------------------------
def test_signer_drip_without_newline_counts_and_closes_and_the_tick_stays_bounded(gw):  # noqa: F811
    import threading
    g, keys = gw
    pairs = [socket.socketpair() for _ in range(4)]
    conns = [AgentConn(index=i, agent_id=a, conn_id=f"c-{i + 1}", gw=pairs[2 * i][0], signer=pairs[2 * i + 1][0],
                       proc=None, uid=None) for i, a in enumerate(AGENTS)]
    signer = SignerService({a: keys.private(a) for a in AGENTS}, {a: 0 for a in AGENTS}.get)
    b = TickBarrier(conns, g, signer, _NoWitness(), deadline_s=1.0)
    drip = pairs[1][1]
    stop = threading.Event()

    def dripper():  # one byte per ms, never a newline
        try:
            while not stop.is_set():
                drip.send(b"x")
                time.sleep(0.001)
        except OSError:
            pass

    th = threading.Thread(target=dripper, daemon=True)
    th.start()
    pairs[2][1].sendall(_frame(keys, agent="agent_01", tick=0, action="ok", nonce="1" * 32))
    t0 = time.monotonic()
    o = b.run_tick(0)
    stop.set()
    th.join(2)
    assert time.monotonic() - t0 < 0.9, "a drip must not hold the tick to its deadline"
    assert not conns[0].alive and conns[1].alive
    assert signer.flooded["agent_00"] >= 1 and o.records == 1


def test_envelope_on_a_connection_with_no_bound_agent_is_denied(gw):  # noqa: F811
    g, keys = gw
    g.open(1, ["agent_00"])
    line = _frame(keys, agent="agent_00", tick=1, action="u1")
    adm = g.admit("c-9", line)                                   # c-9 was never bound by the barrier
    assert (adm.reply.decision, adm.reply.reason) == (Decision.DENY, Reason.BAD_SIG)
    assert adm.record.sig_ok is False
