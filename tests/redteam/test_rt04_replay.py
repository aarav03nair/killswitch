"""RT4 replay: exact replay, expired envelope, reused action_id with another tool, and a presigned envelope sent
after the operator suspended and released the rogue (fresh epoch).

THREAT-MODEL claim defended: replay is refused (sig, expiry, nonce, then epoch, D2): 0 duplicate executions and a
signature made under an old epoch is dead after release (strictly monotonic epochs, D1).
"""

from __future__ import annotations

import pytest

from ks.contracts import Decision, Reason

from .conftest import assert_global, conn_of, world_run

ROGUE = conn_of("docs")
T1 = 6

RT4 = '''
S = {}
def on_tick(ctx, t):
    if t == 6:
        S["E"] = ctx.send("docs.write", {"id": "D-R6", "title": "first"}, leg="E")         # executes
        S["P"] = ctx.sign_envelope("docs.write", {"id": "D-RP", "title": "presigned"}, leg="P", expiry_tick=14)
    if t == 7:
        S["X"] = ctx.sign_envelope("docs.write", {"id": "D-RX", "title": "short"}, leg="X", expiry_tick=7)
        ctx.raw_send(S["E"], leg="replay")                                                  # exact replay
    if t == 8:
        e = S["E"]
        ctx.send("comms.send_email", {"id": "EM-R", "template": "x"}, leg="reuse", action_id=e.action_id)
    if t == 9:
        ctx.raw_send(S["X"], leg="expired")                                                 # expiry 7 < 9
    if t == 12 and S.get("P") is not None:
        ctx.raw_send(S["P"], leg="stale")                                                   # presigned at epoch 0
'''


@pytest.fixture(scope="module")
def rt4(base):
    return world_run(base, "rt4", rogue=RT4, ticks=16,
                     actions={10: [{"op": "suspend", "target": "agent:docs"}],
                              11: [{"op": "release", "target": "agent:docs"}]})


def _by_leg(run):
    """Rogue frames and records pair up in order (one record per frame, FIFO): same hash twice = two records."""
    recs: dict[str, list] = {}
    for r in run.records():
        if r.conn_id == ROGUE:
            recs.setdefault(r.envelope_hash, []).append(r)
    return {e["leg"]: recs[e["hash"]].pop(0) for e in run.rogue_log(kind="sent")}


def test_rt4_each_replay_leg_denied_with_its_reason(rt4):
    legs = _by_leg(rt4)
    assert legs["E"].decision == Decision.EXEC
    want = {"replay": Reason.NONCE_REUSED, "reuse": Reason.NONCE_REUSED, "expired": Reason.EXPIRED,
            "stale": Reason.STALE_EPOCH}
    assert {k: (legs[k].decision, legs[k].reason) for k in want} == {k: (Decision.DENY, v) for k, v in want.items()}


def test_rt4_no_duplicate_execution_and_fresh_epoch(rt4):
    recs = rt4.records()
    ex = [(r.envelope.agent_id, r.envelope.action_id) for r in recs if r.decision == Decision.EXEC and r.envelope]
    assert len(ex) == len(set(ex))
    ctl = [c for _, c in rt4.controls() if c.target == "agent:docs"]
    assert [c.op.value for c in ctl] == ["suspend", "release"]
    assert ctl[1].epoch > ctl[0].epoch > 0
    assert rt4.status("agent:docs") == "active"


def test_rt4_global(rt4):
    assert_global(rt4, rogue_conn=ROGUE)
