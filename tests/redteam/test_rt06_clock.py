"""RT6 clock games: claimed ts/seq/tick/record_id keys in the envelope are a schema denial, and the ordering of
everyone else is identical to the same run without the claims.

THREAT-MODEL claim defended: order and time are gateway-assigned (seq, tick, ts_us), never agent-claimed.
"""

from __future__ import annotations

import pytest

from ks.contracts import Reason

from .conftest import assert_global, conn_of, world_run

ROGUE = conn_of("docs")
SRC = '''
from ks.contracts import SubmitFrame, canonical
CLAIMS = {claims}
def on_tick(ctx, t):
    if t == 5:
        env = ctx.sign_envelope("docs.write", {{"id": "D-C5", "title": "claims"}})
        if CLAIMS:
            obj = {{"type": "submit", "tick": t, "envelope": {{**env.to_obj(), "ts": 0, "seq": 1, "tick": 0,
                                                             "record_id": "r-000001"}}}}
            ctx.raw_send(canonical.dumps_line(obj), leg="claim")
        else:
            ctx.submit(env, leg="claim")
    if t == 6:
        ctx.send("docs.write", {{"id": "D-C6", "title": "t", "ts": "1970-01-01T00:00:00Z"}}, leg="args_claim")
'''


@pytest.fixture(scope="module")
def runs(base):
    return (world_run(base, "rt6a", rogue=SRC.format(claims=True), ticks=14),
            world_run(base, "rt6b", rogue=SRC.format(claims=False), ticks=14))


def test_rt6_claims_change_nothing_but_the_claim_frame(runs):
    a, b = runs
    proj = lambda run: [(r.tick, r.attributed_agent, r.envelope.tool if r.envelope else None, r.decision)
                        for r in run.records() if r.conn_id != ROGUE]
    assert proj(a) == proj(b)
    claim = [r for r in a.records() if r.conn_id == ROGUE and r.tick == 5]
    assert len(claim) == 1 and claim[0].reason == Reason.SCHEMA and claim[0].envelope is None
    recs = a.records()
    assert all(r.seq == i + 1 for i, r in enumerate(recs))
    cfg = a.dir / "config.json"
    from ks.contracts import RunDir
    c = RunDir(a.dir).config()
    assert all(r.ts_us // c.tick_us == r.tick + c.start_ts_us // c.tick_us for r in recs)  # gateway-assigned time


def test_rt6_global(runs):
    for r in runs:
        assert_global(r, rogue_conn=ROGUE)
