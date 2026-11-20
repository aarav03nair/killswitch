"""B3-32 (F8): per-connection denial budget, bounded reader, flood suspend of the connection (not the agent)."""

from __future__ import annotations

import time

from ks.contracts import MAX_FRAME_BYTES, Decision, Reason, SYSTEM_CONN, raw_hash
from ks.gateway import InFrame
from ks.gateway.control import FoldedControl
from ks.gateway.stub import FLOOD_K
from ks.world.agents import AGENT_IDS

from .test_pipeline import A, build, frame


def _flooded_gateway(tmp_path):
    g, keys, ctl, store, ring = build(tmp_path)
    g.control = FoldedControl(AGENT_IDS)
    return g, keys


def test_10k_frame_flood_adds_at_most_k_plus_1_records(tmp_path):
    g, keys = _flooded_gateway(tmp_path)
    g.open(1, AGENT_IDS)
    before = g.recorder.seq
    t0 = time.monotonic()
    out = g.tick(1, [InFrame(A, "c-1", b"garbage\n") for _ in range(10_000)])
    assert time.monotonic() - t0 < 30
    recs = [r for r in g.recorder.rundir.records() if r.seq > before]
    assert len(recs) == FLOOD_K + 1 and len(out) == FLOOD_K
    assert [r.reason for r in recs[:FLOOD_K]] == [Reason.SCHEMA] * FLOOD_K
    ctl = recs[-1]
    assert ctl.conn_id == SYSTEM_CONN and ctl.control.target == "conn:c-1" and ctl.control.reason == "flood"
    assert ctl.control.issued_by == "ks.gateway" and ctl.decision == Decision.EXEC
    assert g.flood_dropped == 10_000 - FLOOD_K and g.flooded == {"c-1"}
    assert g.control.conn_denial("c-1") == Reason.SUSPENDED
    assert g.control.agent_denial(A) is None and g.control.epoch_of(A) == 0  # the agent is not suspended
    g.open(2, AGENT_IDS)
    assert g.flooded == set() and g.flood_dropped == 10_000 - FLOOD_K  # budget resets, counter is cumulative


def test_exactly_k_denials_is_not_a_flood(tmp_path):
    g, keys = _flooded_gateway(tmp_path)
    g.open(1, AGENT_IDS)
    g.tick(1, [InFrame(A, "c-1", b"x\n") for _ in range(FLOOD_K)])
    assert g.flooded == set() and g.flood_dropped == 0


def test_oversize_prefix_is_deny_schema_with_raw_hash_of_prefix(tmp_path):
    g, keys = _flooded_gateway(tmp_path)
    g.open(1, AGENT_IDS)
    prefix = b"a" * (MAX_FRAME_BYTES + 1)
    adm = g.admit("c-1", prefix)
    assert (adm.record.decision, adm.record.reason) == (Decision.DENY, Reason.SCHEMA)
    assert adm.record.envelope_hash == raw_hash(prefix)


def test_honest_conn_unaffected_by_flooder(tmp_path):
    g, keys = _flooded_gateway(tmp_path)
    g.bind("c-2", "crm")
    g.open(1, AGENT_IDS)
    ok = frame(keys, agent="crm", tool="ticket.set_priority", action="a-9")
    out = g.tick(1, [InFrame(A, "c-1", b"x\n") for _ in range(50)] + [InFrame("crm", "c-2", ok)])
    assert "c-2" in {c for c, _ in out} and g.flooded == {"c-1"}
