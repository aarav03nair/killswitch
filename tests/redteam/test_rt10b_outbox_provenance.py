"""RT10b outbox provenance in a real run (S4-01, kabir's B3-35 mutation review: before this, disabling
``Outbox._unrecorded`` failed only gateway unit tests, no RT).

Attack: the off-gateway writer of RT1(b) (single-uid / relaxed-perms deployment; in the container an agent uid cannot
open state.db at all, RT1a) plants a QUEUED, already-due ``payments`` item straight into ``state.db`` while the run is
paused. No record created it.

THREAT-MODEL claims defended: an effect leaves only through ``ks.dispatch`` for an item its creating record accounts
for (ADR-04 §5, F4); an item no record created is held (``unrecorded_item``), never dispatched, and never pinned on an
honest agent.
"""

from __future__ import annotations

import pytest

from ks.contracts import Decision, OutboxItem, OutboxStatus

from .conftest import AGENTS, world_run

T_PLANT = 6
OID = "ob-990001"


def _plant(run_dir):
    from ks.runtime.operator import operator_request
    from ks.state.store import open_store
    store = open_store(run_dir / "workspace" / "state.db")
    try:
        seq = store.conn.execute("SELECT MAX(seq) FROM versions").fetchone()[0] or 1
        it = OutboxItem(outbox_id=OID, author="payments", action_id="forged-1", created_seq=1, sink="payments",
                        action_class="I1", payload_hash="0" * 64, idempotency_key="f" * 64, lineage=(),
                        status=OutboxStatus.QUEUED, release_tick=0, dispatched_seq=None)
        store.conn.execute("BEGIN IMMEDIATE")
        store.put(f"outbox:{OID}", it.to_obj(), author="payments", seq=seq, action_id="forged-1")
        store.conn.execute("COMMIT")
    finally:
        store.conn.close()
    return operator_request(run_dir, {"op": "resume"})


@pytest.fixture(scope="module")
def planted(base):
    return world_run(base, "rt10b", seed=2, ticks=12, actions={T_PLANT: [_plant]})


def test_rt10b_offlog_outbox_item_is_held_never_dispatched(planted):
    recs = planted.records()
    disp = [r for r in recs if r.envelope is not None and r.envelope.tool == "ks.dispatch"
            and (OID in r.outbox_ids or any(w.obj == f"outbox:{OID}" for w in r.write_set))]
    assert disp == [], disp  # mutation: Outbox._unrecorded -> False makes this dispatch
    holds = [(r, c) for r, c in planted.controls() if c.reason == "unrecorded_item" and OID in c.target]
    assert holds and holds[0][0].tick == T_PLANT, planted.controls()
    # no honest agent attributed for the planted item: the hold is a gateway control, not an agent action
    assert not [r for r in recs if r.attributed_agent == "payments" and r.envelope is not None
                and r.envelope.action_id == "forged-1"]
    assert all(planted.status(f"agent:{a}") == "active" for a in AGENTS)
    assert not [r for r in recs if r.decision == Decision.EXEC and r.envelope is not None
                and r.envelope.tool == "ks.dispatch" and r.tick >= T_PLANT
                and any(w.obj == f"outbox:{OID}" for w in r.write_set)]
