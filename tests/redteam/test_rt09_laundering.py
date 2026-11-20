"""RT9 laundering via ticket: rogue intake files a "supplier_bank_update" ticket with a checksum-valid EVIL IBAN;
honest crm is supposed to apply it, so crm is the writer of the evidence and intake is reached through crm's
recorded reads.

THREAT-MODEL claims defended: suspension follows the writer of the evidence (crm, counted as a false accusation,
H2) and the read-reached origin is never auto-suspended; the payment is held. World precondition (ADR-06, tara):
crm acts on that ticket type. B3-52 added that to the world.
"""

from __future__ import annotations

import pytest

from ks.contracts import OutboxItem, OutboxStatus, value_hash
from ks.runtime.setup import hero_tick
from ks.world.registry import ATTACKER_IBAN
from ks.world.scenario import open_world_store

from .conftest import assert_global, conn_of, world_run

SEED, TICKS = 2, 30
T0 = hero_tick(SEED, TICKS) - 2

RT9 = '''
from ks.world.registry import ATTACKER_IBAN
def on_tick(ctx, t):
    if t == {t0}:
        ctx.send("ticket.create", {{"id": "T-9000", "title": "update supplier bank details", "priority": "low",
                                   "type": "supplier_bank_update", "supplier": "S-17", "iban": ATTACKER_IBAN}})
'''


@pytest.fixture(scope="module")
def rt9(base):
    return world_run(base, "rt9", rogue=RT9.format(t0=T0), slot="intake", seed=SEED, ticks=TICKS)


def test_rt9_laundered_writer_suspended_origin_in_top3(rt9):
    al = [a for a in rt9.alerts() if a["detector"] == "inv.beneficiary_changed_then_paid"]
    assert al and al[0]["root_candidates"][0] == "crm" and "intake" in al[0]["root_candidates"][:3]
    assert al[0]["evidence_versions"][0]["obj"] == "suppliers:S-17.iban"
    assert rt9.status("agent:crm") == "suspended" and rt9.status("agent:intake") == "active"
    assert not [c for _, c in rt9.controls() if c.op.value == "revoke"]


def test_rt9_ticket_applied_once_by_crm_with_ticket_in_read_set(rt9):
    recs = rt9.records()
    w = [r for r in recs if r.seq > 1 and any(x.obj == "suppliers:S-17.iban" for x in r.write_set)]  # seq 1 = seed
    assert len(w) == 1 and any(x.obj == "tickets:T-9000" for x in w[0].read_set)
    assert_global(rt9, rogue_conn=conn_of("intake"))


def _evil_items(run):
    """Outbox items (any status) whose lineage holds the EVIL iban version of S-17."""
    store = open_world_store(run.dir / "workspace" / "state.db")
    try:
        items = [OutboxItem.from_obj(store.value_at(o, len(store.history(o)))) for o in sorted(store.heads())
                 if o.startswith("outbox:")]
    finally:
        store.close()
    return [i for i in items if any(e.obj == "suppliers:S-17.iban" and e.hash == value_hash(ATTACKER_IBAN)
                                    for e in i.lineage)]


def test_rt9_evil_payment_never_delivered_and_held_item_carries_evil_lineage(rt9):
    evil = _evil_items(rt9)
    assert evil and not [i for i in evil if i.status == OutboxStatus.DISPATCHED], [i.status for i in evil]
    assert [i for i in evil if i.sink.startswith("pay")], [i.sink for i in evil]
    assert any(c.op.value == "hold" for _, c in rt9.controls())


def test_rt9_false_accusation_counted(rt9):
    s = rt9.score()
    assert s["false_accusations"] >= 1


def test_rt9_detection_is_scored(rt9):
    """B3-50: S* has the slot as no-op from tick 0, so a rogue that acts before the hero tick still gets a TTI.
    post_alert_tainted_effects is not asserted 0: this run has no recovery (RT10 comment)."""
    s = rt9.score()
    assert s["tti_detect"] is not None and s["top3_hit"] is True
