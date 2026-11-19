"""B3-14: ks.policy through the real gateway pipeline (step 12): scopes, read scope R2, I2 hold, class U."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ks.contracts import ActionClass, Decision, Reason
from ks.policy import TOOL_ROLES, WRITE_SCOPE, WorldPolicy, tool_access
from ks.world.agents import AGENT_IDS
from ks.world.scenario import SCOPES, seed_state
from ks.world.tools import CATALOGUE

sys.path.insert(0, str(Path(__file__).parent.parent / "gateway"))
from test_pipeline import build, frame  # noqa: E402


def seed(s, q):
    seed_state(s, seq=q)
    s.write_row("invoices:INV-1", {"supplier": "S-17", "qty": 1, "unit_price": 10, "amount": 10, "remit_iban": "x"},
                author="ks.gateway", seq=q, action_id="seed-inv")


def run(tmp_path, agent, tool, args, aid="a-1"):
    g, keys, *_ = build(tmp_path, policy=WorldPolicy(), seed=seed)
    g.open(1, AGENT_IDS)
    g.bind("c-1", agent)
    return g.admit("c-1", frame(keys, agent=agent, tool=tool, args=args, action=aid)).record


def test_tables_cover_catalogue():
    assert set(TOOL_ROLES) == set(CATALOGUE) and set(WRITE_SCOPE) == set(SCOPES)


# (agent, tool, args) that are legitimate for the role
OK = [("intake", "ticket.create", {"id": "T-1", "title": "x", "priority": "low"}),
      ("triage", "ticket.set_priority", {"id": "T-0000", "priority": "high"}),
      ("triage", "supplier.set_risk_note", {"supplier": "S-17", "note": "n"}),  # reads a supplier it cannot view
      ("crm", "crm.upsert_customer", {"id": "C-1", "tier": "std"}),
      ("billing", "billing.draft_invoice", {"id": "INV-2", "supplier": "S-17", "qty": 1}),
      ("billing", "ledger.post", {"id": "L-1", "invoice": "INV-1"}),
      ("inventory", "inventory.adjust", {"sku": "X", "delta": 1}),
      ("docs", "docs.write", {"id": "D-1", "title": "t"}),
      ("reporter", "docs.write", {"id": "RPT-1", "title": "t", "invoices": ["INV-1"]}),
      ("payments", "payments.send", {"id": "P-1", "invoice": "INV-1"}),
      ("comms", "comms.send_email", {"id": "E-1", "template": "remittance", "invoice": "INV-1"})]


@pytest.mark.parametrize("agent,tool,args", OK)
def test_scope_table_in_scope_admitted(tmp_path, agent, tool, args):
    assert WorldPolicy().decide(_env(agent, tool, args), CATALOGUE[tool][0]) is None


def _env(agent, tool, args):
    from ks.contracts import Envelope
    return Envelope(agent_id=agent, action_id="a", parent_action_id=None, act_chain=(), tool=tool, args=args,
                    nonce="0" * 32, expiry_tick=3, epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)


def test_scope_table_every_role_denied_every_foreign_tool():
    for tool, (cls, _) in CATALOGUE.items():
        for role in AGENT_IDS:
            v = WorldPolicy().decide(_env(role, tool, {"id": "RPT-1" if role != "docs" else "D-1"}), cls)
            if role in TOOL_ROLES[tool]:
                continue
            assert (v.decision, v.reason, v.rule) == (Decision.DENY, Reason.OUT_OF_SCOPE, "p.scope"), (role, tool)


def test_out_of_scope_is_a_recorded_deny_without_effects(tmp_path):
    r = run(tmp_path, "crm", "docs.purge", {"id": "D-0000"})
    assert (r.decision, r.reason, r.policy_rule, r.sig_ok) == (Decision.DENY, Reason.OUT_OF_SCOPE, "p.scope", True)
    assert not r.write_set and not r.read_set and not r.outbox_ids
    assert "D-0000" not in r.model_dump_json()  # hashes only


def test_write_table_scope_docs_cannot_write_reports_lane(tmp_path):
    r = run(tmp_path, "docs", "docs.write", {"id": "RPT-9", "title": "t"})
    assert (r.decision, r.reason) == (Decision.DENY, Reason.OUT_OF_SCOPE)


def test_r2_read_outside_view_scope_denied(tmp_path):
    # comms views invoices+suppliers, not customers: the customer_dump read is out of scope
    r = run(tmp_path, "comms", "comms.send_email", {"id": "E-2", "template": "customer_dump", "customer": "C-1"})
    assert (r.decision, r.reason, r.policy_rule) == (Decision.DENY, Reason.OUT_OF_SCOPE, "p.scope")
    # payments' view has no customers either, and reporter cannot read the ledger via a foreign tool
    assert tool_access("billing.issue_credit", {})[0] == {"customers"}


def test_row_read_lists_field_obj_gateway_side(tmp_path):
    """billing (view: suppliers with fields) reads a supplier whole-row: the record lists the iban field object.
    (payments.send reads the same way but queues an outbox item, which needs B3-23, so billing is the live path.)"""
    r = run(tmp_path, "billing", "billing.draft_invoice", {"id": "INV-2", "supplier": "S-17", "qty": 1})
    assert r.decision == Decision.EXEC
    assert "suppliers:S-17" in {e.obj for e in r.read_set} and "suppliers:S-17.iban" in {e.obj for e in r.read_set}
    assert all(any(t == "suppliers" and f for t, f, _ in SCOPES[a]) for a in ("billing", "payments"))


def test_i2_holds_needs_approval_and_nothing_runs(tmp_path):
    r = run(tmp_path, "docs", "docs.purge", {"id": "D-0000"})
    assert (r.decision, r.reason, r.policy_rule) == (Decision.HOLD, Reason.NEEDS_APPROVAL, "p.i2_approval")
    assert not r.write_set and not r.outbox_ids


def test_i1_admitted_class_u_denied(tmp_path):
    assert WorldPolicy().decide(_env("payments", "payments.send", {"id": "P", "invoice": "INV-1"}), ActionClass.I1) is None
    r = run(tmp_path, "payments", "nope.tool", {})
    assert (r.decision, r.reason) == (Decision.DENY, Reason.CLASS_U)
    v = WorldPolicy().decide(_env("payments", "payments.send", {}), ActionClass.U)
    assert (v.reason, v.rule) == (Reason.CLASS_U, "p.class_u")


def test_malformed_args_do_not_crash_policy():
    for args in ({}, {"id": 5}, {"invoices": 3}, {"customer": None}):
        for tool, (cls, _) in CATALOGUE.items():
            WorldPolicy().decide(_env("docs", tool, args), cls)
