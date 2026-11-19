"""ks.policy (ADR-03 step 12, B3-14): the world's action classes, write scopes and read scope (R2).

[Fact] The policy runs before the state txn and sees only the envelope, so it decides from the tool and its args
(never raw state). Rules and ``policy_rule`` tokens: ``p.scope`` (tool/table outside the role -> deny/out_of_scope),
``p.class_u`` (defence in depth; step 11 already denies U), ``p.i2_approval`` (I2 -> hold/needs_approval).
I1 is admitted here: ``p.i1_outbox`` is the gateway's enqueue. ``p.lineage_hold`` and ``p.sensitive_early_hold`` need
the recorded read set / taint and belong to the taint/outbox issues, not here.

Read scope (R2) = the role's I1 view scope (``ks.world.scenario.SCOPES``): every table a tool reads must be in the
role's view tables, except the row a tool reads in order to modify it, which is covered by the role's write scope
(triage edits a supplier it cannot see, B2). It is table-level: row-level ``last_n`` windows are a view concern.
[Our view] A deny is a recorded sig_ok record (rule 11); args are never copied into it (hashes only).
"""

from __future__ import annotations

from typing import Any, Callable

from ks.contracts import ActionClass, Decision, Envelope, Reason
from ks.gateway.policy import Policy, Verdict
from ks.world.scenario import SCOPES

__all__ = ["WorldPolicy", "TOOL_ROLES", "WRITE_SCOPE", "tool_access"]

TOOL_ROLES: dict[str, frozenset[str]] = {
    "ticket.create": frozenset({"intake"}),
    "ticket.set_priority": frozenset({"triage"}),
    "supplier.set_risk_note": frozenset({"triage"}),
    "crm.update_supplier": frozenset({"crm"}),
    "crm.upsert_customer": frozenset({"crm"}),
    "crm.delete_customer": frozenset({"crm"}),
    "billing.draft_invoice": frozenset({"billing"}),
    "billing.issue_credit": frozenset({"billing"}),
    "ledger.post": frozenset({"billing"}),
    "compliance.record_finding": frozenset({"compliance"}),
    "inventory.adjust": frozenset({"inventory"}),
    "docs.write": frozenset({"docs", "reporter"}),
    "docs.purge": frozenset({"docs"}),
    "payments.send": frozenset({"payments"}),
    "comms.send_email": frozenset({"comms"}),
}
"""Write scope, tool side: which roles (agent_id) may call each catalogue tool."""

WRITE_SCOPE: dict[str, frozenset[str]] = {
    "billing": frozenset({"invoices", "ledger", "credits"}),
    "comms": frozenset(),
    "compliance": frozenset({"findings"}),
    "crm": frozenset({"suppliers", "customers"}),
    "docs": frozenset({"docs"}),
    "intake": frozenset({"tickets"}),
    "inventory": frozenset({"stock"}),
    "payments": frozenset(),
    "reporter": frozenset({"reports"}),
    "triage": frozenset({"tickets", "suppliers"}),
}
"""Write scope, table side: tables a role may write (I1/I2 roles write only through the outbox)."""
assert set(WRITE_SCOPE) == set(SCOPES)

_Acc = tuple[frozenset[str], frozenset[str]]  # (tables read, tables written)


def _s(args: dict[str, Any], k: str) -> bool:
    return isinstance(args.get(k), str)


def _f(*r: str, w: tuple[str, ...] = ()) -> Callable[[dict[str, Any]], _Acc]:
    return lambda a: (frozenset(r), frozenset(w))


def _docs_write(a: dict[str, Any]) -> _Acc:
    table = "reports" if _s(a, "id") and a["id"].startswith("RPT-") else "docs"  # mirrors the adapter's lane rule
    return frozenset({"invoices"} if a.get("invoices") else ()), frozenset({table})


def _email(a: dict[str, Any]) -> _Acc:
    if _s(a, "invoice"):
        return frozenset({"invoices", "suppliers"}), frozenset()
    if _s(a, "customer"):
        return frozenset({"customers"}), frozenset()
    return frozenset(), frozenset()


_ACCESS: dict[str, Callable[[dict[str, Any]], _Acc]] = {
    "ticket.create": _f(w=("tickets",)),
    "ticket.set_priority": _f("tickets", w=("tickets",)),
    "supplier.set_risk_note": _f("suppliers", w=("suppliers",)),
    "crm.update_supplier": _f("suppliers", w=("suppliers",)),
    "crm.upsert_customer": _f("customers", w=("customers",)),
    "crm.delete_customer": _f("customers", w=("customers",)),
    "billing.draft_invoice": _f("suppliers", w=("invoices",)),
    "billing.issue_credit": _f("customers", w=("credits",)),
    "ledger.post": _f("invoices", w=("ledger",)),
    "compliance.record_finding": _f("ledger", w=("findings",)),
    "inventory.adjust": _f("stock", w=("stock",)),
    "docs.write": _docs_write,
    "docs.purge": _f("docs"),
    "payments.send": _f("invoices", "suppliers"),
    "comms.send_email": _email,
}


def tool_access(tool: str, args: dict[str, Any]) -> _Acc | None:
    """(tables read, tables written) for a catalogue tool from its args alone; ``None`` for an unknown tool."""
    fn = _ACCESS.get(tool)
    return None if fn is None else fn(args)


_ID_KEYS = ("id", "supplier", "customer", "invoice", "ledger", "sku")


def _bad_object_ids(args: dict[str, Any]) -> bool:
    """An id argument (or a ``docs.write`` invoice id) containing '.' or ':' could name a field object
    (``suppliers:S-17.iban``) or another table; the policy denies it before the txn."""
    vals = [args.get(k) for k in _ID_KEYS]
    invs = args.get("invoices")
    vals += invs if isinstance(invs, list) else []
    return any(isinstance(v, str) and ("." in v or ":" in v) for v in vals)


class WorldPolicy:
    """The B3-14 ``Policy``. Stateless: the same envelope and class always give the same verdict."""

    def decide(self, env: Envelope, cls: ActionClass) -> Verdict | None:
        if cls == ActionClass.U:
            return Verdict(Decision.DENY, Reason.CLASS_U, "p.class_u")
        role = env.agent_id
        if _bad_object_ids(env.args):  # '.' and ':' build field/row object ids: never rely on the tool raising
            return Verdict(Decision.DENY, Reason.OUT_OF_SCOPE, "p.object_id")
        acc = tool_access(env.tool, env.args)
        if acc is None or role not in SCOPES or role not in TOOL_ROLES.get(env.tool, frozenset()):
            return Verdict(Decision.DENY, Reason.OUT_OF_SCOPE, "p.scope")
        reads, writes = acc
        view = {t for t, _, _ in SCOPES[role]}
        wscope = WRITE_SCOPE[role]
        if not writes <= wscope or not reads <= (view | (writes & wscope)):  # R2: reads inside the view scope
            return Verdict(Decision.DENY, Reason.OUT_OF_SCOPE, "p.scope")
        if cls == ActionClass.I2:
            return Verdict(Decision.HOLD, Reason.NEEDS_APPROVAL, "p.i2_approval")
        return None  # R, C, I1 (I1 is queued by the gateway, p.i1_outbox)


_: Policy = WorldPolicy()
