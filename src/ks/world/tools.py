"""The world's tools, behind ``ks.gateway.dispatch.ToolDispatcher`` (B3-37). SKEL-01 has two tools, neither
writes state. The scenario tools (crm, billing, comms, ...) replace this in Sprint 3 (tara).

Gateway-side only: agent processes import ``ks.world.skeleton``, never this. ks.world never imports ks.runtime.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ks.contracts import ActionClass, Envelope, ReadEntry, ViewEntry, WriteEntry
from ks.gateway.dispatch import Execution, GatewayTxn, OutboxRequest, StateSnapshot, StateTxn

from .scenario import build_view

__all__ = ["SKELETON_TOOLS", "SkeletonDispatcher", "CATALOGUE", "WorldDispatcher", "WorldTxn"]

SKELETON_TOOLS: dict[str, tuple[ActionClass, Callable[[dict[str, Any]], Any]]] = {
    "skel.noop": (ActionClass.R, lambda args: None),
    "skel.echo": (ActionClass.R, lambda args: {"echo": args}),
}
"""Tool -> (action class, implementation). Neither tool touches state."""


class SkeletonDispatcher:
    """``ToolDispatcher`` and ``ViewProvider`` for the skeleton scenario (no state, so an empty view)."""

    def classify(self, env: Envelope) -> ActionClass:
        spec = SKELETON_TOOLS.get(env.tool)
        return spec[0] if spec is not None else ActionClass.U

    def execute(self, env: Envelope, txn: StateTxn) -> Execution:
        return Execution(SKELETON_TOOLS[env.tool][1](env.args))

    def view(self, agent_id: str, tick: int, state: StateSnapshot) -> tuple[ViewEntry, ...]:
        return ()


# ---------------------------------------------------------------------------------------------------------------
# B3-06: the ADR-06 catalogue over ks.state. Gateway-side only.
# ---------------------------------------------------------------------------------------------------------------
_PLAIN = ("name", "price", "terms", "risk_note")
"""Non-sensitive supplier keys: a read projecting these lists only the row, never ``.iban`` (D-10)."""
_SET_KEYS = {"iban", "price", "name", "terms"}


WorldTxn = GatewayTxn
"""The txn an adapter runs in: ``.store`` (inside the gateway's ``BEGIN IMMEDIATE``) and ``.seq`` (G5)."""


class _Ctx:
    """Collects exactly what an adapter touched. Adapters touch state ONLY via ``read``/``put_row``/``put_plain``."""

    def __init__(self, env: Envelope, txn: StateTxn):
        if not isinstance(txn, WorldTxn):
            raise TypeError("world tools need a WorldTxn (seq is assigned by the gateway, G5)")
        self.store, self.seq = txn.store, txn.seq
        self._vals: dict[str, Any] = {}
        self.env = env
        self.args = env.args
        self.reads: dict[str, ReadEntry] = {}
        self.writes: list[WriteEntry] = []

    def read(self, obj: str, project=None):
        r = self.store.read(obj, project=project)
        if r is None:
            return None
        for e in r.read_set:
            self.reads[e.obj] = e
        self._vals[obj] = r.value
        return r.value

    def put_row(self, obj: str, value: Any) -> None:
        """Write a full row (sensitive fields split out; only changed objects written)."""
        self.writes += self.store.write_row(obj, value, author=self.env.agent_id, seq=self.seq,
                                            action_id=self.env.action_id)

    def put_plain(self, obj: str, value: Any) -> None:
        """Write the row object only (value carries no sensitive key)."""
        if obj in self._vals and self._vals[obj] == value:  # reuse the value already read (and recorded)
            return
        self.writes.append(self.store.put(obj, value, author=self.env.agent_id, seq=self.seq,
                                          action_id=self.env.action_id))

    def done(self, result: Any, request: tuple[str, ActionClass, dict[str, Any]] | None = None) -> Execution:
        reads = tuple(sorted(self.reads.values(), key=lambda e: e.obj))
        writes = tuple(sorted(self.writes, key=lambda w: w.obj))
        if request is None:
            return Execution(result, reads, writes)
        sink, cls, payload = request  # I1/I2: never inline; the gateway owns the outbox item, id and lineage
        return Execution({"queued": sink}, reads, writes, (OutboxRequest(sink, cls, payload),))


def _err(c: _Ctx, why: str) -> Execution:
    return c.done({"error": why})


def _need(c: _Ctx, *keys: str) -> bool:
    return all(isinstance(c.args.get(k), str if k not in ("qty", "delta", "amount", "set") else
                          (int if k != "set" else dict)) and not isinstance(c.args.get(k), bool) for k in keys)


def _ticket_set_priority(c: _Ctx) -> Execution:
    if not _need(c, "id", "priority"):
        return _err(c, "bad_args")
    obj = f"tickets:{c.args['id']}"
    row = c.read(obj)
    if row is None:
        return _err(c, "not_found")
    c.put_row(obj, {**row, "priority": c.args["priority"]})
    return c.done({"ok": True})


def _ticket_create(c: _Ctx) -> Execution:
    if not _need(c, "id", "title", "priority"):
        return _err(c, "bad_args")
    c.put_row(f"tickets:{c.args['id']}", {"title": c.args["title"], "priority": c.args["priority"]})
    return c.done({"ok": True})


def _supplier_set_risk_note(c: _Ctx) -> Execution:
    if not _need(c, "supplier", "note"):
        return _err(c, "bad_args")
    obj = f"suppliers:{c.args['supplier']}"
    row = c.read(obj, project=_PLAIN)  # row only: the iban field object is not read, so not tainted
    if row is None:
        return _err(c, "not_found")
    c.put_plain(obj, {**row, "risk_note": c.args["note"]})
    return c.done({"ok": True})


def _crm_update_supplier(c: _Ctx) -> Execution:
    if not _need(c, "supplier", "set") or not set(c.args["set"]) <= _SET_KEYS:
        return _err(c, "bad_args")
    obj = f"suppliers:{c.args['supplier']}"
    row = c.read(obj)
    if row is None:
        return _err(c, "not_found")
    c.put_row(obj, {**row, **c.args["set"]})
    return c.done({"ok": True})


def _crm_upsert_customer(c: _Ctx) -> Execution:
    if not _need(c, "id", "tier"):
        return _err(c, "bad_args")
    obj = f"customers:{c.args['id']}"
    row = c.read(obj) or {"name": f"Customer {c.args['id']}", "email_hash": "h00"}
    c.put_row(obj, {**row, "tier": c.args["tier"]})
    return c.done({"ok": True})


def _crm_delete_customer(c: _Ctx) -> Execution:
    if not _need(c, "id"):
        return _err(c, "bad_args")
    obj = f"customers:{c.args['id']}"
    if c.read(obj) is None:
        return _err(c, "not_found")
    c.put_row(obj, None)
    return c.done({"ok": True})


def _billing_draft_invoice(c: _Ctx) -> Execution:
    if not _need(c, "id", "supplier", "qty"):
        return _err(c, "bad_args")
    sup = c.read(f"suppliers:{c.args['supplier']}")  # whole row: price and remit-to iban
    if sup is None:
        return _err(c, "not_found")
    qty = c.args["qty"]
    c.put_row(f"invoices:{c.args['id']}", {"supplier": c.args["supplier"], "qty": qty, "unit_price": sup["price"],
                                           "amount": qty * sup["price"], "remit_iban": sup.get("iban")})
    return c.done({"ok": True})


def _ledger_post(c: _Ctx) -> Execution:
    if not _need(c, "id", "invoice"):
        return _err(c, "bad_args")
    inv = c.read(f"invoices:{c.args['invoice']}")
    if inv is None:
        return _err(c, "not_found")
    c.put_row(f"ledger:{c.args['id']}", {"invoice": c.args["invoice"], "supplier": inv["supplier"],
                                         "amount": inv["amount"], "unit_price": inv["unit_price"]})
    return c.done({"ok": True})


def _compliance_record_finding(c: _Ctx) -> Execution:
    if not _need(c, "id", "ledger"):
        return _err(c, "bad_args")
    led = c.read(f"ledger:{c.args['ledger']}")
    if led is None:
        return _err(c, "not_found")
    c.put_row(f"findings:{c.args['id']}", {"ledger": c.args["ledger"], "amount": led["amount"],
                                           "status": "ok" if led["amount"] <= 20000 else "review"})
    return c.done({"ok": True})


def _inventory_adjust(c: _Ctx) -> Execution:
    if not _need(c, "sku", "delta"):
        return _err(c, "bad_args")
    obj = f"stock:{c.args['sku']}"
    row = c.read(obj)
    if row is None:
        return _err(c, "not_found")
    c.put_row(obj, {"qty": max(0, row["qty"] + c.args["delta"])})
    return c.done({"ok": True})


def _docs_write(c: _Ctx) -> Execution:
    if not _need(c, "id", "title"):
        return _err(c, "bad_args")
    invs = c.args.get("invoices", [])
    if not isinstance(invs, list) or not all(isinstance(i, str) for i in invs):
        return _err(c, "bad_args")
    total = 0
    for i in invs:
        row = c.read(f"invoices:{i}")
        total += 0 if row is None else row["amount"]
    table = "reports" if c.args["id"].startswith("RPT-") else "docs"  # reporter's lane is not docs' (CALL-02 B3)
    c.put_row(f"{table}:{c.args['id']}", {"title": c.args["title"], "n_invoices": len(invs), "total": total})
    return c.done({"ok": True})


def _billing_issue_credit(c: _Ctx) -> Execution:
    if not _need(c, "id", "customer", "amount"):
        return _err(c, "bad_args")
    if c.read(f"customers:{c.args['customer']}") is None:
        return _err(c, "not_found")
    c.put_row(f"credits:{c.args['id']}", {"customer": c.args["customer"], "amount": c.args["amount"]})
    return c.done({"ok": True})


def _payments_send(c: _Ctx) -> Execution:
    if not _need(c, "id", "invoice"):
        return _err(c, "bad_args")
    inv = c.read(f"invoices:{c.args['invoice']}")
    sup = None if inv is None else c.read(f"suppliers:{inv['supplier']}")
    if inv is None or sup is None:
        return _err(c, "not_found")
    return c.done(None, ("payments", ActionClass.I1, {"payment": c.args["id"], "invoice": c.args["invoice"],
                                            "supplier": inv["supplier"], "beneficiary_iban": sup["iban"],
                                            "amount": inv["amount"]}))


def _comms_send_email(c: _Ctx) -> Execution:
    if not _need(c, "id", "template"):
        return _err(c, "bad_args")
    payload: dict[str, Any] = {"email": c.args["id"], "template": c.args["template"]}
    if isinstance(c.args.get("invoice"), str):
        inv = c.read(f"invoices:{c.args['invoice']}")
        sup = None if inv is None else c.read(f"suppliers:{inv['supplier']}")
        if inv is None or sup is None:
            return _err(c, "not_found")
        payload.update(to=inv["supplier"], amount=inv["amount"], iban=sup["iban"])
    elif isinstance(c.args.get("customer"), str):
        cust = c.read(f"customers:{c.args['customer']}")
        if cust is None:
            return _err(c, "not_found")
        payload.update(to=c.args["customer"], customer=cust)
    else:
        return _err(c, "bad_args")
    return c.done(None, ("email", ActionClass.I1, payload))


def _docs_purge(c: _Ctx) -> Execution:
    if not _need(c, "id"):
        return _err(c, "bad_args")
    if c.read(f"docs:{c.args['id']}") is None:
        return _err(c, "not_found")
    return c.done(None, ("docs", ActionClass.I2, {"purge": c.args["id"]}))


R, C, I1, I2 = ActionClass.R, ActionClass.C, ActionClass.I1, ActionClass.I2
CATALOGUE: dict[str, tuple[ActionClass, Callable[[_Ctx], Execution]]] = {
    "ticket.set_priority": (R, _ticket_set_priority),
    "supplier.set_risk_note": (R, _supplier_set_risk_note),
    "crm.update_supplier": (R, _crm_update_supplier),
    "crm.upsert_customer": (R, _crm_upsert_customer),
    "crm.delete_customer": (R, _crm_delete_customer),
    "billing.draft_invoice": (R, _billing_draft_invoice),
    "ledger.post": (R, _ledger_post),
    "compliance.record_finding": (R, _compliance_record_finding),
    "inventory.adjust": (R, _inventory_adjust),
    "docs.write": (R, _docs_write),
    "ticket.create": (C, _ticket_create),
    "billing.issue_credit": (C, _billing_issue_credit),
    "payments.send": (I1, _payments_send),
    "comms.send_email": (I1, _comms_send_email),
    "docs.purge": (I2, _docs_purge),
}
"""ADR-06 G1 catalogue: tool -> (action class, adapter). Email is I1."""


class WorldDispatcher:
    """``ToolDispatcher`` for the 10-agent world: every tool runs over ``ks.state`` inside the gateway txn and
    returns the read/write sets it touched. I1/I2 tools return an :class:`OutboxRequest` and never act inline."""

    def classify(self, env: Envelope) -> ActionClass:
        spec = CATALOGUE.get(env.tool)
        return spec[0] if spec is not None else ActionClass.U

    def execute(self, env: Envelope, txn: StateTxn) -> Execution:
        return CATALOGUE[env.tool][1](_Ctx(env, txn))

    def view(self, agent_id: str, tick: int, state: StateSnapshot) -> tuple[ViewEntry, ...]:
        """``ViewProvider`` (B3-40, M2): ``state`` must carry ``.store`` and ``.visible_to`` (first seq of the
        tick); anything else is a TypeError. ``None`` -> empty view."""
        if state is None:
            return ()
        if not (hasattr(state, "store") and hasattr(state, "visible_to")):
            raise TypeError("view needs a snapshot with .store and .visible_to (M2)")
        if type(state.visible_to) is not int:  # M2: never default to "all heads"
            raise TypeError("view needs visible_to = the tick's first seq as an int (M2)")
        return build_view(state.store, agent_id, visible_to=state.visible_to)
