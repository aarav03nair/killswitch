"""Scenario seed data and the per-agent view builder (ADR-06, I1, M2).

``seed_state`` writes tick-0 state through ``ks.state``; ``build_view`` returns the ``TickFrame.view`` for one
agent from its narrow scope. A plain function (no gateway import): the gateway's view provider (B3-40) calls it
with ``visible_to`` = the tick's first seq so same-tick writes stay invisible (M2).
Scope entries are ``(table, with_fields, last_n)``; ``with_fields`` also delivers the sensitive field objects of
each row as their own entries. Triage's scope leaves ``with_fields`` off, so its view lists ``suppliers:S-17``
but never ``suppliers:S-17.iban``.
"""

from __future__ import annotations

from ks.contracts import MAX_VIEW_ENTRIES, ViewEntry, split_obj_id, value_hash
from ks.state import FieldSchema, Store

from .agents import AGENT_IDS
from .registry import CUSTOMERS, SENSITIVE_FIELDS, SKUS, SUPPLIER_MASTER

__all__ = ["SEED_AUTHOR", "SCOPES", "FIELDS", "world_fields", "seed_state", "build_view", "open_world_store"]

SEED_AUTHOR = "ks.gateway"
FIELDS = FieldSchema(SENSITIVE_FIELDS)

SCOPES: dict[str, tuple[tuple[str, bool, int], ...]] = {
    "billing": (("suppliers", True, 8), ("invoices", False, 4), ("customers", False, 8)),
    "comms": (("invoices", False, 4), ("suppliers", True, 8)),
    "compliance": (("ledger", False, 8),),
    "crm": (("suppliers", False, 8), ("customers", False, 8), ("tickets", False, 8)),
    "docs": (("docs", False, 8),),
    "intake": (("tickets", False, 8),),
    "inventory": (("stock", False, 8),),
    "payments": (("invoices", False, 4), ("suppliers", True, 8)),
    "reporter": (("invoices", False, 6),),
    "triage": (("tickets", False, 8),),  # edits the supplier named by the scenario; sees no supplier rows (B2)
}
assert tuple(sorted(SCOPES)) == AGENT_IDS


def world_fields() -> FieldSchema:
    return FIELDS


def open_world_store(path) -> Store:
    """``state.db`` with the world's sensitive-field schema (always pass ``fields=``)."""
    from ks.state import open_store
    return open_store(path, fields=FIELDS)


def seed_state(store: Store, *, seq: int = 1) -> None:
    """Tick-0 state: supplier registry (IBAN as field object), customers, stock, one ticket and doc.
    Author ``ks.gateway`` at ``seq``. Caller supplies the transaction (``with store.txn()``)."""
    for pk, row in sorted(SUPPLIER_MASTER.items()):
        store.write_row(f"suppliers:{pk}", {**row, "risk_note": ""}, author=SEED_AUTHOR, seq=seq, action_id=f"seed-{pk}")
    for pk, row in sorted(CUSTOMERS.items()):
        store.write_row(f"customers:{pk}", row, author=SEED_AUTHOR, seq=seq, action_id=f"seed-{pk}")
    for pk, row in sorted(SKUS.items()):
        store.write_row(f"stock:{pk}", row, author=SEED_AUTHOR, seq=seq, action_id=f"seed-{pk}")
    store.write_row("tickets:T-0000", {"title": "onboarding", "priority": "low"}, author=SEED_AUTHOR, seq=seq,
                    action_id="seed-T-0000")
    store.write_row("docs:D-0000", {"title": "handbook"}, author=SEED_AUTHOR, seq=seq, action_id="seed-D-0000")


def build_view(store: Store, agent_id: str, *, visible_to: int | None = None) -> tuple[ViewEntry, ...]:
    """The agent's ``TickFrame.view``: <= MAX_VIEW_ENTRIES entries sorted by obj, versions visible at seq <
    ``visible_to``. Newest rows (highest pk) win when a table exceeds its ``last_n``; the total is capped by
    dropping the lowest-sorted rows' entries last-first."""
    heads = store.heads(visible_to=visible_to)
    entries: list[ViewEntry] = []
    for table, with_fields, last_n in SCOPES[agent_id]:
        rows = sorted((o for o in heads if split_obj_id(o)[0] == table and split_obj_id(o)[2] is None
                       and heads[o].hash != _TOMB), key=lambda o: split_obj_id(o)[1], reverse=True)[:last_n]
        for row in rows:
            objs = [row, *(FIELDS.field_objs_of(row) if with_fields else ())]
            for obj in objs:
                try:
                    g = store.get(obj, visible_to=visible_to)
                except ValueError:  # S4-28: an off-gateway edit left an unparsable value; reconcile alerts
                    continue
                if g is None or g.value is None:
                    continue
                if g.hash != value_hash(g.value):  # S4-28: off-gateway edit; never deliver it (reconcile alerts)
                    continue
                entries.append(ViewEntry(obj=obj, ver=g.ver, hash=g.hash, value=g.value))
    entries.sort(key=lambda e: e.obj)
    if len(entries) > MAX_VIEW_ENTRIES:
        entries = entries[:MAX_VIEW_ENTRIES]
    assert all(e.hash == value_hash(e.value) for e in entries)
    return tuple(entries)


from ks.contracts import TOMBSTONE_HASH as _TOMB  # noqa: E402
