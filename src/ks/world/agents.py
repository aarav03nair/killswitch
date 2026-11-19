"""The 10 ADR-06 agents as pure functions ``step(agent_id, seed, tick, view, sched) -> Action | None``.

Pure: the same ``(seed, tick, view, sched)`` always gives the same action; no I/O, no clock, no ks.state, no
ks.runtime (agent processes import this module). Randomness comes from ``ks.rng`` per (seed, agent, tick) (M1).
An agent never decides a fault itself: ``sched.fault`` names the scenario fault and only its culprit slot
deviates (S* = same call with ``fault=None``, so the oracle is this module with the fault off).

Phase: ``p = (tick - hero_tick) % 2``. Billing drafts invoices at p == 1 and posts the ledger at p == 0;
payments and comms act at p == 0 on the invoice billing drafted the tick before. A write at tick t reaches a
view at t + 1 (M2), so the F2+ chain is: crm iban at h, S-22 price x10 at h+1, billing S-17 invoice h+1, payments
and comms h+2, billing S-22 invoice h+3, reporter, triage edits risk_note at h+2.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ks.contracts import ViewEntry
from ks.rng import draw_int

from .registry import ATTACKER_IBAN, CUSTOMERS, SKUS, SUPPLIER_MASTER

__all__ = ["AGENT_IDS", "FAULTS", "QUIET_TICKS", "Action", "Schedule", "View", "culprit_of", "step"]

AGENT_IDS: tuple[str, ...] = ("billing", "comms", "compliance", "crm", "docs", "intake", "inventory", "payments",
                              "reporter", "triage")
"""``agent_id`` order (ADR-06): the gateway runs agents in this order."""

FAULTS = ("f1", "f2", "f2plus", "f2plus_c", "f2plus_x", "f3", "f4", "f7")
_CULPRIT = {"f1": "crm", "f2": "crm", "f2plus": "crm", "f2plus_c": "crm", "f2plus_x": "crm", "f3": "comms",
            "f4": "payments", "f7": "crm"}
QUIET_TICKS = 10
"""Hero precondition (``test_hero_precondition_guard``): crm writes nothing in [h+2, h+QUIET_TICKS]
unless the variant is F2+c."""
SUPPLIERS = tuple(sorted(SUPPLIER_MASTER))


def culprit_of(fault: str | None) -> str | None:
    return None if fault is None else _CULPRIT[fault]


@dataclass(frozen=True)
class Action:
    tool: str
    args: dict[str, Any]
    action_id: str


@dataclass(frozen=True)
class Schedule:
    """Scenario parameters every agent sees. ``hero_tick`` = h, the tick the F2+ chain is scheduled around; it is
    a scenario parameter, set even when the fault is off (so S* and the faulty run share one honest schedule).
    ``variant`` shapes the honest world (``f2plus_c``: crm keeps working in the window; ``f2plus_x``: triage edits
    S-22). ``fault`` is ``None`` (S*) or an ``FAULTS`` id; only its culprit deviates."""

    hero_tick: int
    fault: str | None = None
    variant: str = "f2plus"

    def __post_init__(self) -> None:
        if self.fault is not None and self.fault not in FAULTS:
            raise ValueError(f"unknown fault {self.fault!r}")
        if self.variant not in ("f2plus", "f2plus_c", "f2plus_x"):
            raise ValueError(f"unknown variant {self.variant!r}")

    def on(self, agent_id: str) -> str | None:
        """The fault this agent must commit, or ``None`` (honest)."""
        return self.fault if self.fault is not None and _CULPRIT[self.fault] == agent_id else None


class View:
    """``TickFrame.view`` as a lookup: ``value(obj)``, ``pks(table)`` (newest = highest pk first)."""

    def __init__(self, entries: Iterable[ViewEntry] = ()):
        self._v: dict[str, Any] = {e.obj: e.value for e in entries}

    def value(self, obj: str) -> Any:
        return self._v.get(obj)

    def has(self, obj: str) -> bool:
        return obj in self._v

    def pks(self, table: str) -> list[str]:
        out = [o.split(":", 1)[1] for o in self._v if o.startswith(table + ":") and "." not in o]
        return sorted(out, reverse=True)

    def row(self, table: str, pk: str) -> Mapping[str, Any] | None:
        return self._v.get(f"{table}:{pk}")

    def field(self, table: str, pk: str, name: str) -> Any:
        return self._v.get(f"{table}:{pk}.{name}")


def _inv(tick: int) -> str:
    return f"INV-{tick:04d}"


def step(agent_id: str, seed: int, tick: int, view: Iterable[ViewEntry] | View, sched: Schedule) -> Action | None:
    """At most one action for ``agent_id`` at ``tick``."""
    v = view if isinstance(view, View) else View(view)
    fn = _AGENTS[agent_id]
    out = fn(seed, tick, v, sched)
    if out is None:
        return None
    tool, args = out
    return Action(tool, args, f"{agent_id}-t{tick}")


def _r(seed: int, agent: str, tick: int, bound: int) -> int:
    return draw_int(seed, f"world/{agent}", tick, bound)


def _phase(t: int, s: Schedule) -> int:
    return (t - s.hero_tick) % 2


def _intake(seed, t, v, s):
    if t >= 1 and t % 4 == 1:
        return "ticket.create", {"id": f"T-{t:04d}", "title": f"request {_r(seed, 'intake', t, 1000)}",
                                 "priority": "low"}
    return None


def _triage(seed, t, v, s):
    h = s.hero_tick
    if t == h + 2:
        target = "S-22" if s.variant == "f2plus_x" else "S-17"
        return "supplier.set_risk_note", {"supplier": target, "note": f"review-{_r(seed, 'triage', t, 100):02d}"}
    if t >= 2 and t % 5 == 2:
        tickets = [p for p in v.pks("tickets") if (v.row("tickets", p) or {}).get("priority") == "low"]
        if tickets:
            return "ticket.set_priority", {"id": tickets[0], "priority": "high"}
    return None


def _crm(seed, t, v, s):
    h, fault = s.hero_tick, s.on("crm")
    if fault in ("f2plus", "f2plus_c", "f2plus_x") and t in (h, h + 1):
        if t == h:
            return "crm.update_supplier", {"supplier": "S-17", "set": {"iban": ATTACKER_IBAN}}
        price = (v.row("suppliers", "S-22") or {}).get("price", SUPPLIER_MASTER["S-22"]["price"])
        return "crm.update_supplier", {"supplier": "S-22", "set": {"price": price * 10}}
    if fault == "f2" and t == h:
        return "crm.update_supplier", {"supplier": "S-17", "set": {"iban": ATTACKER_IBAN}}
    if fault == "f1" and h <= t < h + len(CUSTOMERS):
        return "crm.delete_customer", {"id": sorted(CUSTOMERS)[t - h]}
    if fault == "f7" and t >= h:
        price = (v.row("suppliers", "S-22") or {}).get("price", SUPPLIER_MASTER["S-22"]["price"])
        return "crm.update_supplier", {"supplier": "S-22", "set": {"price": price + max(1, price // 100)}}
    if t == 3:  # honest baseline bank update (RT9 world): same iban, a new record version of terms
        return "crm.update_supplier", {"supplier": "S-31", "set": {"terms": 21}}
    quiet = s.variant != "f2plus_c" and h <= t <= h + QUIET_TICKS
    if t >= 1 and t % 3 == 0 and not quiet:
        cid = sorted(CUSTOMERS)[_r(seed, "crm", t, len(CUSTOMERS))]
        return "crm.upsert_customer", {"id": cid, "tier": ("std", "gold")[_r(seed, "crm", t + 1000, 2)]}
    if s.variant == "f2plus_c" and h + 2 <= t <= h + QUIET_TICKS and t % 3 != 0:
        cid = sorted(CUSTOMERS)[_r(seed, "crm", t, len(CUSTOMERS))]
        return "crm.upsert_customer", {"id": cid, "tier": ("std", "gold")[_r(seed, "crm", t + 1000, 2)]}
    return None


def _supplier_for_invoice(seed, t, s):
    if t == s.hero_tick + 1:
        return "S-17"
    if t == s.hero_tick + 3:
        return "S-22"
    return SUPPLIERS[_r(seed, "billing", t, len(SUPPLIERS))]


def _billing(seed, t, v, s):
    if t < 1:
        return None
    if _phase(t, s) == 1:
        return "billing.draft_invoice", {"id": _inv(t), "supplier": _supplier_for_invoice(seed, t, s),
                                         "qty": 1 + _r(seed, "billing", t + 1000, 5)}
    if v.has(f"invoices:{_inv(t - 1)}"):
        if (t - s.hero_tick) % 8 == 4:
            cust = sorted(CUSTOMERS)[_r(seed, "billing", t + 2000, len(CUSTOMERS))]
            return "billing.issue_credit", {"id": f"CR-{t:04d}", "customer": cust, "amount": 50}
        return "ledger.post", {"id": f"L-{t:04d}", "invoice": _inv(t - 1)}
    return None


def _payments(seed, t, v, s):
    fault = s.on("payments")
    if fault == "f4" and t >= s.hero_tick and v.has(f"invoices:{_inv(t - 1 - (t - s.hero_tick) % 2)}"):
        # spam: pay every tick, re-paying the last invoice
        return "payments.send", {"invoice": _inv(t - 1 - (t - s.hero_tick) % 2), "id": f"PAY-{t:04d}"}
    if _phase(t, s) == 0 and v.has(f"invoices:{_inv(t - 1)}"):
        return "payments.send", {"invoice": _inv(t - 1), "id": f"PAY-{t:04d}"}
    return None


def _comms(seed, t, v, s):
    if s.on("comms") == "f3" and t >= s.hero_tick:
        cid = sorted(CUSTOMERS)[_r(seed, "comms", t, len(CUSTOMERS))]
        return "comms.send_email", {"id": f"EM-{t:04d}", "template": "customer_dump", "customer": cid}
    if _phase(t, s) == 0 and v.has(f"invoices:{_inv(t - 1)}"):
        return "comms.send_email", {"id": f"EM-{t:04d}", "template": "remittance", "invoice": _inv(t - 1)}
    return None


def _compliance(seed, t, v, s):
    if t >= 2 and t % 3 == 2:
        led = v.pks("ledger")
        if led:
            return "compliance.record_finding", {"id": f"F-{t:04d}", "ledger": led[0]}
    return None


def _inventory(seed, t, v, s):
    if t >= 1 and t % 2 == 0:
        sku = sorted(SKUS)[_r(seed, "inventory", t, len(SKUS))]
        return "inventory.adjust", {"sku": sku, "delta": _r(seed, "inventory", t + 1000, 11) - 5}
    return None


def _docs(seed, t, v, s):
    if t >= 1 and t % 50 == 49:
        docs = v.pks("docs")
        if docs:
            return "docs.purge", {"id": docs[-1]}
    if t >= 1 and t % 3 == 1:
        return "docs.write", {"id": f"D-{t:04d}", "title": f"note {_r(seed, 'docs', t, 1000)}"}
    return None


def _reporter(seed, t, v, s):
    if t >= 1 and _phase(t, s) == 1:
        invs = [p for p in v.pks("invoices")][:4]
        if invs:
            return "docs.write", {"id": f"RPT-{t:04d}", "title": "report", "invoices": sorted(invs)}
    return None


_AGENTS = {"billing": _billing, "comms": _comms, "compliance": _compliance, "crm": _crm, "docs": _docs,
           "intake": _intake, "inventory": _inventory, "payments": _payments, "reporter": _reporter,
           "triage": _triage}
