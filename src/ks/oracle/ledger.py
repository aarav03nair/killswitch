"""Effect ledger (ADR-06-metrics §1): one line per world effect, keyed per (table, pk, field), harness-side.

Source is a per-tick ``state.db`` diff plus sink deliveries, never the recorder, so a write that bypassed the
gateway (``seq`` null) is in the ledger. No ground-truth label (no ``injected``) ever enters a line.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ks.contracts import TOMBSTONE_HASH, canonical, split_obj_id, value_hash

__all__ = ["DELIVERED", "LedgerBuilder", "delivered", "key_of", "outbox_key", "fold", "final", "equal", "b_set", "g_set", "t0_of",
           "read_ledger", "dumps_ledger"]

DELIVERED = frozenset({"present", "released", "dispatched"})
_KIND = {"payments": "payment", "email": "email", "docs": "purge"}
_ABSENT = object()


def key_of(table: str, pk: str, field: str | None) -> str:
    return f"{table}:{pk}" if field is None else f"{table}:{pk}.{field}"


def outbox_key(idem_key: str) -> str:
    """Ledger key of a sink effect, the same on the S* side and the run side: ``outbox:<idempotency_key>`` (never
    the gateway's ``ob-NNNNNN`` id). The key itself is ``ks.contracts.idempotency_key`` (gateway-derived)."""
    return key_of("outbox", idem_key, None)


def delivered(state: str) -> bool:
    return state in DELIVERED


class LedgerBuilder:
    """Per-tick diff of a ``ks.state`` store. ``mark_recorded(seq)`` names the seqs the gateway (or the harness
    standing in for it) wrote; a version at any other seq gets ``seq = null`` (bypass)."""

    def __init__(self, store) -> None:
        self.store = store
        self.effects: list[dict[str, Any]] = []
        self._heads: dict[str, Any] = {}
        self._vals: dict[str, Any] = {}
        self._known: set[tuple[int, str, str | None]] = set()

    def mark_recorded(self, seq: int, author: str, action_id: str | None = None) -> None:
        """Name a write the gateway recorded: provenance is ``(seq, author, action_id)``; ``action_id=None`` matches
        any action of that author at that seq (the seed). A version that reuses a recorded seq under another
        author or action is still a bypass (anaya B3-22 minor)."""
        self._known.add((seq, author, action_id))

    def _emit(self, tick, seq, agent, kind, table, pk, field, vh, idem, state) -> None:
        self.effects.append({"eff": f"e{len(self.effects) + 1:06d}", "tick": tick, "seq": seq, "agent": agent,
                             "kind": kind, "table": table, "pk": pk, "field": field,
                             "key": key_of(table, pk, field), "value_hash": vh, "idem_key": idem, "state": state})

    def observe(self, tick: int, deliveries: Iterable[Mapping[str, Any]] = ()) -> None:
        """Diff the store against the previous call and record sink ``deliveries``
        (``{agent, sink, idem_key, payload}``; dispatched this tick)."""
        heads = self.store.heads()
        for obj in sorted(heads):
            ref = heads[obj]
            if self._heads.get(obj) == ref:
                continue
            table, pk, field = split_obj_id(obj)
            h = self.store.history(obj)[-1]
            seq = h.seq if (h.seq, h.author, h.action_id) in self._known or (h.seq, h.author, None) in self._known \
                else None
            new = None if ref.hash == TOMBSTONE_HASH else self.store.value_at(obj, ref.ver)
            old = self._vals.get(obj)
            if field is None and (isinstance(new, dict) or isinstance(old, dict)):
                a, b = old if isinstance(old, dict) else {}, new if isinstance(new, dict) else {}
                for k in sorted(set(a) | set(b)):
                    nv, ov = b.get(k, _ABSENT), a.get(k, _ABSENT)
                    if nv != ov:
                        self._emit(tick, seq, h.author, "row", table, pk, k,
                                   value_hash(None if nv is _ABSENT else nv), None, "present")
            else:
                self._emit(tick, seq, h.author, "row", table, pk, field, value_hash(new), None, "present")
            self._heads[obj], self._vals[obj] = ref, new
        for d in deliveries:
            self._emit(tick, None if d.get("seq") is None else d["seq"], d["agent"], _KIND.get(d["sink"], d["sink"]),
                       "outbox", d["idem_key"], None, value_hash(d["payload"]), d["idem_key"], "dispatched")

    def dumps(self) -> bytes:
        return dumps_ledger(self.effects)


def dumps_ledger(effects: Iterable[Mapping[str, Any]]) -> bytes:
    return b"".join(canonical.dumps_line(e) for e in effects)


def read_ledger(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line]


def _order(e: Mapping[str, Any]) -> tuple[int, int, str]:
    return (e["tick"], -1 if e["seq"] is None else e["seq"], e["eff"])


def fold(effects: Iterable[Mapping[str, Any]], upto: int | None = None) -> dict[str, Mapping[str, Any]]:
    """``final_x(k)``: last effect per key by (tick, seq), over ticks <= ``upto``."""
    out: dict[str, Mapping[str, Any]] = {}
    for e in sorted(effects, key=_order):
        if upto is None or e["tick"] <= upto:
            out[e["key"]] = e
    return out


def final(effects, key: str, upto: int | None = None):
    return fold(effects, upto).get(key)


def equal(a: Mapping[str, Any] | None, b: Mapping[str, Any] | None) -> bool:
    """``final(k) == S*(k)``: value_hash and delivery. Cancelled equals only absent; absent equals only absent."""
    if a is None or a["state"] == "cancelled":
        return b is None or b["state"] == "cancelled"
    if b is None or b["state"] == "cancelled":
        return False
    return a["value_hash"] == b["value_hash"] and delivered(a["state"]) == delivered(b["state"])


def b_set(run: Iterable[Mapping[str, Any]], star: Iterable[Mapping[str, Any]], upto: int | None = None) -> set[str]:
    """B = {k : final_x(k) != S*_x(k)} at tick ``upto`` (t_rec)."""
    run = list(run)
    r, s = fold(run, upto), fold(star, upto)
    b = {k for k in r.keys() | s.keys() if not equal(r.get(k), s.get(k))}
    # a bypass (seq null, not a sink delivery) enters B by value even when a later write overwrote it: nothing
    # recorded can forgive it. It is harmless only if it wrote exactly what S* holds for that key.
    for e in run:
        if e["seq"] is None and e["table"] != "outbox" and (upto is None or e["tick"] <= upto) and e["key"] not in b:
            sv = s.get(e["key"])
            if sv is None or sv["state"] == "cancelled" or sv["value_hash"] != e["value_hash"]:
                b.add(e["key"])
    return b


def g_set(run: Iterable[Mapping[str, Any]], b: set[str], t_inject: int) -> set[str]:
    """G = {k : an effect at tick >= t_inject, k not in B} (the culprit's honest writes included, A8)."""
    return {e["key"] for e in run if e["tick"] >= t_inject} - b


def t0_of(run: Iterable[Mapping[str, Any]], b: set[str], t_inject: int) -> int | None:
    """Oracle t0 = min tick over effects on B keys at tick >= t_inject; null when B is empty."""
    ts = [e["tick"] for e in run if e["key"] in b and e["tick"] >= t_inject]
    return min(ts) if ts else None
