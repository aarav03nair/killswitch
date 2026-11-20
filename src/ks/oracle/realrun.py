"""Effect ledger of a REAL gateway run (state.db + record.jsonl), same shape and keys as the S* ledger.

Scorer-side only. Row effects are per (table, pk, field) per version; a sink effect is keyed
``outbox:<idempotency_key>`` (the gateway-derived key, never the ``ob-NNNNNN`` id) and appears only when the item
left (``dispatched``) or was ``cancelled``: queued/held/released items have not landed, as in S*.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ks.contracts import TOMBSTONE_HASH, OutboxItem, OutboxStatus, split_obj_id, value_hash
from ks.world.scenario import SEED_AUTHOR, open_world_store

from .ledger import _ABSENT, _KIND, key_of, outbox_key

__all__ = ["real_ledger"]


def real_ledger(run_dir: str | Path) -> list[dict[str, Any]]:
    run = Path(run_dir)
    tick_of: dict[int, int] = {}
    recov: dict[int, set[tuple[str, int, str]]] = {}  # seq of a ks.recover.* record -> what it wrote
    prov: dict[tuple[int, str, str], set[tuple[str, int, str]]] = {}  # (seq, agent, action_id) -> {(obj, after ver, after hash)} the record's write_set lists
    for line in (run / "record.jsonl").read_text().splitlines():
        if line:
            r = json.loads(line)
            tick_of[r["seq"]] = r["tick"]
            env = r.get("envelope")
            if env and r.get("sig_ok"):  # an unsigned / forged record backs nothing
                prov.setdefault((r["seq"], env["agent_id"], env["action_id"]), set()).update(
                    (w["obj"], w["after"]["ver"], w["after"]["hash"]) for w in r.get("write_set") or [])
                if env["agent_id"] == "ks.recovery" and env["tool"].startswith("ks.recover.") and r["decision"] == "exec" and r.get("sig_ok"):
                    # B3-27: a re-run (M14) writes under the ORIGINAL agent/action ids; its own record still lists
                    # each (obj, ver, hash) it wrote, which is what backs the version
                    recov[r["seq"]] = {(w["obj"], w["after"]["ver"], w["after"]["hash"]) for w in r.get("write_set") or []}
    store = open_world_store(run / "workspace" / "state.db")
    out: list[dict[str, Any]] = []

    def emit(tick, seq, agent, kind, table, pk, field, vh, idem, state, key):
        out.append({"eff": "", "tick": tick, "seq": seq, "agent": agent, "kind": kind, "table": table, "pk": pk,
                    "field": field, "key": key, "value_hash": vh, "idem_key": idem, "state": state})
    try:
        for obj in sorted(store.heads()):
            table, pk, field = split_obj_id(obj)
            old: Any = None
            prev_tick = 0
            for h in store.history(obj):
                # recorded only if the record at that seq lists THIS obj with the matching after ver and hash; matching
                # (seq, agent, action_id) alone is spoofable by a bypass write to another object.
                # seed rows: action_id seed-<pk>, record 'seed'. B3-27: only those; ks.gateway also authors every
                # ks.dispatch / hold status change (action_id dispatch-<id> etc.), which must match its own record
                seed_row = h.author == SEED_AUTHOR and (h.action_id or "").startswith("seed-")
                ak = (h.seq, h.author, "seed" if seed_row else h.action_id)
                if (obj, h.ver, h.hash) in prov.get(ak, ()) or (obj, h.ver, h.hash) in recov.get(h.seq, ()):
                    tick, seq = tick_of.get(h.seq, 0), h.seq
                else:
                    # bypass: no record backs this version. seq null (never forgiven, ADR s1); tick is its position,
                    # not 0: the tick of the object's previous version (the earliest it can have landed). The
                    # scorer's b_set also keeps every non-outbox bypass effect whose value differs from S*.
                    tick, seq = prev_tick, None
                prev_tick = tick
                new = None if h.hash == TOMBSTONE_HASH else store.value_at(obj, h.ver)
                if table == "outbox":
                    it = OutboxItem.from_obj(new) if new is not None else None
                    if it is not None and it.status in (OutboxStatus.DISPATCHED, OutboxStatus.CANCELLED):
                        emit(tick, seq, h.author, _KIND.get(it.sink, it.sink), "outbox", it.idempotency_key,
                             None, it.payload_hash, it.idempotency_key,
                             "dispatched" if it.status == OutboxStatus.DISPATCHED else "cancelled",
                             outbox_key(it.idempotency_key))
                    continue
                if field is None and (isinstance(new, dict) or isinstance(old, dict)):
                    a, b = old if isinstance(old, dict) else {}, new if isinstance(new, dict) else {}
                    for k in sorted(set(a) | set(b)):
                        nv, ov = b.get(k, _ABSENT), a.get(k, _ABSENT)
                        if nv != ov:
                            emit(tick, seq, h.author, "row", table, pk, k,
                                 value_hash(None if nv is _ABSENT else nv), None, "present", key_of(table, pk, k))
                else:
                    emit(tick, seq, h.author, "row", table, pk, field, value_hash(new), None, "present",
                         key_of(table, pk, field))
                old = new
    finally:
        store.close()
    out.sort(key=lambda e: (e["tick"], -1 if e["seq"] is None else e["seq"]))
    for i, e in enumerate(out, 1):
        e["eff"] = f"e{i:06d}"
    return out
