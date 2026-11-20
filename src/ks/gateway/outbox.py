"""The outbox (ADR-03 I1, ADR-04 §5/§7, CALL-02 G3/G4): the gateway owns every irreversible effect request.

An executed tool returns ``OutboxRequest``s; ``Outbox.create`` turns each into an ``outbox:<id>`` object (the C3
``OutboxItem``) written inside the same state txn and the same record as the action, so ``state = fold(record)``
holds and the record's ``outbox_ids`` name it. The gateway derives everything a tool must not choose: the id,
the ``idempotency_key`` (``idempotency_key(agent, action, sink, n)``), the lineage (the record's read set, never
agent-declared) and ``release_tick``::

    release_tick = tick + H                              (H = RunConfig.hold_window_ticks; H = 0: next tick)
    release_tick = max(tick + H, v + 2H)                 (G3, H > 0, lineage holds a sensitive-field version
                                                          written at tick v; the latest such v counts)

Status lives in the object: queued -> held | released | dispatched | cancelled. A new item is ``held`` at creation
if its lineage touches a tainted version (``TaintView``). The release phase (``Gateway.open``, before the tick's
views) walks queued items whose ``release_tick`` has come, in outbox-id order:

    lineage touches a tainted version                     -> ks.control hold,  reason lineage_hold
    a sensitive-field version in lineage is no longer the head (H > 0)
                                                           -> ks.control hold,  reason sensitive_field
    else                                                   -> ks.dispatch (F4): read_set = lineage U outbox:<id>@ver,
                                                              write_set = status change, item.dispatched_seq = seq

Every one of these is a signed ``ks.gateway`` envelope on ``c-0`` with a ``write_set`` (the status change), so
every refusal to dispatch is recorded. ``ks.dispatch`` exists only for dispatch (G4); an effect leaves the
boundary exactly when that record lands. A re-created item of the same (agent, action, sink, n), i.e. a recovery
re-run, derives the same idempotency_key and reuses ``outbox:<id>`` at v+1, back on hold (CALL-02 B2).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from ks.contracts import (ActionClass, Envelope, OutboxItem, OutboxStatus, ReadEntry, RunConfig, WriteEntry,
                          idempotency_key, split_obj_id, value_hash)
from ks.contracts.state import SideDomain

from .dispatch import OutboxRequest

__all__ = ["Outbox", "TaintView", "Due", "OUTBOX_PREFIX", "outbox_obj"]

OUTBOX_PREFIX = "outbox:"
SYSTEM_AUTHOR = "ks.gateway"
RERUN_TOOL = "ks.recover.rerun"
"""B3-30: an item re-held by an approved re-run has this record as its creating record (``_unrecorded_rerun``)."""


def outbox_obj(outbox_id: str) -> str:
    return OUTBOX_PREFIX + outbox_id


class TaintView(Protocol):
    """What containment tells the gateway: is this object version tainted (ADR-04 §5)?"""

    def is_tainted(self, obj: str, ver: int) -> bool: ...


@dataclass(frozen=True)
class Due:
    """A queued item whose release tick has come, with the version it was read at."""

    item: OutboxItem
    ver: int
    hash: str

    @property
    def obj(self) -> str:
        return outbox_obj(self.item.outbox_id)

    def read_entry(self) -> ReadEntry:
        return ReadEntry(obj=self.obj, ver=self.ver, hash=self.hash)


class Outbox:
    def __init__(self, store: Any, config: RunConfig, *, taint: TaintView | None = None,
                 tick_of_seq: Callable[[int], int] | None = None,
                 record_at: Callable[[int], Any] | None = None):
        self.store, self.config, self.taint = store, config, taint
        self._tick_of_seq = tick_of_seq
        # D10 contrast only (B3-51, contracts 1.6): RunConfig.lineage_hold False drops the alert-driven lineage hold
        # so that, with H = 0, a tainted payment dispatches and is scored. It is in config.json / config_hash, so
        # the record shows the run was a contrast run; `ks run --hold 0 --no-lineage-hold` is the only setter.
        self.lineage_holds = config.lineage_hold
        self._record_at = record_at  # seq -> the landed Record or None (provenance check before any dispatch)

    # --- creation ----------------------------------------------------------------------------------
    def create(self, requests: Sequence[OutboxRequest], env: Envelope, seq: int, tick: int,
               lineage: Iterable[ReadEntry]) -> tuple[tuple[WriteEntry, ...], tuple[str, ...]]:
        """Write one object per request inside the caller's txn; returns (write entries, outbox ids in order)."""
        lineage = tuple(sorted(lineage, key=lambda e: (e.obj, e.ver)))  # v1.4: one obj may appear at two versions
        writes, ids = [], []
        existing = self._by_key()
        counter = self._count()
        for n, req in enumerate(requests):
            if req.action_class not in (ActionClass.I1, ActionClass.I2):
                raise ValueError("only I-class effects use the outbox")
            key = idempotency_key(env.agent_id, env.action_id, req.sink, n)
            payload_hash = value_hash(req.payload)
            self.store.side.put(SideDomain.VALUE, req.payload)
            if key in existing:  # a re-run of the same action: same object, v+1, back on hold (B2)
                oid = existing[key]
                prev = self.get(oid)
                if prev.item.status == OutboxStatus.DISPATCHED:
                    raise ValueError("a dispatched effect is irreversible; re-run needs a compensation, not an item")
                item = prev.item.model_copy(update=dict(status=OutboxStatus.HELD, payload_hash=payload_hash,
                                                        lineage=lineage, created_seq=seq))
            else:
                counter += 1
                oid = f"ob-{counter:06d}"
                item = OutboxItem(outbox_id=oid, author=env.agent_id, action_id=env.action_id, created_seq=seq,
                                  sink=req.sink, action_class=req.action_class.value, payload_hash=payload_hash,
                                  idempotency_key=key, lineage=lineage,
                                  status=OutboxStatus.QUEUED,  # a tainted lineage is held by a record (Gateway)
                                  release_tick=self.release_tick(tick, lineage), dispatched_seq=None)
            writes.append(self.store.put(outbox_obj(oid), item.to_obj(), author=env.agent_id, seq=seq,
                                         action_id=env.action_id))
            ids.append(oid)
        return tuple(sorted(writes, key=lambda w: w.obj)), tuple(ids)

    def release_tick(self, tick: int, lineage: Iterable[ReadEntry]) -> int:
        h = self.config.hold_window_ticks
        t = tick + h
        if h == 0:
            return t  # G3 is off at H = 0
        v = self._sensitive_tick(lineage)
        return t if v is None else max(t, v + 2 * h)

    # --- inspection ----------------------------------------------------------------------------------
    def get(self, outbox_id: str) -> Due:
        row = self.store.get(outbox_obj(outbox_id))
        if row is None or row.value is None:
            raise KeyError(outbox_id)
        return Due(OutboxItem.from_obj(row.value), row.ver, row.hash)

    def items(self) -> list[Due]:
        out = []
        for (obj,) in self.store.conn.execute("SELECT obj FROM objects WHERE obj LIKE 'outbox:%' ORDER BY obj"):
            row = self.store.get(obj)
            if row is not None and row.value is not None:
                out.append(Due(OutboxItem.from_obj(row.value), row.ver, row.hash))
        return out

    def due(self, tick: int) -> list[Due]:
        return [d for d in self.items() if d.item.status == OutboxStatus.QUEUED and d.item.release_tick <= tick]

    def hold_reason(self, d: Due) -> str | None:
        """Why this due item must not leave, or None (ADR-04 §5, §7)."""
        if self._unrecorded(d):
            return "unrecorded_item"
        if self.lineage_holds and self._tainted(d.item.lineage):
            return "lineage_hold"
        if self.config.hold_window_ticks > 0 and self._sensitive_moved(d.item.lineage):
            return "sensitive_field"
        return None

    # --- status change (one write; the caller records it) -----------------------------------------------
    def set_status(self, d: Due, status: OutboxStatus, *, seq: int, author: str, action_id: str) -> WriteEntry:
        update: dict[str, Any] = {"status": status}
        if status == OutboxStatus.DISPATCHED:
            update["dispatched_seq"] = seq
        item = d.item
        top = self.store.conn.execute("SELECT ver, hash FROM versions WHERE obj = ? ORDER BY ver DESC LIMIT 1",
                                      (d.obj,)).fetchone()
        if top is not None and top[0] != d.ver:
            # The head was moved behind the chain (raw SQL). Append on top of the real chain, never raise: the hold
            # is recorded on the true latest version, and a dispatched item stays dispatched.
            self.store.conn.execute("UPDATE objects SET head_ver = ?, head_hash = ? WHERE obj = ?",
                                    (top[0], top[1], d.obj))
            real = OutboxItem.from_obj(self.store.value_at(d.obj, top[0]))
            item = real
            if real.status == OutboxStatus.DISPATCHED:
                update = {}
        item = item.model_copy(update=update)
        return self.store.put(d.obj, item.to_obj(), author=author, seq=seq, action_id=action_id)

    # --- provenance: an item leaves only if the record that created it says so ------------------------------
    def _unrecorded(self, d: Due) -> bool:
        """True if the item cannot be tied to the log. Checks: the stored value hashes to the head hash; the head
        version is the last write to the item in the record log and was written by a record that lists it in its write_set; the creating record (``created_seq``) is an
        agent record listing the id in ``outbox_ids`` with the item's obj in its write_set, and the item's author,
        action_id, class, sink, idempotency_key, lineage (= that record's read set) and release_tick are what the
        gateway would have derived from it. A re-run's re-held item (B3-30) is checked by ``_unrecorded_rerun``."""
        if self._record_at is None:
            return False
        it = d.item
        row = self.store.get(d.obj)
        if row is None or row.value is None or value_hash(row.value) != row.hash:
            return True
        head = self.store.conn.execute("SELECT seq FROM versions WHERE obj = ? AND ver = ?",
                                       (d.obj, d.ver)).fetchone()
        hr = self._record_at(head[0]) if head else None
        if hr is None or not any(w.obj == d.obj and w.after.ver == d.ver and w.after.hash == d.hash
                                 for w in hr.write_set):
            return True
        top = self.store.conn.execute("SELECT MAX(ver) FROM versions WHERE obj = ?", (d.obj,)).fetchone()[0]
        if top != d.ver:
            return True  # head rolled back behind a newer version row
        seq = head[0] + 1
        while (r := self._record_at(seq)) is not None:  # the head must be the LAST write to the item in the log
            if any(w.obj == d.obj for w in r.write_set):
                return True
            seq += 1
        cr = self._record_at(it.created_seq)
        if cr is None or cr.envelope is None or it.outbox_id not in cr.outbox_ids:
            return True
        if not any(w.obj == d.obj for w in cr.write_set):
            return True
        lineage = tuple(sorted(it.lineage, key=lambda e: (e.obj, e.ver)))
        want = tuple(sorted(cr.read_set, key=lambda e: (e.obj, e.ver)))
        if cr.envelope.tool == RERUN_TOOL:
            return self._unrecorded_rerun(it, cr, lineage, want)
        env = cr.envelope
        if (it.author, it.action_id) != (env.agent_id, env.action_id) or lineage != want:
            return True
        if it.idempotency_key not in {idempotency_key(env.agent_id, env.action_id, it.sink, n)
                                      for n in range(len(cr.outbox_ids))}:
            return True
        return it.release_tick != self.release_tick(cr.tick, want)

    def _unrecorded_rerun(self, it: OutboxItem, cr: Any, lineage: tuple, want: tuple) -> bool:
        """B3-30: an item re-held by an approved re-run (M14, CALL-02 B2). Its creating record is the executed
        ``ks.recover.rerun`` of ``ks.recovery`` on c-0, which lists the item in ``outbox_ids`` and writes it, with
        ``lineage`` = that record's read set (the re-run's tool reads). Author, action id, idempotency key and
        ``release_tick`` stay the original's, so they are checked against the original agent record of
        (author, action_id) that created the same ``outbox_id``, with the original tick and read set."""
        from ks.contracts import SYSTEM_CONN, Decision

        if (cr.envelope.agent_id != "ks.recovery" or cr.conn_id != SYSTEM_CONN or cr.decision != Decision.EXEC
                or not cr.sig_ok or lineage != want):
            return True
        seq = 1
        while (r := self._record_at(seq)) is not None and seq < cr.seq:
            e = r.envelope
            if (e is not None and r.conn_id != SYSTEM_CONN and r.decision == Decision.EXEC
                    and (e.agent_id, e.action_id) == (it.author, it.action_id) and it.outbox_id in r.outbox_ids):
                if it.idempotency_key not in {idempotency_key(e.agent_id, e.action_id, it.sink, n)
                                              for n in range(len(r.outbox_ids))}:
                    return True
                orig = tuple(sorted(r.read_set, key=lambda x: (x.obj, x.ver)))
                return it.release_tick != self.release_tick(r.tick, orig)
            seq += 1
        return True  # no original agent record created this item

    # --- internals ---------------------------------------------------------------------------------------
    def _tainted(self, lineage: Iterable[ReadEntry]) -> bool:
        return self.taint is not None and any(self.taint.is_tainted(e.obj, e.ver) for e in lineage)

    def _is_sensitive(self, obj: str) -> bool:
        table, _, field = split_obj_id(obj)
        return field is not None and f"{table}.{field}" in self.config.sensitive_fields

    def _sensitive_tick(self, lineage: Iterable[ReadEntry]) -> int | None:
        best = None
        for e in lineage:
            if not self._is_sensitive(e.obj):
                continue
            row = self.store.conn.execute("SELECT seq FROM versions WHERE obj = ? AND ver = ?",
                                          (e.obj, e.ver)).fetchone()
            if row is None:
                continue
            if self._tick_of_seq is None:
                raise LookupError("no tick source: cannot place a sensitive-field version")
            t = self._tick_of_seq(row[0])
            if (best is None or t > best):
                best = t
        return best

    def _sensitive_moved(self, lineage: Iterable[ReadEntry]) -> bool:
        """A sensitive field the item read now holds a different value. B3-27: compared by hash as well as version,
        so an approved restore back to the value the item read (the hero's iban) does not strand honest items that
        read the original; an item that read the changed version still differs from the restored head."""
        for e in lineage:
            if self._is_sensitive(e.obj):
                head = self.store.conn.execute("SELECT head_ver, head_hash FROM objects WHERE obj = ?",
                                               (e.obj,)).fetchone()
                if head is not None and head[0] != e.ver and head[1] != e.hash:
                    return True
        return False

    def _count(self) -> int:
        return self.store.conn.execute("SELECT COUNT(*) FROM objects WHERE obj LIKE 'outbox:%'").fetchone()[0]

    def _by_key(self) -> dict[str, str]:
        out = {}
        for (v,) in self.store.conn.execute(
                "SELECT head_value FROM objects WHERE obj LIKE 'outbox:%' AND head_value IS NOT NULL"):
            o = json.loads(v)
            out[o["idempotency_key"]] = o["outbox_id"]
        return out
