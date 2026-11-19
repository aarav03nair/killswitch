"""B3-21 fixtures: the B3-18 taint ``Book`` with every executed write mirrored into a real ``ks.state.Store``,
so record hashes and store versions agree (dry-run needs the store, the planner needs the records)."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from taint import fixture as tf  # noqa: E402

from ks.contracts import Decision, OutboxItem, OutboxStatus, idempotency_key  # noqa: E402
from ks.state import FieldSchema, Store  # noqa: E402

alert = tf.alert
H = tf.H
IBAN = "suppliers:S-17.iban"


class StoreBook(tf.Book):
    def __init__(self):
        super().__init__()
        self.store = Store(sqlite3.connect(":memory:", isolation_level=None), FieldSchema(["suppliers.iban"]))
        self._pending: dict = {}

    def act(self, agent, tick, *, reads=(), writes=None, outbox=0, tool=None, **kw):
        """As B3-23's ``Outbox.create``: each outbox id is a real ``outbox:<id>`` object in the record's write set
        (queued, derived key, lineage = the tool reads, ``release_tick = tick + 3``)."""
        if outbox:
            tool = tool or f"{agent}.act"
            sink = "payments" if tool.startswith("payments") else "email"
            action_id = f"{agent}-t{tick}-{self.next_seq}"
            lineage = sorted((self.read(o) if isinstance(o, str) else o for o in reads), key=lambda e: (e.obj, e.ver))
            writes = dict(writes or {})
            for i in range(outbox):
                oid = f"ob-{self.n_ob + 1 + i:06d}"
                writes[f"outbox:{oid}"] = OutboxItem(
                    outbox_id=oid, author=agent, action_id=action_id, created_seq=self.next_seq, sink=sink,
                    action_class="I1", payload_hash=tf.value_hash({"o": oid}),
                    idempotency_key=idempotency_key(agent, action_id, sink, i), lineage=tuple(lineage),
                    status=OutboxStatus.QUEUED, release_tick=tick + 3, dispatched_seq=None).to_obj()
        return super().act(agent, tick, reads=reads, writes=writes, outbox=outbox, tool=tool, **kw)

    def _writes(self, writes):
        self._pending = dict(writes or {})
        return super()._writes(writes)

    def _seal(self, **kw):
        r = super()._seal(**kw)
        pending, self._pending = self._pending, {}
        if pending and r.decision == Decision.EXEC:
            with self.store.txn():
                for o, v in sorted(pending.items()):
                    self.store.put(o, v, author=r.attributed_agent, seq=r.seq, action_id=r.envelope.action_id)
        return r


def f2plus():
    """The B3-18 F2+ fixture, built on a StoreBook."""
    orig = tf.Book
    tf.Book = StoreBook
    try:
        return tf.f2plus()
    finally:
        tf.Book = orig


SUP = tf.SUP


def seeded(extra=None) -> StoreBook:
    b = StoreBook()
    seed = {}
    for s in SUP:
        seed[f"suppliers:{s}"] = {"name": s, "price": 100, "terms": 30, "risk_note": ""}
        seed[f"suppliers:{s}.iban"] = f"DE00{s}"
    seed.update(extra or {})
    b.seed(seed)
    return b
