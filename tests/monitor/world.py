"""In-memory fixture world: builds C2 records with real versions, plus a read-only StateView and a side store."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "contracts"))
import samples  # noqa: E402

from ks.contracts import (TOMBSTONE_HASH, ActionClass, Decision, HistoryEntry, OutboxItem, OutboxStatus, ReadEntry,
                          Reason, Record, SideDomain, SideEntry, StateRead, VersionRef, WriteEntry, args_hash,
                          field_obj_id, idempotency_key, tagged_hash, value_hash)
from ks.contracts.hashing import Domain
from ks.monitor import Context, MonitorParams

GOOD_IBAN = "DE89370400440532013000"      # checksum-valid
EVIL_IBAN = "GB82WEST12345698765432"      # checksum-valid (the laundered, poisoned payee)
BAD_CHECK = "DE89370400440532013001"      # fails mod-97
PAYEE = field_obj_id("suppliers", "S-17", "iban")  # suppliers:S-17.iban


class MemSide:
    def __init__(self):
        self.d: dict[str, SideEntry] = {}

    def put(self, domain, value):
        e = SideEntry(hash=tagged_hash({SideDomain.VALUE: Domain.VALUE}[domain], value), domain=domain,
                      value=value, redacted=False)
        self.d[e.hash] = e
        return e.hash

    def get(self, h):
        return self.d.get(h)

    def redact(self, h):
        self.d[h] = SideEntry(hash=h, domain=self.d[h].domain, value=None, redacted=True)


class World:
    def __init__(self):
        self.records: list[Record] = []
        self.side = MemSide()
        self.head: dict[str, tuple[int, str]] = {}
        self.hist: dict[str, list[HistoryEntry]] = {}
        self.authors: dict[str, str] = {}
        self.witness = []
        self.n_ob = 0

    # --- StateView ---
    def get(self, obj):
        if obj not in self.head:
            return None
        ver, h = self.head[obj]
        e = self.side.get(h)
        return StateRead(obj=obj, value=e.value if e else None, ver=ver, author=self.authors[obj], hash=h)

    def history(self, obj):
        return list(self.hist.get(obj, ()))

    def heads(self):
        return {o: VersionRef(ver=v, hash=h) for o, (v, h) in self.head.items()}

    def ctx(self, **kw) -> Context:
        return Context(records=list(self.records), state=self, side=self.side,
                       params=kw.pop("params", MonitorParams()), witness=kw.pop("witness", self.witness), **kw)

    # --- building records ---
    def read(self, obj):
        v, h = self.head[obj]
        return ReadEntry(obj=obj, ver=v, hash=h)

    def act(self, agent, tool, *, tick, reads=(), writes=None, cls=ActionClass.R, outbox=(), args=None,
            decision=Decision.EXEC, reason=Reason.OK, sig_ok=True, conn=None, signer=None, off_log=None):
        seq = len(self.records) + 1
        env = samples.envelope(agent=agent, action_id=f"{agent}-{seq}", tool=tool, args=args or {"n": seq},
                               signer=signer, nonce=hashlib.sha256(f"n{seq}".encode()).hexdigest()[:32],
                               expiry_tick=tick + 2, parent_action_id=None, act_chain=())
        ws = []
        if decision == Decision.EXEC:
            for obj, val in (writes or {}).items():
                before = self.head.get(obj)
                h = TOMBSTONE_HASH if val is None else value_hash(val)
                if val is not None:
                    self.side.put(SideDomain.VALUE, val)
                after = (before[0] + 1 if before else 1, h)
                ws.append(WriteEntry(obj=obj, before=VersionRef(ver=before[0], hash=before[1]) if before else None,
                                     after=VersionRef(ver=after[0], hash=after[1])))
                self.head[obj] = after
                self.authors[obj] = agent
                self.hist.setdefault(obj, []).append(HistoryEntry(obj=obj, ver=after[0], hash=h, author=agent,
                                                                  seq=seq, action_id=env.action_id))
        r = Record.seal(
            prev_hash=self.records[-1].hash if self.records else samples.GENESIS_HASH, seq=seq, tick=tick,
            ts_us=1_000_000_000 + seq, record_id=f"r-{seq:06d}", conn_id=conn or f"c-{1 + len(agent) % 5}",
            envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=sig_ok, decision=decision,
            reason=reason, policy_rule=None, action_class=cls,
            read_set=tuple(sorted((self.read(o) if isinstance(o, str) else o for o in reads), key=lambda e: e.obj))
            if decision != Decision.DENY else (),
            write_set=tuple(sorted(ws, key=lambda w: w.obj)), outbox_ids=tuple(outbox),
            result_hash=None, control=None, reexec_of=None)
        self.records.append(r)
        return r

    def queue_email(self, agent, *, tick, payload, reads=()):
        self.n_ob += 1
        oid = f"ob-{self.n_ob:06d}"
        ph = self.side.put(SideDomain.VALUE, payload)
        seq = len(self.records) + 1
        item = OutboxItem(outbox_id=oid, author=agent, action_id=f"{agent}-{seq}", created_seq=seq,
                          sink="email", action_class="I1", payload_hash=ph,
                          idempotency_key=idempotency_key(agent, f"{agent}-{seq}", "email"),
                          lineage=tuple(sorted((self.read(o) for o in reads), key=lambda e: e.obj)),
                          status=OutboxStatus.QUEUED, release_tick=tick + 6, dispatched_seq=None)
        return self.act(agent, "comms.send_email", tick=tick, reads=reads, writes={f"outbox:{oid}": item.to_obj()},
                        cls=ActionClass.I1, outbox=(oid,))

    def checkpoint(self):
        """Witness the current head (a healthy witness)."""
        from ks.contracts import WitnessCheckpoint
        r = self.records[-1]
        self.witness.append(WitnessCheckpoint(witness_id="ks.witness", seq=r.seq, tick=r.tick, head=r.hash,
                                              count=len(self.witness) + 1, sig=None))

    def off_log_write(self, obj, value, author="mallory"):
        """A write that bypassed the gateway: state changes, no record."""
        h = self.side.put(SideDomain.VALUE, value)
        prev = self.head.get(obj)
        ver = prev[0] + 1 if prev else 1
        self.head[obj] = (ver, h)
        self.authors[obj] = author
        self.hist.setdefault(obj, []).append(HistoryEntry(obj=obj, ver=ver, hash=h, author=author, seq=1,
                                                          action_id="bypass-1"))


def clean_world() -> World:
    """seed (ks.gateway-free), ticket, honest supplier update long ago, payment on the old payee, balanced ledger."""
    w = World()
    w.act("seeder", "world.seed", tick=0, writes={
        "suppliers:S-17": {"name": "Acme Steel", "unit_price": 100}, PAYEE: GOOD_IBAN,
        "suppliers:S-22": {"name": "Beta", "unit_price": 50}, "ledger:L-1": {"debit": 100, "credit": 100}})
    w.act("crm", "crm.update_supplier", tick=1, reads=["suppliers:S-17"], writes={PAYEE: GOOD_IBAN})
    # crm re-writes the same IBAN at tick 1; a payment far later is outside any window
    w.act("billing", "ledger.post", tick=30, reads=["ledger:L-1"], writes={"ledger:L-2": {"debit": 5, "credit": 5}})
    w.act("payments", "payments.send", tick=40, reads=[PAYEE, "suppliers:S-17"], cls=ActionClass.I1)
    w.act("comms", "comms.send_email", tick=41, reads=["suppliers:S-17"], cls=ActionClass.R)
    w.queue_email("comms", tick=42, payload={"to": "ops@example.com", "subject": "Weekly", "body": "Order 17 shipped."})
    w.act("crm", "crm.update_supplier", tick=43, reads=["suppliers:S-22"],
          writes={"suppliers:S-22": {"name": "Beta", "unit_price": 60}})
    w.checkpoint()
    return w


def hero_world() -> World:
    """RT9 laundering: intake (rogue) files a ticket carrying EVIL; crm (honest) applies it; payments pays."""
    w = clean_world()
    w.act("intake", "ticket.create", tick=50, cls=ActionClass.C,
          writes={"tickets:T-3": {"type": "supplier_bank_update", "supplier": "S-17", "iban": EVIL_IBAN}})
    w.act("crm", "crm.update_supplier", tick=51, reads=["tickets:T-3", "suppliers:S-17"], writes={PAYEE: EVIL_IBAN})
    w.act("payments", "payments.send", tick=52, reads=[PAYEE, "suppliers:S-17"], cls=ActionClass.I1)
    w.checkpoint()
    return w
