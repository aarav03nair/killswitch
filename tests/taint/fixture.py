"""Record fixtures for ks.taint, built through the contracts (C2 Record, C1 Envelope, C4 Control/Alert).

``Book`` keeps object heads so read entries carry real (ver, hash); values are hashed, never stored in a record.
``f2plus()`` is a hand-built F2+ shape mirroring ks.world.agents (crm iban at h, S-22 price at h+1, consumers
after), with triage reading tickets + the clean ``suppliers:S-17`` row only (the acceptance's "clean row").
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "contracts"))
import samples  # noqa: E402

from ks.contracts import (CONTROL_TOOL, GENESIS_HASH, SEED_TOOL, ActionClass, Alert, AlertKind, Control, ControlOp, Decision,
                          Envelope, ObjVer, ReadEntry, Reason, Record, VersionRef, WriteEntry, value_hash)

H = 10


class Book:
    def __init__(self):
        self.records: list[Record] = []
        self.head: dict[str, tuple[int, str]] = {}
        self.n_ob = 0
        self.n_k = 0

    @property
    def next_seq(self) -> int:
        return len(self.records) + 1

    def read(self, obj: str) -> ReadEntry:
        v, h = self.head[obj]
        return ReadEntry(obj=obj, ver=v, hash=h)

    def _writes(self, writes):
        ws = []
        for obj, val in sorted((writes or {}).items()):
            before = self.head.get(obj)
            h = value_hash(val)
            after = (before[0] + 1 if before else 1, h)
            ws.append(WriteEntry(obj=obj, before=VersionRef(ver=before[0], hash=before[1]) if before else None,
                                 after=VersionRef(ver=after[0], hash=after[1])))
            self.head[obj] = after
        return tuple(ws)

    def _seal(self, *, tick, env, conn, decision=Decision.EXEC, reason=Reason.OK, rule=None, cls=ActionClass.R,
              reads=(), writes=(), outbox=(), control=None) -> Record:
        seq = self.next_seq
        r = Record.seal(prev_hash=self.records[-1].hash if self.records else GENESIS_HASH, seq=seq, tick=tick,
                        ts_us=1_000_000 * tick + seq, record_id=f"r-{seq:06d}", conn_id=conn,
                        envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=True, decision=decision,
                        reason=reason, policy_rule=rule, action_class=cls,
                        read_set=tuple(sorted(reads, key=lambda e: e.obj)), write_set=writes,
                        outbox_ids=tuple(outbox), result_hash=None, control=control, reexec_of=None)
        self.records.append(r)
        return r

    def _env(self, agent, tool, args, tick, act_id=None):
        seq = self.next_seq
        if agent.startswith("ks."):
            e = Envelope(agent_id=agent, action_id=act_id or f"k-{seq:06d}", parent_action_id=None, act_chain=(),
                         tool=tool, args=args, nonce=hashlib.sha256(f"n{seq}".encode()).hexdigest()[:32],
                         expiry_tick=tick + 2, epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)
            return e.with_sig(samples.sign(agent, e.signing_bytes()))
        return samples.envelope(agent=agent, action_id=act_id or f"{agent}-t{tick}-{seq}", tool=tool, args=args,
                                nonce=hashlib.sha256(f"n{seq}".encode()).hexdigest()[:32], expiry_tick=tick + 2,
                                parent_action_id=None, act_chain=())

    # --- record kinds ---
    def seed(self, objs: dict, *, tool=SEED_TOOL) -> Record:
        """D-SEQ1/D-15 seed record: ``ks.seed`` at seq 1, tick 0, ks.gateway on c-0, no policy_rule marker."""
        assert not self.records
        env = self._env("ks.gateway", tool, {"seed": True}, 0, act_id="seed")
        return self._seal(tick=0, env=env, conn="c-0", writes=self._writes(objs))

    def act(self, agent, tick, *, reads=(), writes=None, outbox=0, tool=None, cls=ActionClass.R) -> Record:
        rs = [self.read(o) if isinstance(o, str) else o for o in reads]
        ws = self._writes(writes)
        obs = []
        for _ in range(outbox):
            self.n_ob += 1
            obs.append(f"ob-{self.n_ob:06d}")
        env = self._env(agent, tool or f"{agent}.act", {"t": tick, "s": self.next_seq}, tick)
        return self._seal(tick=tick, env=env, conn=f"c-{1 + sum(map(ord, agent)) % 9}",
                          cls=ActionClass.I1 if outbox else cls, reads=rs, writes=ws, outbox=obs)

    def denied(self, agent, tick) -> Record:
        env = self._env(agent, f"{agent}.act", {"t": tick, "s": self.next_seq}, tick)
        return self._seal(tick=tick, env=env, conn=f"c-{1 + sum(map(ord, agent)) % 9}", decision=Decision.DENY,
                          reason=Reason.SUSPENDED)

    def suspend(self, agent, tick) -> Record:
        self.n_k += 1
        c = Control(control_id=f"k-{self.n_k:06d}", op=ControlOp.SUSPEND, target=f"agent:{agent}", epoch=self.n_k,
                    alert_id="a-000001", issued_by="ks.monitor", auto=True, reason="hard_alert")
        env = self._env("ks.monitor", CONTROL_TOOL, c.to_obj(), tick, act_id=c.control_id)
        return self._seal(tick=tick, env=env, conn="c-0", rule="hard_alert_suspend", control=c)

    def recovery(self, tick, *, reads=(), writes=None) -> Record:
        env = self._env("ks.recovery", "ks.recover.restore", {"n": self.next_seq}, tick)
        return self._seal(tick=tick, env=env, conn="c-0", reads=[self.read(o) for o in reads],
                          writes=self._writes(writes))

    def ov(self, obj) -> ObjVer:
        return ObjVer(obj=obj, ver=self.head[obj][0])


def alert(evidence, *, seq=1, aid="a-000001", detector="inv.beneficiary_changed_then_paid") -> Alert:
    return Alert(alert_id=aid, tick=1, seq=seq, detector=detector, kind=AlertKind.INVARIANT, hard=True,
                 evidence_seqs=(seq,), evidence_versions=tuple(sorted(evidence, key=lambda v: (v.obj, v.ver))),
                 root_candidates=(), conn_id=None)


SUP = ("S-17", "S-22", "S-31")


def _sup_rows():
    return [f"suppliers:{s}" for s in SUP]


def _sup_all():
    return [o for s in SUP for o in (f"suppliers:{s}", f"suppliers:{s}.iban")]


def f2plus() -> tuple[Book, dict]:
    """F2+ (B2): crm writes S-17.iban v2 at h and S-22 v2 (price) at h+1; consumers read them; triage edits the
    S-17 row (risk_note) at h+2 reading tickets and the S-17 row only. Returns (book, named records)."""
    b = Book()
    seed = {}
    for s in SUP:
        seed[f"suppliers:{s}"] = {"name": s, "price": 100, "terms": 30, "risk_note": ""}
        seed[f"suppliers:{s}.iban"] = f"DE00{s}"
    seed.update({"customers:C-01": {"tier": "std"}, "stock:SKU-1": {"qty": 100}, "tickets:T-0000": {"p": "low"},
                 "docs:D-0000": {"title": "handbook"}})
    n = {"seed": b.seed(seed)}
    # honest history: crm edits S-31 terms at tick 3 (crm's view then holds its own S-31 v2: a self-read)
    n["crm_honest"] = b.act("crm", 3, reads=["suppliers:S-31", "suppliers:S-31.iban", "customers:C-01"],
                            writes={"suppliers:S-31": {"name": "S-31", "price": 100, "terms": 21, "risk_note": ""}})
    n["intake"] = b.act("intake", 5, reads=["tickets:T-0000"], writes={"tickets:T-0005": {"p": "low"}})
    n["inv1"] = b.act("inventory", 6, reads=["stock:SKU-1"], writes={"stock:SKU-1": {"qty": 99}})
    # h: the fault. crm's tick read set = adapter (S-17 row + iban) + view (supplier rows, customers)
    n["crm_iban"] = b.act("crm", H, reads=[*_sup_rows(), "suppliers:S-17.iban", "customers:C-01"],
                          writes={"suppliers:S-17.iban": "DE99ATTACKER"}, tool="crm.update_supplier")
    # h+1: billing drafts the S-17 invoice (sees iban v2); crm writes S-22 price x10
    n["bill_inv17"] = b.act("billing", H + 1, reads=[*_sup_all(), "customers:C-01"],
                            writes={"invoices:INV-0011": {"supplier": "S-17"}}, tool="billing.draft_invoice")
    n["crm_s22"] = b.act("crm", H + 1, reads=[*_sup_rows(), "suppliers:S-22.iban", "customers:C-01"],
                         writes={"suppliers:S-22": {"name": "S-22", "price": 1000, "terms": 30, "risk_note": ""}},
                         tool="crm.update_supplier")
    # h+2: ledger, payment (held), remittance email, triage edits S-17 risk_note (clean row only), docs
    n["bill_ledger"] = b.act("billing", H + 2, reads=["invoices:INV-0011", *_sup_all()],
                             writes={"ledger:L-0012": {"invoice": "INV-0011"}}, tool="ledger.post")
    n["comms"] = b.act("comms", H + 2, reads=["invoices:INV-0011", *_sup_all()], outbox=1,
                       tool="comms.send_email")
    n["docs"] = b.act("docs", H + 2, reads=["docs:D-0000"], writes={"docs:D-0012": {"title": "note"}})
    n["payments"] = b.act("payments", H + 2, reads=["invoices:INV-0011", *_sup_all()], outbox=1,
                          tool="payments.send")
    n["triage"] = b.act("triage", H + 2, reads=["tickets:T-0000", "tickets:T-0005", "suppliers:S-17"],
                        writes={"suppliers:S-17": {"name": "S-17", "price": 100, "terms": 30, "risk_note": "r"}},
                        tool="supplier.set_risk_note")
    # h+3: containment suspends crm at the control phase; crm is denied after
    n["suspend"] = b.suspend("crm", H + 3)
    n["bill_inv22"] = b.act("billing", H + 3, reads=[*_sup_all(), "customers:C-01"],
                            writes={"invoices:INV-0013": {"supplier": "S-22"}}, tool="billing.draft_invoice")
    n["crm_denied"] = b.denied("crm", H + 3)
    n["inv2"] = b.act("inventory", H + 3, reads=["stock:SKU-1"], writes={"stock:SKU-1": {"qty": 98}})
    n["reporter"] = b.act("reporter", H + 3, reads=["invoices:INV-0011"],
                          writes={"docs:RPT-0013": {"title": "report"}}, tool="docs.write")
    n["triage_later"] = b.act("triage", H + 4, reads=["tickets:T-0000", "tickets:T-0005", "suppliers:S-17"],
                              writes={"tickets:T-0005": {"p": "high"}}, tool="ticket.set_priority")
    return b, n
