"""B3-41: the gateway is the authority on read/write sets; refusals are recorded denies; view joins the read set."""

from __future__ import annotations

import os
import signal
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ks.contracts import Decision, Exit, Reason, ReadEntry, VersionRef, WriteEntry
from ks.gateway import Execution
from ks.verify import verify
from ks.world.agents import AGENT_IDS
from ks.world.tools import WorldDispatcher

from .test_pipeline import A, build, frame


def _deny(g, keys, reason=Reason.TOOL_ERROR, **kw):
    r = g.admit("c-1", frame(keys, **kw)).record
    assert (r.decision, r.reason, r.sig_ok) == (Decision.DENY, reason, True), r
    assert not (r.read_set or r.write_set or r.outbox_ids) and r.result_hash is None
    return r


def _clean(g, keys, store):
    assert len(store.history("tickets:T-0000")) == 1 and not store.conn.in_transaction
    assert g.admit("c-1", frame(keys, action="next")).record.decision == Decision.EXEC


def test_sets_come_from_the_txn_and_include_view_reads(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    delivered = {e.obj for e in g.delivered[A]}
    r = g.admit("c-1", frame(keys)).record
    assert r.decision == Decision.EXEC
    from ks.gateway import writes_at
    assert r.write_set == writes_at(store, r.seq)
    objs = {e.obj for e in r.read_set}
    assert delivered <= objs and "tickets:T-0000" in objs  # the delivered view joined the read set (I1)
    assert {e.obj for e in g.view_reads} == delivered and "tickets:T-0000" in {e.obj for e in g.tool_reads}


def test_lying_write_set_is_a_recorded_deny(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)

    class Liar(WorldDispatcher):
        def execute(self, env, txn):
            ex = super().execute(env, txn)
            return Execution(ex.result, ex.read_set, (), ex.outbox)  # hides its write

    g.dispatcher = Liar()
    r = _deny(g, keys)
    assert r.seq == 2
    g.dispatcher = WorldDispatcher()
    _clean(g, keys, store)


def test_lying_read_set_is_a_recorded_deny(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)

    class Liar(WorldDispatcher):
        def execute(self, env, txn):
            ex = super().execute(env, txn)
            return Execution(ex.result, (ReadEntry(obj="tickets:T-0000", ver=1, hash="0" * 64),), ex.write_set)

    g.dispatcher = Liar()
    _deny(g, keys)
    g.dispatcher = WorldDispatcher()
    _clean(g, keys, store)


def test_dispatcher_side_commit_is_refused(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)

    class Commits(WorldDispatcher):
        def execute(self, env, txn):
            ex = super().execute(env, txn)
            txn.store.conn.execute("COMMIT")
            return ex

    g.dispatcher = Commits()
    _deny(g, keys)
    g.dispatcher = WorldDispatcher()
    _clean(g, keys, store)  # nothing landed behind the deny


def test_nonempty_outbox_before_b323_is_a_recorded_deny(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    from ks.gateway import Execution as E
    from ks.gateway.dispatch import OutboxRequest
    from ks.contracts import ActionClass

    class Emits(WorldDispatcher):
        def execute(self, env, txn):
            return E(None, outbox=(OutboxRequest("email", ActionClass.I1, {"to": "x"}),))

    g.dispatcher = Emits()
    _deny(g, keys)
    g.dispatcher = WorldDispatcher()
    _clean(g, keys, store)


@pytest.mark.parametrize("bad", ["S-17.iban", "S-17:x", "a.b"])
def test_policy_denies_dotted_object_ids(tmp_path, bad):
    from ks.policy import WorldPolicy
    g, keys, ctl, store, _ = build(tmp_path, policy=WorldPolicy())
    g.bind("c-2", "crm")
    g.open(1, AGENT_IDS)
    r = g.admit("c-2", frame(keys, agent="crm", tool="supplier.set_risk_note",
                             args={"supplier": bad, "note": "x"})).record
    assert (r.decision, r.reason, r.policy_rule) == (Decision.DENY, Reason.OUT_OF_SCOPE, "p.object_id")


def test_db_lock_on_seed_releases_seq_1(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    real = store.conn

    class Locked:
        def __getattr__(self, n):
            return getattr(real, n)

        def execute(self, sql, *a):
            if sql == "BEGIN IMMEDIATE":
                raise sqlite3.OperationalError("database is locked")
            return real.execute(sql, *a)

    store.conn = Locked()
    with pytest.raises(sqlite3.OperationalError):
        g.open(0, AGENT_IDS)
    assert g.recorder.seq == 0
    store.conn = real
    g.open(0, AGENT_IDS)  # retried: seed is seq 1, next admit works
    assert g.recorder.seq == 1
    g.open(1, AGENT_IDS)
    assert g.admit("c-1", frame(keys)).record.seq == 2


GW_CRASH = textwrap.dedent("""
    import os, sys, signal
    sys.path[:0] = [sys.argv[1] + "/src", sys.argv[1]]
    from pathlib import Path
    from tests.gateway.test_pipeline import build, frame
    from ks.world.agents import AGENT_IDS
    g, keys, ctl, store, _ = build(Path(sys.argv[2]))
    from ks.contracts import WitnessCheckpoint
    from ks.identity import sign_hex
    def witness(rec):
        w = WitnessCheckpoint(witness_id="ks.witness", seq=rec.seq, tick=rec.tick, head=rec.hash, count=rec.seq, sig=None)
        g.recorder.rundir.append(w.with_sig(sign_hex(keys.private("ks.witness"), w.signing_bytes())))
    g.open(0, AGENT_IDS)
    witness(list(g.recorder.rundir.records())[0])
    g.open(1, AGENT_IDS)
    witness(g.admit("c-1", frame(keys, action="a-1")).record)
    real_begin = g.recorder.begin
    class T:
        def __init__(self, t): self.t = t
        seq = property(lambda s: s.t.seq)
        def append(self, **kw):
            os.kill(os.getpid(), signal.SIGKILL)   # committed, never appended
        def rollback(self): self.t.rollback()
    g.recorder.begin = lambda: T(real_begin())
    g.admit("c-1", frame(keys, action="a-2", args={"id": "T-0000", "priority": "low"}))
""")


def test_crash_between_commit_and_append_through_the_gateway(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    p = subprocess.run([sys.executable, "-c", GW_CRASH, str(repo), str(tmp_path)], capture_output=True, text=True,
                       timeout=60)
    assert p.returncode == -signal.SIGKILL, p.stderr[-1500:]
    (tmp_path / "state.db").replace(tmp_path / "run" / "workspace" / "state.db")  # where ks run keeps it
    rep = verify(tmp_path / "run")
    assert (rep.exit, rep.reason) == (Exit.RECONCILE, "reconcile_mismatch"), rep
