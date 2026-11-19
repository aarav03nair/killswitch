"""B3-46 (contracts 1.4): the gateway tags each read-set entry view|tool and keeps both versions when the view and
the tool disagree on one object (Panel ruling on B3-41)."""

from __future__ import annotations

from ks.contracts import Decision, Reason, ViewEntry, value_hash
from ks.gateway import Execution
from ks.world.agents import AGENT_IDS
from ks.world.tools import WorldDispatcher

from .test_pipeline import A, build, frame


def test_read_set_entries_are_tagged_view_or_tool(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    r = g.admit("c-1", frame(keys)).record
    assert r.decision == Decision.EXEC
    tool = {(e.obj, e.ver) for e in g.tool_reads}
    assert tool and all(e.source == "tool" for e in g.tool_reads)
    assert all(e.source == "view" for e in g.view_reads)
    for e in r.read_set:
        assert e.source == ("tool" if (e.obj, e.ver) in tool else "view")
    assert ("tickets:T-0000", 1) in {(e.obj, e.ver) for e in r.read_set if e.source == "tool"}


def test_view_and_tool_at_different_versions_keep_both(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)
    val = {"stale": True}
    other = ViewEntry(obj="tickets:T-0000", ver=7, hash=value_hash(val), value=val)
    g.delivered[A] = tuple(sorted((*[v for v in g.delivered[A] if v.obj != other.obj], other),
                                  key=lambda v: v.obj))
    r = g.admit("c-1", frame(keys)).record
    assert r.decision == Decision.EXEC
    got = [(e.ver, e.source) for e in r.read_set if e.obj == "tickets:T-0000"]
    assert got == [(1, "tool"), (7, "view")]


def test_tool_naming_one_object_twice_is_a_recorded_deny(tmp_path):
    g, keys, ctl, store, _ = build(tmp_path)
    g.open(1, AGENT_IDS)

    class Twice(WorldDispatcher):
        def execute(self, env, txn):
            ex = super().execute(env, txn)
            return Execution(ex.result, (*ex.read_set, ex.read_set[0]), ex.write_set, ex.outbox)

    g.dispatcher = Twice()
    r = g.admit("c-1", frame(keys)).record
    assert (r.decision, r.reason) == (Decision.DENY, Reason.TOOL_ERROR)
    assert not r.read_set
