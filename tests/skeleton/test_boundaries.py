"""B3-37: module seams before the parallel build (barrier = I/O + timing; tools behind ToolDispatcher; ks.rng)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import ks
from ks.contracts import ActionClass, Decision, Reason, ViewEntry, value_hash
from ks.gateway import Execution, Gateway, InFrame, OutboxRequest, ToolDispatcher, ViewProvider
from ks.world.tools import SkeletonDispatcher

from .test_units import _frame, gw  # noqa: F401  (fixture)

SRC = Path(ks.__file__).parent


def _imports(path: Path) -> set[str]:
    mods = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            mods |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:  # relative: resolve against the file's package
                pkg = path.relative_to(SRC.parent).with_suffix("").parts[:-node.level]
                base = ".".join(pkg + ((base,) if base else ()))
            mods.add(base)
            mods |= {f"{base}.{a.name}" for a in node.names}
    return mods


def test_world_never_imports_runtime():
    for p in (SRC / "world").rglob("*.py"):
        assert not any(m == "ks.runtime" or m.startswith("ks.runtime.") for m in _imports(p)), p


def test_rng_lives_in_ks_rng():
    assert not (SRC / "runtime" / "rng.py").exists()
    assert {m for m in _imports(SRC / "rng.py") if m.startswith("ks.")} <= {"ks.contracts", "ks.contracts.canonical"}


def test_barrier_is_io_and_timing_only():
    tree = ast.parse((SRC / "runtime" / "barrier.py").read_text())
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    imported = {a.asname or a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    banned = {"decode_frame", "SubmitFrame", "Envelope", "Decision", "Reason", "TickFrame"}
    assert not (names | imported) & banned
    assert not attrs & {"admit", "dispatcher", "classify", "execute", "epochs"}
    assert {"open", "tick"} <= attrs  # the only calls into the gateway's logic


def test_gateway_has_no_tool_table():
    import ks.gateway as g
    import ks.gateway.stub as stub
    assert not hasattr(g, "TOOLS") and not hasattr(stub, "TOOLS")
    assert "skel." not in (SRC / "gateway" / "stub.py").read_text()
    assert isinstance(SkeletonDispatcher(), ToolDispatcher)


def test_gateway_tick_orders_by_agent_and_dispatches(gw):  # noqa: F811
    g, keys = gw
    calls = []

    class Spy(SkeletonDispatcher):
        def execute(self, env, txn):
            calls.append(env.agent_id)
            return super().execute(env, txn)

    g.dispatcher = Spy()
    opened = g.open(2, ["agent_00", "agent_01"])
    assert {a: (f.tick, f.epoch) for a, f in opened.items()} == {"agent_00": (2, 0), "agent_01": (2, 0)}
    frames = [InFrame("agent_01", "c-2", _frame(keys, agent="agent_01", tick=2, action="b")),
              InFrame("agent_00", "c-1", _frame(keys, agent="agent_00", tick=2, action="a"))]  # arrival order
    replies = g.tick(2, frames)
    assert [c for c, _ in replies] == ["c-1", "c-2"] and calls == ["agent_00", "agent_01"]
    assert all((r.decision, r.reason) == (Decision.EXEC, Reason.OK) for _, r in replies)
    assert [r.action_class for r in g.recorder.rundir.records()] == [ActionClass.R] * 2
    assert isinstance(g, Gateway)


def test_importing_world_loads_no_runtime():  # B3-40: transitive, not just static imports
    code = ("import pkgutil, importlib, sys, ks.world\n"
            "for m in pkgutil.walk_packages(ks.world.__path__, 'ks.world.'): importlib.import_module(m.name)\n"
            "bad = sorted(m for m in sys.modules if m == 'ks.runtime' or m.startswith('ks.runtime.'))\n"
            "assert not bad, bad\n")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_open_fills_view_from_provider(gw):  # noqa: F811  B3-40
    g, _ = gw
    entry = ViewEntry(obj="suppliers:S-17", ver=4, hash=value_hash({"name": "Acme"}), value={"name": "Acme"})
    seen = []

    class Views:
        def view(self, agent_id, tick, state):
            seen.append((agent_id, tick))
            return (entry,) if agent_id == "agent_00" else ()

    assert isinstance(Views(), ViewProvider) and isinstance(SkeletonDispatcher(), ViewProvider)
    g.views = Views()
    opened = g.open(3, ["agent_00", "agent_01"])
    assert opened["agent_00"].view == (entry,) and opened["agent_01"].view == ()
    assert seen == [("agent_00", 3), ("agent_01", 3)] and g.delivered["agent_00"] == (entry,)


from ks.contracts import Decision, Reason  # noqa: E402


def test_execution_outbox_defaults_empty_and_is_not_dropped(gw):  # noqa: F811  B3-40
    g, keys = gw
    assert Execution(None).outbox == ()

    class Emits(SkeletonDispatcher):
        def execute(self, env, txn):
            return Execution(None, outbox=(OutboxRequest("email", ActionClass.I1, {"to": "x"}),))

    g.dispatcher = Emits()
    r = g.admit("c-1", _frame(keys)).record  # until B3-23 creates OutboxItems: a recorded deny, never dropped
    assert (r.decision, r.reason, r.outbox_ids) == (Decision.DENY, Reason.TOOL_ERROR, ())


def test_sets_refuses_write_without_txn(gw):  # noqa: F811  B3-40 panel change (1)
    from ks.contracts import WriteEntry
    from tests.contracts.samples import record_exec
    g, keys = gw
    w = record_exec().write_set[0]
    assert isinstance(w, WriteEntry)
    with pytest.raises(Exception, match="without a state txn"):
        g._sets(Execution(None, write_set=(w,)), None, 'agent_00')

    class Writes(SkeletonDispatcher):
        def execute(self, env, txn):
            return Execution(None, write_set=(w,))

    g.dispatcher = Writes()
    r = g.admit("c-1", _frame(keys)).record  # B3-41: a recorded deny
    assert (r.decision, r.reason, r.write_set) == (Decision.DENY, Reason.TOOL_ERROR, ())
    assert g._sets(Execution(None), None, "agent_00") == ((), ())
