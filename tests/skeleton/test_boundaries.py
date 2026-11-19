"""B3-37: module seams before the parallel build (barrier = I/O + timing; tools behind ToolDispatcher; ks.rng)."""

import ast
from pathlib import Path

import ks
from ks.contracts import ActionClass, Decision, Reason
from ks.gateway import Gateway, InFrame, ToolDispatcher
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
    assert not names & {"decode_frame", "SubmitFrame", "Envelope", "Decision", "Reason", "TickFrame"}
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
