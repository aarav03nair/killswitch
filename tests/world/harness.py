"""Tiny in-process world loop for tests: seed, then per tick build views and run agents in agent_id order."""

from __future__ import annotations

from types import SimpleNamespace

from ks.world.agents import AGENT_IDS, Schedule, step
from ks.world.scenario import build_view, open_world_store, seed_state
from ks.world.tools import OutboxRequest, WorldDispatcher, WorldTxn


def env_of(agent, act):
    return SimpleNamespace(agent_id=agent, action_id=act.action_id, tool=act.tool, args=act.args)


def run_world(tmp_path, seed, ticks, sched, name="s.db"):
    store = open_world_store(tmp_path / name)
    with store.txn():
        seed_state(store)
    disp = WorldDispatcher()
    seq = 1
    log = []  # (tick, agent, tool, args, Execution)
    for t in range(1, ticks + 1):
        snap = seq + 1
        for a in AGENT_IDS:
            view = build_view(store, a, visible_to=snap)
            act = step(a, seed, t, view, sched)
            if act is None:
                continue
            seq += 1
            with store.txn():
                ex = disp.execute(env_of(a, act), WorldTxn(store, seq))
            log.append((t, a, act.tool, act.args, ex))
    return store, log
