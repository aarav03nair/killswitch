"""SKEL-01 agent behaviour: one deterministic action per tick, a function of (seed, agent, tick) only.
The real scenario agents (crm, billing, ...) replace this in Sprint 3 (tara)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ks.runtime.rng import draw_int

__all__ = ["Action", "step"]


@dataclass(frozen=True)
class Action:
    tool: str
    args: dict[str, Any]
    action_id: str


def step(agent_id: str, seed: int, tick: int) -> Action | None:
    """Every third tick a ``skel.noop``, otherwise a ``skel.echo`` carrying a seeded number."""
    action_id = f"{agent_id}-t{tick}"
    if tick % 3 == 2:
        return Action("skel.noop", {}, action_id)
    return Action("skel.echo", {"n": draw_int(seed, f"world/{agent_id}", tick, 1000), "tick": tick}, action_id)
