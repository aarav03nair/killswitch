"""Run setup decided before anything is spawned (B3-10): scenario wiring, default run_id / run dir, and the
isolation pin check (SKEL-01 findings 1, 4, 12).

* ``skeleton``: ``agent_NN`` agents running ``ks.world.skeleton`` (SKEL-01).
* ``world``: the 10 ADR-06 agents (``ks.world.agents.AGENT_IDS``) running ``ks.world.agents.step`` on their
  ``TickFrame.view``, behind ``ks.world.tools.WorldDispatcher``.

``RunConfig.isolation`` is fixed from the environment before spawn (it is covered by ``config_hash``). After spawn
the runtime reads every child's uid back from ``/proc``; :func:`isolation_problems` lists every contradiction and
the run aborts before tick 0 if there is one. Degraded mode (not Linux root, e.g. native macOS) promises nothing,
so it never aborts; the banner says per-agent attribution is VOID.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ks.rng import draw_int

__all__ = ["SCENARIOS", "Scenario", "scenario", "default_run_id", "default_out", "hero_tick", "isolation_problems",
           "refuse_existing", "IsolationError", "WORLD_TICKS_UNTIL_STATE"]

SCENARIOS = ("skeleton", "world")

WORLD_TICKS_UNTIL_STATE = 1
"""TODO(B3-11/B3-41): the gateway passes ``txn=None`` to the dispatcher, so a state-writing world tool would hit
the gateway's fail-stop. Every ADR-06 agent is idle at tick 0, so a world run is capped at 1 tick until the
gateway wires the ks.state txn and the seed record (D-SEQ1 in ks/ARCHITECTURE.md). Then delete this cap."""


class IsolationError(RuntimeError):
    """The /proc readback contradicts ``RunConfig.isolation`` (or the uids the runtime asked for)."""


@dataclass(frozen=True)
class Scenario:
    name: str
    agent_ids: tuple[str, ...]
    sensitive_fields: tuple[str, ...]
    behaviour: str
    """Module agent processes import for ``step``."""
    agent_argv: tuple[str, ...]
    """Extra argv for ``ks.runtime.agent_template`` (same for every agent)."""

    def dispatcher(self) -> Any:
        if self.name == "world":
            from ks.world.tools import WorldDispatcher
            return WorldDispatcher()
        from ks.world.tools import SkeletonDispatcher
        return SkeletonDispatcher()


def hero_tick(seed: int, ticks: int) -> int:
    """h in [T/4, T/2] (ADR-06-metrics: t_inject seeded in [T/4, T/2]), one ks.rng draw. A scenario parameter
    every agent gets, set even with the fault off so S* and the faulty run share one honest schedule."""
    lo, hi = ticks // 4, max(ticks // 4, ticks // 2)
    return lo + draw_int(seed, "world/hero_tick", 0, hi - lo + 1)


def scenario(name: str, *, agents: int | None, seed: int, ticks: int) -> Scenario:
    """Resolve ``--scenario`` and ``--agents``. Raises ValueError on a bad combination."""
    if name == "skeleton":
        n = 2 if agents is None else agents
        if n < 1:
            raise ValueError("need at least one agent")
        return Scenario("skeleton", tuple(f"agent_{i:02d}" for i in range(n)), (), "ks.world.skeleton", ())
    if name == "world":
        from ks.world.agents import AGENT_IDS
        from ks.world.registry import SENSITIVE_FIELDS
        if agents not in (None, len(AGENT_IDS)):
            raise ValueError(f"the world scenario has exactly {len(AGENT_IDS)} agents (ADR-06)")
        if ticks > WORLD_TICKS_UNTIL_STATE:
            raise ValueError(f"the world scenario runs at most {WORLD_TICKS_UNTIL_STATE} tick until the gateway "
                             "wires the state txn (B3-11/B3-41)")
        return Scenario("world", AGENT_IDS, SENSITIVE_FIELDS, "ks.world.agents",
                        ("--hero-tick", str(hero_tick(seed, ticks))))
    raise ValueError(f"unknown scenario {name!r} (one of {', '.join(SCENARIOS)})")


def default_run_id(scenario_name: str, seed: int) -> str:
    """``<scenario>-s<seed>``: same-seed runs get the same config, so repro runs compare byte-identical."""
    return f"{scenario_name}-s{seed}"


def default_out(run_id: str) -> Path:
    """``/run/ks/<run_id>`` as Linux root (the live setup), else ``runs/<run_id>`` (degraded, e.g. macOS)."""
    if sys.platform == "linux" and os.geteuid() == 0:
        return Path("/run/ks") / run_id
    return Path("runs") / run_id


def refuse_existing(out: Path) -> None:
    """A run dir is never reused or merged into (checked before anything is spawned)."""
    if os.path.lexists(out):
        raise FileExistsError(f"run dir {out} already exists: refusing to start")


def isolation_problems(isolation: str, planned: Sequence[int | None], readback: Mapping[str, int | None],
                       witness_uid: int | None, planned_witness_uid: int | None, *, our_uid: int) -> list[str]:
    """Contradictions between what the config promised / the runtime asked for and what /proc shows.

    ``planned[i]`` is the uid agent i was meant to get (``None`` = ours, nothing to drop to); ``readback`` maps
    agent id -> uid read from /proc, in spawn order. ``per_agent_uid`` additionally needs distinct, non-root agent
    uids that differ from ours and from the witness."""
    out = []
    got = list(readback.items())
    if len(got) != len(planned):
        out.append(f"{len(got)} agents read back, {len(planned)} planned")
    for (a, u), want in zip(got, planned):
        if want is not None and u != want:
            out.append(f"{a}: uid {u} read back, {want} planned")
    if planned_witness_uid is not None and witness_uid != planned_witness_uid:
        out.append(f"witness: uid {witness_uid} read back, {planned_witness_uid} planned")
    if isolation == "per_agent_uid":
        uids = [u for _, u in got]
        if None in uids:
            out.append("per_agent_uid: an agent uid could not be read back")
        if 0 in uids or our_uid in uids:
            out.append("per_agent_uid: an agent runs as root or as the gateway uid")
        if len(set(uids)) != len(uids):
            out.append("per_agent_uid: agents share a uid")
        if witness_uid is None or witness_uid in uids or witness_uid in (0, our_uid):
            out.append("per_agent_uid: the witness uid is not separate")
    return out
