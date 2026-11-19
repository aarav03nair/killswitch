"""Injection spec, seeded ``t_inject`` and the hero precondition guard (ADR-06, ADR-06-metrics)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ks.rng import draw_int
from ks.world.agents import FAULTS, QUIET_TICKS, Schedule, culprit_of

__all__ = ["FAULT_VARIANT", "InjectSpec", "HeroGuardError", "check_hero_guard", "culprit_window", "make_spec",
           "t_inject_for", "world_fault"]

FAULT_VARIANT = {"f2plus_c": "f2plus_c", "f2plus_x": "f2plus_x"}
"""Fault -> honest-world variant; every other fault uses the base ``f2plus`` world."""


class HeroGuardError(AssertionError):
    """The hero precondition (crm silent in (t_inject+1, t_inject+QUIET_TICKS]) or the F2+c requirement failed."""


def t_inject_for(seed: int, ticks: int = 120) -> int:
    """``RunConfig.fault_tick``: uniform in [T/4, T/2] (ADR-06-metrics), a function of ``(seed, T)`` only."""
    lo, hi = ticks // 4, max(ticks // 4, ticks // 2)
    return lo + draw_int(seed, "world/hero_tick", 0, hi - lo + 1)


@dataclass(frozen=True)
class InjectSpec:
    """Scorer-only injection record. ``schedule`` is the faulty world; ``oracle_schedule`` is S* (same
    ``hero_tick`` and variant, fault off) so both share one honest schedule."""

    fault: str
    seed: int
    ticks: int
    t_inject: int
    culprit: str
    variant: str

    @property
    def schedule(self) -> Schedule:
        return Schedule(self.t_inject, self.fault, self.variant)

    @property
    def oracle_schedule(self) -> Schedule:
        return Schedule(self.t_inject, None, self.variant)


def make_spec(fault: str, seed: int, *, ticks: int = 120, culprit: str | None = None,
              t_inject: int | None = None) -> InjectSpec:
    """Build the spec for fault id ``fault`` (``FAULTS``). ``culprit`` may only restate the fault's own culprit
    slot (the world fixes it); anything else is a ValueError."""
    if fault not in FAULTS:
        raise ValueError(f"unknown fault {fault!r}")
    want = culprit_of(fault)
    if culprit is not None and culprit != want:
        raise ValueError(f"fault {fault} is committed by {want!r}, not {culprit!r}")
    if t_inject is not None and not ticks // 4 <= t_inject <= ticks // 2:
        raise ValueError(f"t_inject {t_inject} outside [T/4, T/2] = [{ticks // 4}, {ticks // 2}]")
    t = t_inject_for(seed, ticks) if t_inject is None else t_inject
    return InjectSpec(fault, seed, ticks, t, want, FAULT_VARIANT.get(fault, "f2plus"))


def culprit_window(spec: InjectSpec, suspend_tick: int | None = None) -> range:
    """Ticks in which the culprit's honest writes would be lost with the rest of its work: (t_inject+1, suspend]
    (X3d); without a suspension, the guard window ``QUIET_TICKS``."""
    end = spec.t_inject + QUIET_TICKS if suspend_tick is None else suspend_tick
    return range(spec.t_inject + 2, end + 1)


def check_hero_guard(spec: InjectSpec, culprit_write_ticks: Iterable[int], suspend_tick: int) -> None:
    """``test_hero_precondition_guard`` (ADR-06 B2): for F2+ and F2+x the culprit writes nothing in
    (t_inject+1, suspend_tick] and suspend_tick <= t_inject+QUIET_TICKS (else the quiet claim, hence C=0, is not
    guaranteed: raise); for F2+c it writes at least once there. Other faults are not hero-shaped: no check."""
    if spec.fault not in ("f2plus", "f2plus_c", "f2plus_x"):
        return
    window = culprit_window(spec, suspend_tick)
    inside = sorted(t for t in culprit_write_ticks if t in window)
    if spec.fault == "f2plus_c":
        if not inside:
            raise HeroGuardError("f2plus_c: culprit did no honest work in (t_inject+1, suspend]")
        return
    if suspend_tick > spec.t_inject + QUIET_TICKS:
        raise HeroGuardError(f"{spec.fault}: suspend at {suspend_tick} is past t_inject+QUIET "
                             f"({spec.t_inject + QUIET_TICKS}); C=0 is not guaranteed")
    if inside:
        raise HeroGuardError(f"{spec.fault}: culprit wrote at ticks {inside} in the quiet window")


def world_fault(cli_id: str) -> str:
    """The one fault-name mapping (CLI, ``RunConfig.fault``, scorer): ``F2+``/``F2+x``/``F2+c`` to the world's
    ``f2plus``/``f2plus_x``/``f2plus_c``; ``F1`` to ``f1``; already-internal names pass through."""
    f = cli_id.lower().replace("+", "plus")
    return f[:-1] + "_" + f[-1] if f.startswith("f2plus") and len(f) > 6 and f[6] != "_" else f
