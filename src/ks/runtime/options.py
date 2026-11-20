"""RunOptions: the scenario knobs ``ks run`` / ``ks inject`` forward to ``ks.runtime.run`` (B3-12 review). Owner: maya.

One frozen value instead of signature introspection in the CLI: a renamed field breaks loudly here, and ``run``
raises NotImplementedError for any field it does not serve yet (``SERVED`` lists the ones it does). The default
``RunOptions()`` requests nothing, so a plain run is byte-identical to a run without options.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, fields

__all__ = ["RunOptions", "SERVED"]

# Fields ks.runtime.run implements today. Grow this as features land; the CLI placeholder test reads it.
SERVED: frozenset[str] = frozenset({"pause_at", "step", "monitor", "decisions", "decisions_head", "fault", "culprit",
                                    "hold", "pause_on_alert", "rogue", "slot", "no_lineage_hold"})
# B3-13 pacing (ADR-07 L1); B3-19 monitor; B3-30 anchored decisions replay (R3, B3-20); B3-27 fault/culprit/hold


@dataclass(frozen=True, slots=True, kw_only=True)
class RunOptions:
    fault: str | None = None                  # ks.inject fault id (e.g. "F2+"); validated by the CLI via ks.inject
    culprit: str | None = None                # agent id the fault is injected into; needs fault
    hold: int | None = None                   # lineage hold window in ticks; 0 is a real bench value
    pause_at: tuple[int, ...] | None = None   # pause the live gateway before these ticks
    step: bool = False                        # pause between every tick
    rogue: str | os.PathLike[str] | None = None  # jury Python run in place of ``slot``
    slot: str | None = None                   # agent replaced by ``rogue``
    decisions: str | os.PathLike[str] | None = None  # anchored run whose operator decisions are replayed
    decisions_head: str | None = None         # that run's RunAnchor line (ks verify --head); needs decisions
    monitor: bool = False                     # B3-19: scan records after every tick; hard alert -> suspend (world only)
    pause_on_alert: bool = False              # B3-27 pacing: pause after the first monitor suspend and after a recovery apply
    no_lineage_hold: bool = False             # B3-51 D10 contrast: with hold 0, also drop the taint (lineage) hold
    with_baselines: bool = False              # also run the baseline recoveries for scoring

    def __post_init__(self) -> None:
        if self.no_lineage_hold and self.hold != 0:
            raise ValueError("no_lineage_hold is the D10 contrast and needs hold 0")
        if self.pause_at is not None:
            object.__setattr__(self, "pause_at", tuple(self.pause_at))
            if any(not isinstance(t, int) or isinstance(t, bool) or t < 0 for t in self.pause_at):
                raise ValueError("pause_at must be non-negative tick numbers")
        if self.pause_on_alert and not self.monitor:
            raise ValueError("pause_on_alert needs monitor")
        if self.pause_at is not None and self.step:
            raise ValueError("pause_at and step are mutually exclusive")
        if self.rogue is not None and self.fault is not None:
            raise ValueError("rogue and fault are mutually exclusive")
        if self.decisions is not None and self.rogue is not None:
            raise ValueError("decisions and rogue are mutually exclusive (R3)")
        if self.decisions_head is not None and self.decisions is None:
            raise ValueError("decisions_head needs decisions")
        if self.slot is not None and self.rogue is None:
            raise ValueError("slot needs rogue")
        if self.culprit is not None and self.fault is None:
            raise ValueError("culprit needs fault")
        if self.hold is not None and (isinstance(self.hold, bool) or not isinstance(self.hold, int) or self.hold < 0):
            raise ValueError("hold must be a non-negative number of ticks")

    def requested(self) -> tuple[str, ...]:
        """Names of fields set away from their default, in declaration order."""
        out = []
        for f in fields(self):
            v = getattr(self, f.name)
            if v is not None and v is not False:
                out.append(f.name)
        return tuple(out)

    def unserved(self) -> tuple[str, ...]:
        return tuple(n for n in self.requested() if n not in SERVED)
