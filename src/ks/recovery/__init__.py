"""ks.recovery: plan builder and dry-run diff (ADR-05 §6-7, C5). Owner: vikram.

``plan_recovery(records, taint, alert_id=...)`` -> :class:`Planned` (C5 plan without diff + console lanes);
``dry_run(store, planned, rerunner=None)`` -> :class:`DryRun` (plan with diff, live digest unchanged);
``render(dry)`` the console text; ``write_plan(plan, rundir)`` (``<run>/plans/``). Re-run simulation (B3-24): ``ToolRerunner(dispatcher, args_of)`` as ``rerunner``;
conflict rule at apply (B3-29): ``recheck(store, dry, step)`` / ``first_stale`` give ``hold/stale_plan`` (M8);
oracle-assisted ``revert_culprit_only`` baseline (ADR-06); apply via c-0 is B3-30 (``apply_restore`` is the store-side primitive).

A3 (TCB blind): this package never imports ``RunConfig`` and never reads ``fault``/``culprit``/``fault_tick``.
"""

from .dryrun import C_IDENTICAL, ClassC, DryRun, Rerunner, Stale, StaleRerun, StatePerturbed, dry_run, render, write_plan
from .planner import (Held, Kept, NoPlan, Planned, Rider, action_ref, apply_restore, default_plan_id, plan_recovery,
                      restores_to_absent, with_diff)

from .baseline import ORACLE_NOTE, Baseline, revert_culprit_only
from .conflict import STALE_PLAN, conflict_flags, first_stale, recheck
from .rerun import (ArgsUnavailable, Effect, RerunError, RerunOutcome, ToolRerunner, args_from_mapping,
                    args_from_sidestore)

__all__ = ["ORACLE_NOTE", "Baseline", "revert_culprit_only", "STALE_PLAN", "conflict_flags", "first_stale", "recheck",
           "C_IDENTICAL", "ClassC", "ArgsUnavailable", "Effect", "RerunError", "RerunOutcome", "Stale", "StaleRerun", "ToolRerunner",
           "args_from_mapping", "args_from_sidestore", "DryRun", "Held", "Kept", "NoPlan", "Planned", "Rerunner", "Rider", "StatePerturbed", "action_ref",
           "apply_restore", "default_plan_id", "dry_run", "plan_recovery", "render", "restores_to_absent",
           "with_diff", "write_plan"]
