"""ks.inject: fault injection per ADR-06 (``ks inject <F> --seed S --culprit A``).

The world's agents already carry the faulty behaviour behind ``Schedule.fault`` (only the culprit slot deviates);
this package decides *when* (``t_inject`` seeded in [T/4, T/2]), builds the faulty and the S* schedules, and
holds the hero precondition guard. ``InjectSpec`` is scorer-only: agents, gateway and the planner never see it
(the planner is t0-blind, ``test_t0_est_tcb_blind``). Imports ks.world and ks.rng only, never ks.runtime.
"""

from .spec import (FAULT_VARIANT, InjectSpec, RogueSpec, HeroGuardError, check_hero_guard, culprit_window, make_spec,
                   rogue_spec, t_inject_for, world_fault)

__all__ = ["FAULT_VARIANT", "InjectSpec", "RogueSpec", "rogue_spec", "HeroGuardError", "check_hero_guard", "culprit_window", "make_spec",
           "t_inject_for", "world_fault"]
