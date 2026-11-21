<!-- S4-35, vikram, 21 Nov 2026 -->
# S4-35: why late-inject F2+ seeds end with R = 1/6 at T=120

**Verdict:** the leftover is a **scoring artefact (oracle vs policy mismatch)**. It is not a recovery, taint or planner bug. The B key that counts as "left" is an honest `docs.purge` outbox item. S\* dispatches it. The real run never executes it, because the gateway holds every I2 action for approval (ADR-03, `p.i2_approval`) and nobody in the bench approves policy holds. The same item explains every non-zero `collateral_stall` at T=120. No code was changed, so the T=40 numbers do not move.

## 1. Repro (seed 2, F2+, H=6, system, T=120)

- [Fact] I ran it natively (macOS, HEAD 588daaf + working tree) with `ks.bench.runner.run_cell("F2+", 2, 6, "system", 120, out)`. Result: R = 1/6, C = 0/623, collateral_stall = 1/1123 (basis s_star), t_inject 53, t_rec 56. This matches the container cell in `/private/tmp/claude-501/s414/bench-t120/F2p/h6/system/s2/score.json`. Per-agent uids are not needed here: R and collateral_stall are computed from state, not from attribution.
- [Fact] `ks bench --keep-runs` does not keep the run dirs. `bench()` ends with `shutil.rmtree(scratch)` (src/ks/bench/runner.py:291) whether or not `keep_runs` is set, so I called `run_cell` directly. This is a small separate bug. I have not fixed it because it is outside this issue.

## 2. Record evidence

B (folded at t_rec−1 = 55, ADR-06-metrics A1) has 6 keys. Five are restored and equal S\*_T. The one that is lost:

| key | S\* | real run |
|---|---|---|
| `outbox:c3a7e458…bf36` (docs purge) | docs.purge executed tick 49 (seq 213), dispatched at tick 55 (49 + H) | no ledger effect at all |

- [Fact] Agent code: `_docs` in src/ks/world/agents.py issues `docs.purge` when `t % 50 == 49`, i.e. at ticks 49 and 99. This is fault-independent.
- [Fact] Real run record: seq 255, tick 49, `docs.purge`, decision `hold`, reason `needs_approval`. Seq 536, tick 99, same. Neither has a later unhold or approval record. The bench approver releases only the outbox items that the recovery apply lists (runner.py, X4), plus the `ks.approve` of the plan.
- [Fact] Oracle: `run_pure` (src/ks/oracle/run.py) runs every agent action through `WorldDispatcher.execute` with no policy step. It models H and the G3 sensitive-field hold, but not `p.i2_approval`. So S\* executes both purges and dispatches them at ticks 55 and 105.
- [Fact] `fp_cost.held_honest_policy_actions` = 2 in all 60 F2+ cells at T=120 (all three baselines). Those are the two purges.

## 3. Why only seeds injected at ticks 53..58

- [Fact] Whether the tick-55 purge falls into B depends only on t_rec. B = {k : final_{t_rec−1}(k) ≠ S\*_{t_rec−1}(k)}. If t_rec − 1 ≥ 55 (t_rec ≥ 56), the missing purge already differs at the fold and enters B. Otherwise it is outside B and is counted in collateral_stall (non-culprit key ∉ B with final_T ≠ S\*_T).
- [Fact] Across the 20 system cells in the T=120 bench, every seed with t_rec ≥ 56 has R = 1/6 and collateral_stall n = 1: seeds 2 (t_rec 56), 8 (61), 13 (59), 14 (61), 16 (59). Every seed with t_rec ≤ 55 has R = 0 and collateral_stall n = 2. In every seed, R_n + collateral_stall_n = 2, which is the two purges (ticks 55 and 105). The tick-105 purge is always outside B, so collateral_stall is never 0 at T=120.
- [Fact] At T=40 the first purge request is at tick 49, which is after T, so neither the purge nor the policy hold happens. Seed 2 at T=40 (t_inject 11) has no `hold` decision in the record, and R = 0/9, C = 0/265, collateral_stall = 0/381. That is unchanged, and the counterfactual below gives the same numbers.

## 4. Counterfactual (proves the cause, changes nothing in the repo)

I re-scored the same seed 2 T=120 run dir with S\* minus docs purge effects (scratch script, `score_run` unchanged):

| S\* used | R | C | collateral_stall |
|---|---|---|---|
| as produced by `run_s_star` | 1/6 | 0/623 | 1/1123 |
| without the two docs purges | 0/5 | 0/623 | 0/1122 |

T=40 seed 2: both rows give R 0/9, C 0/265, collateral_stall 0/381.

## 5. What it means for quoted numbers

- [Our view] The system's recovery left nothing behind on these seeds. The 1/6 is S\* assuming an honest I2 action that the product's own policy (ADR-03) holds for a human. R at T=120 on F2+ is therefore an artefact of the oracle and the horizon. It should not be quoted as residual damage. The same applies to the snapshot and revert_culprit_only R numerators on those seeds (4/6 includes the same key) and to every collateral_stall at T=120.
- [Our view] T=40 (ADR-06-metrics A4 headline) is untouched, because T < 49.

## 6. Fix options (ADR-06 / oracle change, owner maya/pmo to decide; not done here)

1. **S\* models `p.i2_approval`** [Our view, recommended]: in `run_pure`, an I2 action that the run held for approval does not execute unless the run's record shows its approval (the same kind of mirroring as X3a). This keeps S\* "the same world under the same policy, minus the fault." It needs an ADR-06-metrics amendment (A-number) and a test where a seed with a late t_rec and T > 49 gives R = 0. The oracle may read the tool class from `ks.world.tools.CATALOGUE`, which avoids a `ks.policy` import (test_import_lint applies to ks.score).
2. **The bench approver approves honest policy holds** (unhold by `ks.operator`, ADR-03): the real run then executes the purges. This adds operator unholds to fp_cost on every T=120 cell.
3. **Leave it and footnote it:** quote T=120 R and collateral_stall only with this note.

Whichever option is chosen, the T=120 F2+ and F2+x tables in BENCH-S4-T120.md should carry this note until a rerun.
