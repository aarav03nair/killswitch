# ks bench: T=40 (ADR-06-metrics A4), seeds 1..20 (n=20)

Every number here is at **T=40**; do not compare ratio metrics with T=120. Cells are `median [min..max] k/n` (k = seeds with a non-null value), next to a p95 column (nearest-rank, 19th of 20; null = never = +inf).

Platform: run in the container (OrbStack, arm64, Linux) with per-agent uids, not native macOS (stated by pmo, 21 Nov, closing ALLOWED-NUMBERS G9; run dir `runs/bench-b3-33/` does not record it).

- `system`: the product path; its recovery is not told the culprit or t_inject.
- `snapshot` and `revert_culprit_only` are **oracle-assisted**: they are given t_inject and the culprit from the inject spec, which the system is not. They are upper-bound-style baselines, not products.
- `no_op`: pause (suspend) only, no recovery.
- `collateral_stall` is a **proxy**, basis `s_star` (A3): non-culprit keys outside B whose final_T differs from S*_T. Real runs have no unmirrored S0.
- `tti_*`/`ttc` for a denied or held bad action (F3: scope alert on a denied pii egress) follow ADR-06-metrics A5: first alert naming the culprit, measured from the bad action.

### F2+, H=6, T=40

| metric | system | system p95 | snapshot | snapshot p95 | revert_culprit_only | revert_culprit_only p95 | no_op | no_op p95 |
|---|---|---|---|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 1 [0..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 | 20 [5..46] 20/20 | 41 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| R | 0 [0..0] 20/20 | 0 | 3/5 [0..7/9] 20/20 | 7/9 | 3/5 [0..7/9] 20/20 | 7/9 | 1 [1..1] 20/20 | 1 |
| C | 0 [0..0] 20/20 | 0 | 34/263 [9/190..34/185] 20/20 | 33/193 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 3 [0..7] 20/20 | 7 | 2 [0..2] 20/20 | 2 | 27 [1..29] 20/20 | 29 | 6 [6..6] 20/20 | 6 |
| fp_cost.operator_unholds.total | 5 [1..9] 20/20 | 9 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.honest | 3 [0..7] 20/20 | 7 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.tainted | 2 [1..2] 20/20 | 2 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| damage_in_window | 3 [1..3] 20/20 | 3 | 5 [1..9] 20/20 | 9 | 3 [1..3] 20/20 | 3 | 5 [2..5] 20/20 | 5 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 0 [0..0] 20/20 | 0 | 17/191 [9/398..37/385] 20/20 | 12/127 | 7/132 [1/398..23/381] 20/20 | 23/381 | 0 [0..0] 20/20 | 0 |
| kept_without_redo | 263/265 [185/187..189/190] 20/20 | 137/138 | 228/263 [151/185..181/190] 20/20 | 245/274 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| revert_precision | 1 [1..1] 20/20 | 1 | 5/31 [1/10..3/11] 20/20 | 3/11 | 1 [1..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 |
| revert_recall | 2/5 [2/9..1] 20/20 | 2/5 | 1 [1..1] 20/20 | 1 | 2/5 [2/9..1] 20/20 | 2/5 | 0 [0..0] 20/20 | 0 |

### F2+c, H=6, T=40

| metric | system | system p95 | snapshot | snapshot p95 | revert_culprit_only | revert_culprit_only p95 | no_op | no_op p95 |
|---|---|---|---|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 1 [0..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 | 20 [5..46] 20/20 | 41 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| R | 0 [0..1/6] 20/20 | 1/6 | 3/5 [0..7/9] 20/20 | 7/9 | 3/5 [0..7/9] 20/20 | 7/9 | 1 [1..1] 20/20 | 1 |
| C | 0 [0..0] 20/20 | 0 | 34/263 [9/190..34/185] 20/20 | 33/193 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 3 [0..7] 20/20 | 7 | 2 [0..2] 20/20 | 2 | 27 [1..29] 20/20 | 29 | 6 [6..6] 20/20 | 6 |
| fp_cost.operator_unholds.total | 5 [1..9] 20/20 | 9 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.honest | 3 [0..7] 20/20 | 7 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.tainted | 2 [1..2] 20/20 | 2 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| damage_in_window | 3 [1..4] 20/20 | 4 | 6 [1..10] 20/20 | 10 | 3 [1..4] 20/20 | 4 | 5 [2..6] 20/20 | 6 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 0 [0..0] 20/20 | 0 | 17/191 [9/398..37/385] 20/20 | 36/379 | 21/395 [1/398..23/379] 20/20 | 23/380 | 0 [0..0] 20/20 | 0 |
| kept_without_redo | 263/265 [185/187..189/190] 20/20 | 137/138 | 228/263 [151/185..181/190] 20/20 | 245/274 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| revert_precision | 1 [1..1] 20/20 | 1 | 3/17 [1/10..5/17] 20/20 | 3/11 | 1 [1..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 |
| revert_recall | 2/5 [2/9..1] 20/20 | 1/2 | 1 [5/6..1] 20/20 | 1 | 2/5 [2/9..1] 20/20 | 1/2 | 0 [0..0] 20/20 | 0 |

### F2+x, H=6, T=40

| metric | system | system p95 | snapshot | snapshot p95 | revert_culprit_only | revert_culprit_only p95 | no_op | no_op p95 |
|---|---|---|---|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 1 [0..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 | 20 [5..46] 20/20 | 41 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| R | 1/5 [0..1/5] 20/20 | 1/5 | 3/5 [0..7/9] 20/20 | 7/9 | 3/5 [0..7/9] 20/20 | 7/9 | 1 [1..1] 20/20 | 1 |
| C | 21/254 [0..44/243] 20/20 | 39/254 | 34/263 [9/190..34/185] 20/20 | 33/193 | 1/242 [0..1/174] 20/20 | 1/179 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 29 [0..35] 20/20 | 35 | 2 [0..2] 20/20 | 2 | 27 [1..29] 20/20 | 29 | 6 [6..6] 20/20 | 6 |
| fp_cost.operator_unholds.total | 3 [1..7] 20/20 | 7 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.honest | 3 [0..7] 20/20 | 7 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.tainted | 0 [0..1] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| damage_in_window | 3 [1..3] 20/20 | 3 | 5 [1..9] 20/20 | 9 | 3 [1..3] 20/20 | 3 | 5 [2..5] 20/20 | 5 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 37/381 [0..22/127] 20/20 | 61/389 | 17/191 [9/398..37/385] 20/20 | 12/127 | 1/18 [1/398..8/127] 20/20 | 8/127 | 0 [0..0] 20/20 | 0 |
| kept_without_redo | 32/35 [199/243..189/190] 20/20 | 75/77 | 228/263 [151/185..181/190] 20/20 | 245/274 | 241/242 [173/174..1] 20/20 | 252/253 | 1 [1..1] 20/20 | 1 |
| revert_precision | 1 [1..1] 20/20 | 1 | 5/31 [1/10..3/11] 20/20 | 3/11 | 2/3 [2/3..1] 20/20 | 2/3 | 0 [0..0] 20/20 | 0 |
| revert_recall | 1/5 [1/9..1] 20/20 | 1/5 | 1 [1..1] 20/20 | 1 | 2/5 [2/9..1] 20/20 | 2/5 | 0 [0..0] 20/20 | 0 |

### F3, H=6, T=40

| metric | system (pause-only) | system (pause-only) p95 | snapshot | snapshot p95 | no_op | no_op p95 |
|---|---|---|---|---|---|---|
| tti_detect | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| R | 1 [1..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 | 1 [1..1] 20/20 | 1 |
| C | 0 [0..0] 20/20 | 0 | 7/197 [7/261..12/245] 20/20 | 10/207 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.total | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.honest | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.tainted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| damage_in_window | null [null..null] 0/20 | null | null [null..null] 0/20 | null | null [null..null] 0/20 | null |
| exposure | null [null..null] 0/20 | null | null [null..null] 0/20 | null | null [null..null] 0/20 | null |
| collateral_stall | 0 [0..0] 20/20 | 0 | 4/193 [6/373..2/63] 20/20 | 5/188 | 0 [0..0] 20/20 | 0 |
| kept_without_redo | 1 [1..1] 20/20 | 1 | 27/28 [233/245..254/261] 20/20 | 217/223 | 1 [1..1] 20/20 | 1 |
| revert_precision | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| revert_recall | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |

## H=0 and D10 contrast (F2+, F2+x only; T=40)

H=0 for F2, F1, F4, F7, F2+c and F3 is deferred (B3-33 review: "other faults at H=0 may be deferred"). The CONTRAST tables below are the D10 `--hold 0 --no-lineage-hold` runs (system, and no_op = pause with no recovery applied, "contrast before recovery"): not a security result, never aggregated with system cells, never quoted as a system result.

### F2+, H=0, T=40

| metric | system | system p95 | snapshot | snapshot p95 | revert_culprit_only | revert_culprit_only p95 | no_op | no_op p95 |
|---|---|---|---|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 1 [0..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 | 20 [5..46] 20/20 | 41 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| R | 0 [0..0] 20/20 | 0 | 1/3 [0..1/3] 20/20 | 1/3 | 1/3 [0..1/3] 20/20 | 1/3 | 1 [1..1] 20/20 | 1 |
| C | 0 [0..0] 20/20 | 0 | 33/265 [8/189..3/17] 20/20 | 32/193 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 0 [0..0] 20/20 | 0 | 2 [1..2] 20/20 | 2 | 26 [1..28] 20/20 | 28 | 0 [0..2] 20/20 | 2 |
| fp_cost.operator_unholds.total | 2 [1..2] 20/20 | 2 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.honest | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.tainted | 2 [1..2] 20/20 | 2 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| damage_in_window | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 5 [2..5] 20/20 | 5 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 0 [0..0] 20/20 | 0 | 33/388 [9/404..36/391] 20/20 | 35/391 | 12/197 [1/404..28/401] 20/20 | 28/401 | 0 [0..0] 20/20 | 0 |
| kept_without_redo | 261/263 [187/189..189/190] 20/20 | 139/140 | 231/265 [14/17..181/189] 20/20 | 125/139 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| revert_precision | 1 [1..1] 20/20 | 1 | 3/28 [1/10..3/26] 20/20 | 3/26 | 1 [1..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 |
| revert_recall | 2/3 [2/3..1] 20/20 | 2/3 | 1 [1..1] 20/20 | 1 | 2/3 [2/3..1] 20/20 | 2/3 | 0 [0..0] 20/20 | 0 |

### F2+x, H=0, T=40

| metric | system | system p95 | snapshot | snapshot p95 | revert_culprit_only | revert_culprit_only p95 | no_op | no_op p95 |
|---|---|---|---|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 1 [0..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 | 20 [5..46] 20/20 | 41 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| R | 1/3 [0..1/3] 20/20 | 1/3 | 1/3 [0..1/3] 20/20 | 1/3 | 1/3 [0..1/3] 20/20 | 1/3 | 1 [1..1] 20/20 | 1 |
| C | 1/12 [0..44/241] 20/20 | 37/237 | 33/265 [8/189..3/17] 20/20 | 32/193 | 1/237 [0..1/171] 20/20 | 1/176 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 26 [0..28] 20/20 | 28 | 2 [1..2] 20/20 | 2 | 26 [1..28] 20/20 | 28 | 0 [0..2] 20/20 | 2 |
| fp_cost.operator_unholds.total | 0 [0..1] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.honest | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.tainted | 0 [0..1] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| damage_in_window | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 5 [2..5] 20/20 | 5 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 41/391 [0..70/391] 20/20 | 67/401 | 33/388 [9/404..36/391] 20/20 | 35/391 | 25/394 [1/404..29/401] 20/20 | 29/401 | 0 [0..0] 20/20 | 0 |
| kept_without_redo | 221/242 [197/241..189/190] 20/20 | 221/227 | 231/265 [14/17..181/189] 20/20 | 125/139 | 236/237 [170/171..1] 20/20 | 251/252 | 1 [1..1] 20/20 | 1 |
| revert_precision | 1 [1..1] 20/20 | 1 | 3/28 [1/10..3/26] 20/20 | 3/26 | 2/3 [2/3..1] 20/20 | 2/3 | 0 [0..0] 20/20 | 0 |
| revert_recall | 1/3 [1/3..1] 20/20 | 1/3 | 1 [1..1] 20/20 | 1 | 2/3 [2/3..1] 20/20 | 2/3 | 0 [0..0] 20/20 | 0 |

### CONTRAST (D10, not a security result), F2+, H=0, T=40: system and no_op (pause, no recovery) with the lineage hold off

| metric | system (CONTRAST: no lineage hold) [CONTRAST: NO-LINEAGE-HOLD] | system (CONTRAST: no lineage hold) [CONTRAST: NO-LINEAGE-HOLD] p95 | no_op (CONTRAST: no lineage hold) [CONTRAST: NO-LINEAGE-HOLD] | no_op (CONTRAST: no lineage hold) [CONTRAST: NO-LINEAGE-HOLD] p95 |
|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 31 [16..62] 20/20 | 57 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 12 [6..18] 20/20 | 16 |
| R | 0 [0..0] 20/20 | 0 | 1 [1..1] 20/20 | 1 |
| C | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.total | 2 [1..2] 20/20 | 2 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.honest | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.tainted | 2 [1..2] 20/20 | 2 | 0 [0..0] 20/20 | 0 |
| damage_in_window | 3 [1..3] 20/20 | 3 | 7 [3..7] 20/20 | 7 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| kept_without_redo | 261/263 [187/189..189/190] 20/20 | 139/140 | 1 [1..1] 20/20 | 1 |
| revert_precision | 1 [1..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 |
| revert_recall | 2/3 [2/3..1] 20/20 | 2/3 | 0 [0..0] 20/20 | 0 |

### CONTRAST (D10, not a security result), F2+x, H=0, T=40: system and no_op (pause, no recovery) with the lineage hold off

| metric | system (CONTRAST: no lineage hold) [CONTRAST: NO-LINEAGE-HOLD] | system (CONTRAST: no lineage hold) [CONTRAST: NO-LINEAGE-HOLD] p95 | no_op (CONTRAST: no lineage hold) [CONTRAST: NO-LINEAGE-HOLD] | no_op (CONTRAST: no lineage hold) [CONTRAST: NO-LINEAGE-HOLD] p95 |
|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 31 [16..62] 20/20 | 57 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 12 [6..18] 20/20 | 16 |
| R | 1/3 [0..1/3] 20/20 | 1/3 | 1 [1..1] 20/20 | 1 |
| C | 29/280 [0..58/267] 20/20 | 49/263 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.total | 0 [0..1] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.honest | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.tainted | 0 [0..1] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| damage_in_window | 3 [1..3] 20/20 | 3 | 7 [3..7] 20/20 | 7 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 26/389 [0..58/391] 20/20 | 51/401 | 0 [0..0] 20/20 | 0 |
| kept_without_redo | 239/268 [209/267..189/190] 20/20 | 241/251 | 1 [1..1] 20/20 | 1 |
| revert_precision | 1 [1..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 |
| revert_recall | 1/3 [1/3..1] 20/20 | 1/3 | 0 [0..0] 20/20 | 0 |


## S4-13: F2+x before and after the resolver (D-18), H=6, T=40

New table (S4-13, vikram, 21 Nov; ADR-05a rev 3). It does not replace the F2+x H=6 table above. Both columns are the
`system` baseline on the same tree (contracts 1.7.0), seeds 1..20: **before** = `resolver: off` (the B5 before-row),
**after** = `ks run --resolver ww_rebase/1`, labelled `resolver: ww_rebase/1 (on)` in config.json, verify, console and
score.json. Command: `ks bench --seeds 1-20 --faults F2+x --hold 6 --baselines system --ticks 40 --resolver-faults F2+x`
run in the container (image `killswitch:kabir`, `--network none`, run dirs on the container fs), raw in
`runs/bench-s4-13-ctr/` (gitignored).

Platform: container, isolation `per_agent_uid` (kabir rerun for the S4-13 review, 21 Nov). Vikram's native macOS
run (degraded isolation) gave the same table cell for cell. The before column is identical, cell for cell, to the
`system` column of the container F2+x H=6 table above.

| metric | system (resolver: off, before) | system (resolver: off, before) p95 | system (resolver: ww_rebase/1 (on), after) | system (resolver: ww_rebase/1 (on), after) p95 |
|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| R | 1/5 [0..1/5] 20/20 | 1/5 | 0 [0..0] 20/20 | 0 |
| C | 21/254 [0..44/243] 20/20 | 39/254 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 29 [0..35] 20/20 | 35 | 3 [0..7] 20/20 | 7 |
| fp_cost.operator_unholds.total | 3 [1..7] 20/20 | 7 | 5 [1..9] 20/20 | 9 |
| fp_cost.operator_unholds.honest | 3 [0..7] 20/20 | 7 | 3 [0..7] 20/20 | 7 |
| fp_cost.operator_unholds.tainted | 0 [0..1] 20/20 | 0 | 2 [1..2] 20/20 | 2 |
| damage_in_window | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 37/381 [0..22/127] 20/20 | 61/389 | 0 [0..0] 20/20 | 0 |
| kept_without_redo | 32/35 [199/243..189/190] 20/20 | 75/77 | 263/265 [185/187..189/190] 20/20 | 137/138 |
| revert_precision | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| revert_recall | 1/5 [1/9..1] 20/20 | 1/5 | 2/5 [2/9..1] 20/20 | 2/5 |

Resolver columns from the after-row score.json files (ADR-05a §7 keys):

| seeds | ww_flags_before | ww_flags_after | resolutions |
|---|---|---|---|
| 19 of 20 (all but s7) | 1 | 0 | 1 (S-22, rebased agent triage) |
| s7 | 0 | 0 | 0 (no write-write conflict on this seed) |

Verify (container, `per_agent_uid`): a separate pass over the same 20 seeds, resolver off and on (40 runs, same
`run_cell` as the bench, `ks.verify.verify` on each run dir) gave verify OK and isolation `per_agent_uid` on all 40,
including the 19 resolved runs (no `resolution_invalid`), with the same R, C and resolutions as the table.

Hero F2+ (seeds 1..5, H=6, T=40): score.json identical with `--resolver off` and `--resolver ww_rebase/1` (0 resolutions,
0 write-write flags), verify OK on all 10 runs.

Reading (S4-13):
- [Fact] With the resolver on, F2+x R goes from 1/5 median [0..1/5] to 0 [0..0], C from 21/254 [0..44/243] to 0 [0..0],
  held honest actions from 29 [0..35] to 3 [0..7]. Operator unholds rise from 3 [1..7] to 5 [1..9]; the tainted count
  (2 median) counts items recovery re-ran and re-held, which the bench approver releases (X4, D-17).
- [Fact] Rev 2 of ADR-05a (first run, same day) resolved nothing: it refused every ranked root candidate and the alert
  names triage. Maya's rev 3 (§2a, `refused_agents`) refuses the suspect, each alert's `root_candidates[0]`, evidence
  writers and authors of taint origins, not later candidates for rank alone. This table is rev 3.
- [Our view] Numbers from the after column must say "with resolver on" (D-19, ADR-05a §7).

## Reading notes (T=40)

- **F2+x held_honest_actions** (system, H=6, median 29, max 35): `held_honest_outbox` is 27 on seed 1 and 35 on seed 2. These are triage lineage items that stay held because the conflict is flagged and the Section 4 bench approver never resolves flags. It is the cost of the flag, not a wrong revert; read it next to C=21/254 and R=1/5 (medians). `revert_culprit_only` shows 27 (median) for the same reason: its outbox is untouched, so held honest items are never released.
- **F3**: system cell has no recovery plan (`no_plan`, listed under notes): it is scored as pause-only, R=1 is the honest emails comms never sent while suspended, not exfiltration. `revert_culprit_only` is n/a on F3 (the culprit wrote nothing landed): those 20 cells are listed under "not applicable", not under failures, and not scored. tti_detect/ttc for F3 follow ADR-06-metrics A5.
- **D10 contrast, honest reading** (contrast rows are D10 diagnostics, not system results; compare only against the same-fault no_op H=0 column above, which has the hold on): the lineage hold protects the window between the alert and the operator's decision. Contrast before recovery (no_op = pause, no recovery applied; `--hold 0 --no-lineage-hold` vs normal `--hold 0`), over seeds 1..20: with the hold off, irreversible_tainted_released is 12 median [6..18], 245 payments in total, >0 on 20/20 seeds (F2+ and F2+x identical; s1 = 10); with the hold on (normal no_op H=0 column) it is 0 [0..0] 20/20. With recovery applied instantly at the alert tick (the system contrast cells) the hold has nothing left to stop, because the apply re-runs and holds the tainted payment (queued at the alert tick) before it is dispatched, so system contrast also reads irreversible_tainted_released 0 on all 20 seeds. Read: the hold matters when the operator has not yet decided; an instant apply makes it redundant for F2+.

## notes (cells scored as run, not as planned)

- F3/h6/system/s1: no_plan
- F3/h6/system/s2: no_plan
- F3/h6/system/s3: no_plan
- F3/h6/system/s4: no_plan
- F3/h6/system/s5: no_plan
- F3/h6/system/s6: no_plan
- F3/h6/system/s7: no_plan
- F3/h6/system/s8: no_plan
- F3/h6/system/s9: no_plan
- F3/h6/system/s10: no_plan
- F3/h6/system/s11: no_plan
- F3/h6/system/s12: no_plan
- F3/h6/system/s13: no_plan
- F3/h6/system/s14: no_plan
- F3/h6/system/s15: no_plan
- F3/h6/system/s16: no_plan
- F3/h6/system/s17: no_plan
- F3/h6/system/s18: no_plan
- F3/h6/system/s19: no_plan
- F3/h6/system/s20: no_plan

## not applicable

- F3/h6/revert_culprit_only/s1: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 15)
- F3/h6/revert_culprit_only/s2: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 11)
- F3/h6/revert_culprit_only/s3: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 18)
- F3/h6/revert_culprit_only/s4: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 12)
- F3/h6/revert_culprit_only/s5: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 10)
- F3/h6/revert_culprit_only/s6: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 18)
- F3/h6/revert_culprit_only/s7: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 20)
- F3/h6/revert_culprit_only/s8: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 20)
- F3/h6/revert_culprit_only/s9: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 12)
- F3/h6/revert_culprit_only/s10: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 19)
- F3/h6/revert_culprit_only/s11: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 10)
- F3/h6/revert_culprit_only/s12: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 15)
- F3/h6/revert_culprit_only/s13: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 11)
- F3/h6/revert_culprit_only/s14: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 13)
- F3/h6/revert_culprit_only/s15: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 17)
- F3/h6/revert_culprit_only/s16: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 11)
- F3/h6/revert_culprit_only/s17: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 12)
- F3/h6/revert_culprit_only/s18: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 11)
- F3/h6/revert_culprit_only/s19: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 10)
- F3/h6/revert_culprit_only/s20: n/a: culprit wrote nothing landed (comms wrote nothing at tick >= 17)
