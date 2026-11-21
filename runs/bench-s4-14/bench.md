# ks bench: T=120 (ADR-06-metrics A4), seeds 1..20 (n=20)

Every number here is at **T=120**; do not compare ratio metrics with T=120. Cells are `median [min..max] k/n` (k = seeds with a non-null value), next to a p95 column (nearest-rank, 19th of 20; null = never = +inf).

- `system`: the product path; its recovery is not told the culprit or t_inject.
- `snapshot` and `revert_culprit_only` are **oracle-assisted**: they are given t_inject and the culprit from the inject spec, which the system is not. They are upper-bound-style baselines, not products.
- `no_op`: pause (suspend) only, no recovery.
- `collateral_stall` is a **proxy**, basis `s_star` (A3): non-culprit keys outside B whose final_T differs from S*_T. Real runs have no unmirrored S0.
- `tti_*`/`ttc` for a denied or held bad action (F3: scope alert on a denied pii egress) follow ADR-06-metrics A5: first alert naming the culprit, measured from the bad action.

### F2+, H=6, T=120

| metric | system | system p95 | snapshot | snapshot p95 | revert_culprit_only | revert_culprit_only p95 |
|---|---|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 1 [0..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| R | 0 [0..1/6] 20/20 | 1/6 | 3/5 [0..2/3] 20/20 | 2/3 | 3/5 [0..2/3] 20/20 | 2/3 |
| C | 0 [0..0] 20/20 | 0 | 32/739 [7/750..2/33] 20/20 | 35/594 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 5 [2..5] 20/20 | 5 | 4 [2..4] 20/20 | 4 | 65 [3..91] 20/20 | 91 |
| fp_cost.operator_unholds.total | 5 [1..5] 20/20 | 5 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.honest | 3 [0..3] 20/20 | 3 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.operator_unholds.tainted | 2 [1..2] 20/20 | 2 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| damage_in_window | 3 [1..3] 20/20 | 3 | 5 [1..5] 20/20 | 5 | 3 [1..3] 20/20 | 3 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 1/567 [1/1129..1/560] 20/20 | 2/1121 | 35/1121 [1/125..20/567] 20/20 | 39/1129 | 29/564 [1/379..85/1121] 20/20 | 85/1132 |
| kept_without_redo | 359/360 [287/288..833/834] 20/20 | 772/773 | 343/359 [31/33..743/750] 20/20 | 413/417 | 1 [1..1] 20/20 | 1 |
| revert_precision | 1 [1..1] 20/20 | 1 | 5/32 [1/12..5/29] 20/20 | 1/6 | 1 [1..1] 20/20 | 1 |
| revert_recall | 2/5 [1/3..1] 20/20 | 1 | 1 [5/6..1] 20/20 | 1 | 2/5 [1/3..1] 20/20 | 1 |

### F2+x, H=6, T=120

| metric | system (resolver: off, before) | system (resolver: off, before) p95 | snapshot | snapshot p95 | revert_culprit_only | revert_culprit_only p95 | system (resolver: ww_rebase/1 (on), after) | system (resolver: ww_rebase/1 (on), after) p95 |
|---|---|---|---|---|---|---|---|---|
| tti_detect | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 | 2 [0..2] 20/20 | 2 |
| tti_attribute | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| ttc | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| post_alert_tainted_effects | 0 [0..0] 20/20 | 0 | 1 [0..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| irreversible_tainted_released | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| R | 1/5 [0..1/3] 20/20 | 1/3 | 3/5 [0..2/3] 20/20 | 2/3 | 3/5 [0..2/3] 20/20 | 2/3 | 0 [0..1/6] 20/20 | 1/6 |
| C | 42/575 [0..5/36] 20/20 | 11/106 | 32/739 [7/750..2/33] 20/20 | 35/594 | 1/668 [0..1/521] 20/20 | 1/521 | 0 [0..0] 20/20 | 0 |
| c_culprit_window | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| reemitted | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| false_accusations | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.honest_suspensions | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.stall_ticks | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 |
| fp_cost.held_honest_actions | 67 [2..93] 20/20 | 93 | 4 [2..4] 20/20 | 4 | 65 [3..91] 20/20 | 91 | 5 [2..5] 20/20 | 5 |
| fp_cost.operator_unholds.total | 3 [1..3] 20/20 | 3 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 5 [1..5] 20/20 | 5 |
| fp_cost.operator_unholds.honest | 3 [0..3] 20/20 | 3 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 3 [0..3] 20/20 | 3 |
| fp_cost.operator_unholds.tainted | 0 [0..1] 20/20 | 1 | 0 [0..0] 20/20 | 0 | 0 [0..0] 20/20 | 0 | 2 [1..2] 20/20 | 2 |
| damage_in_window | 3 [1..3] 20/20 | 3 | 5 [1..5] 20/20 | 5 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| exposure | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 | 3 [1..3] 20/20 | 3 |
| collateral_stall | 106/1129 [2/1137..161/1121] 20/20 | 36/283 | 35/1121 [1/125..20/567] 20/20 | 39/1129 | 59/1128 [1/379..86/1121] 20/20 | 43/566 | 1/567 [1/1129..1/560] 20/20 | 2/1121 |
| kept_without_redo | 161/174 [31/36..833/834] 20/20 | 772/773 | 343/359 [31/33..743/750] 20/20 | 413/417 | 648/649 [520/521..1] 20/20 | 1 | 359/360 [287/288..833/834] 20/20 | 772/773 |
| revert_precision | 1 [1..1] 20/20 | 1 | 5/32 [1/12..5/29] 20/20 | 1/6 | 2/3 [2/3..1] 20/20 | 1 | 1 [1..1] 20/20 | 1 |
| revert_recall | 1/5 [1/6..1] 20/20 | 1 | 1 [5/6..1] 20/20 | 1 | 2/5 [1/3..1] 20/20 | 1 | 2/5 [1/3..1] 20/20 | 1 |
