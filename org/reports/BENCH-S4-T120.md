<!-- S4-14, tara, 21 Nov 2026; revised after maya review (changes) -->
## S4-14 header (read first)

> **Footnote (S4-35 / S4-37):** the T=120 `R` and `collateral_stall` figures in this report are inflated by an oracle artefact, not by residual damage. S\* executed the honest I2 `docs.purge` that the real run holds for approval (`p.i2_approval`), so R 1/6 on seeds 2, 8, 13, 14, 16 and every non-zero `collateral_stall` are that one item (R_n + cstall_n = 2 on all 20 seeds; seed 2 re-scored without the purges: R 0/5, cstall 0). Fixed in code by S4-37 (ADR-06-metrics A6, proposed, pending maya sign-off); the figures below are not rerun. T=40 is unaffected.

- **Headline decision:** T=40 (ADR-06-metrics A4, BENCH-S3) **stays the headline**. This T=120 run is a **disclosed confirming run, not a replacement**, because it does not reproduce T=40 exactly (two deltas below). The open investigation of the R=1/6 late-inject seeds is tracked as **S4-35**. Binding docs and ALLOWED-NUMBERS are untouched; switching is pmo/Aarav's decision.
- **Source:** the run output is (gitignored, like runs/bench-b3-33) `runs/bench-s4-14/` (copied unchanged from the container `/work/runs/bench-t120`; 592 KB: `bench.json`, `bench.md`, `timings.json`, 140 `score.json`). The tables below are `bench.md` byte-for-byte. Line 3 of the generated `bench.md` reads "do not compare ratio metrics with T=120" at a T=120 run: that is a formatter bug (hard-coded text in `src/ks/bench/runner.py`), fixed after this run (the line now names the other tick count, so a T=120 run says T=40). The generated line is left as is in `runs/bench-s4-14/bench.md` and here; read it as "T=40". An earlier draft of this report hand-edited that line without saying so; that edit is removed.
- **Run:** `ks bench --seeds 1-20 --faults F2+,F2+x --hold 6 --baselines system,snapshot,revert_culprit_only --ticks 120 --resolver-faults F2+x`, HEAD 588daaf, image `killswitch:tara`, one container (`--network none`), exit 0, 140/140 cells ok (F2+: 3 x 20; F2+x: 4 x 20 incl. the `ww_rebase/1` column), `failures` = [], `not_applicable` = []. About 2.6 h (about 73 s per cell). No `no_op` column (not requested).
- **Platform:** container (OrbStack, arm64, Linux), per-agent uids, not native macOS. Host: 11 CPUs, 1-min load about 4.0 (about 0.36 per CPU, under the finale 0.5 threshold), no other container.
- **Validity per cell:** 0 of 140 `score.json` carry a `run_validity` key (S4-22: written only for VOID or DEGRADED: isolation, key_mode, any deadline miss); `config.json` was present in every run (maya checked t_inject 30..58). So 140/140 OK, 0 deadline-miss cells. Scratch run dirs are deleted by the bench, so `timing.jsonl` was not re-read by hand. `invariants_ok` is "unavailable" in all 140 (same gap as T=40), so Clean is not claimable at either T.
- **D-17 release counts:** `irreversible_tainted_released` = 0 [0..0] 20/20 in every cell; `post_alert_tainted_effects` 0 for system and revert_culprit_only, snapshot 1 [0..1]. Operator unholds: F2+ system total 5 [1..5] (honest 3, tainted 2); F2+x resolver off 3 [1..3] (honest 3, tainted 0 [0..1]); F2+x resolver on 5 [1..5] (honest 3, tainted 2).
- **Deltas against T=40 (stated plainly; this run does NOT simply match T=40):**
  1. **F2+ system R is 0 [0..1/6] (p95 1/6); at T=40 it was 0 [0..0].** R = 1/6 on seeds 2, 8, 13, 14 and 16, all late injections (t_inject 53..58; seed 2 is the hero/demo seed); the same five seeds in the F2+x resolver-on column. R is 0 on the other 15 seeds. Cause not yet known: S4-35.
  2. **System `collateral_stall` is non-zero on all 20 seeds** (F2+ system median 1/567 [1/1129..1/560], p95 2/1121); at T=40 it was 0 [0..0]. C (the headline-style count) is still 0 [0..0] for F2+ system and for F2+x resolver on.
- **Otherwise consistent with T=40:** F2+ system tti_detect 2, tti_attribute 0, ttc 1, false_accusations 0, honest_suspensions 0. F2+x resolver off: C 42/575 [0..5/36] (T=40: 21/254 [0..44/243]), R 1/5 [0..1/3] (T=40: 1/5). snapshot F2+ C 32/739 (T=40: 34/263), non-zero on all seeds. revert_culprit_only F2+x C 1/668 (T=40: 1/242). Counts that scale with T (kept_without_redo, collateral_stall, held_honest_actions) are larger; ratios are not compared across T. The bench's min/max fraction ordering is its existing formatter (same as BENCH-S3).
- **Not rerun at T=120:** F2+c, F3, H=0 and the `no_op` baseline stay T=40 only.

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
