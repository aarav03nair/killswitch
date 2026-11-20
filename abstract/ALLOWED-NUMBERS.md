# ALLOWED NUMBERS: our own measured values the abstract may cite (D-19, S4-18)

zoya · 21 Nov 2026 · Reviewer: anaya · Decision: **D-19** (Aarav, CALL-04 decision 3, revising D13): the abstract may cite measured BENCH-S3 numbers, each with its conditions. Conditions: **D-17** (CALL-02 B2-b), **D-18** (CALL-04 decision 2), **D10** (CALL-01). Source of every value: `org/reports/BENCH-S3.md` (raw in `runs/bench-b3-33/`, gitignored).

**How to use.** This is a list of values and the conditions that travel with them. It is not abstract text: Aarav writes every sentence (CHARTER). A number of ours **not on this list** stays out of the abstract. Outside numbers still come only from `abstract/FACT-CARD.md`.

## 0. Conditions that travel with every value below [Fact]

| # | Condition | Source |
|---|---|---|
| G1 | **T = 40** ticks per run. Do not compare ratio metrics with T=120 (S4-14 rerun has no numbers yet) | BENCH-S3 title + line 3 |
| G2 | **20 seeded runs** (seeds 1..20); cells are `median [min..max]`, p95 = nearest-rank 19th of 20 | BENCH-S3 line 3 |
| G3 | Hold window **H = 6** unless the row says H=0 | BENCH-S3 section titles |
| G4 | Times are in **ticks** (logical clock, tick barrier), never seconds | TERMS §5; GUARDRAILS L7 |
| G5 | Our own simulated workspace: ~10 **deterministic** agents, single host. Not LLM agents | GUARDRAILS L6, L7 |
| G6 | The system's recovery is **not told** the culprit or t_inject; baselines snapshot and revert-culprit-only **are** (oracle-assisted) | BENCH-S3 lines 7–8 |
| G7 | Recovery is scored against the oracle S\* (same seed, fault off, culprit stops from its suspension tick) | TERMS §5; GUARDRAILS W1 |
| G8 | Say "median over 20 seeds" (or give the range) next to any median. Quote fractions as printed; convert to % only when exact (e.g. 1/5 = 20%) | BENCH-S3 line 3 |
| G9 | Bench platform: run in the container (OrbStack, arm64, Linux) with per-agent uids, not native macOS (where attribution is VOID). Closed 21 Nov (anaya review; pmo statement). The run dir does not record this itself, so per-agent isolation may be stated only about BENCH-S3 values, not about other runs | BENCH-S3 "Platform" line; HANDOFF line 3 |

## 1. Hero fault F2+ (system, H=6, T=40) [Fact]

All rows: BENCH-S3 §"F2+, H=6, T=40", column `system`, 20/20 seeds.

| ID | Value (cell as printed) | Metric row | Must travel with it |
|---|---|---|---|
| N1 | TTI-detect **2 [0..2]**, p95 2 | `tti_detect` | ticks (G4); from t0 to first alert |
| N2 | TTI-attribute **0 [0..0]** | `tti_attribute` | attribution is a lookup on signed records (F5); not an accuracy claim (X20) |
| N3 | TTC **1 [1..1]** | `ttc` | ticks; alert → first denied culprit envelope |
| N4 | residual damage R **0 [0..0]** | `R` | **D-17, mandatory in the same sentence or the next:** holds *after the operator released* a median **5** held items **[1..9]** (`fp_cost.operator_unholds.total`), of which **3 [0..7]** honest (`…honest`) and **2 [1..2]** tainted-lineage (`…tainted`). The tainted-lineage ones are payments recovery re-ran and re-held; they leave with clean payloads (scripts/demo.sh line 5). Never a bare R = 0 |
| N5 | collateral loss C **0 [0..0]**; culprit-window loss **0 [0..0]** | `C`, `c_culprit_window` | Hero F2+ only. Holds because crm writes nothing else between fault and suspension (per-seed precondition, GUARDRAILS L8). Never "C = 0" as unconditional. Do not extend to F2+c (⚑ S4-24, §5) |
| N6 | post-alert tainted effects **0 [0..0]** | `post_alert_tainted_effects` | counted from the ledger, not from our taint graph |
| N7 | irreversible tainted effects released **0 [0..0]** | `irreversible_tainted_released` | at H=6 with the lineage hold on; see N17 for what the hold adds |
| N8 | re-emitted effects **0 [0..0]** | `reemitted` | pairs with "re-runs count as redo" (X27) |
| N9 | false accusations **0 [0..0]**; honest suspensions **0 [0..0]** | `false_accusations`, `fp_cost.honest_suspensions` | this fault only; not a general false-positive rate (X30) |
| N10 | honest items held **3 [0..7]** | `fp_cost.held_honest_actions` | the cost of over-taint (L2); same seeds as N4's honest releases |
| N11 | collateral stall **0 [0..0]** | `collateral_stall` | always "proxy" (basis `s_star`, ADR-06 A3), never "the S0 measure" |

Not on the list (do not cite): `kept_without_redo` (a median of fractions with different denominators, easy to misread), `revert_precision` / `revert_recall` (need a definition the abstract has no room for), `damage_in_window`, `exposure`.

## 2. Baselines on F2+ (H=6, T=40): comparison only [Fact]

BENCH-S3 §"F2+, H=6, T=40". Must travel with every row: **oracle-assisted** (given culprit and t_inject, which the system is not), "upper-bound-style baselines, not products" (BENCH-S3 line 8). Allowed verb: "compared with our own baselines". ✗ "beats", "outperforms" (GUARDRAILS §3).

| ID | Value | Column · metric row |
|---|---|---|
| N12 | snapshot: residual damage R **3/5 [0..7/9]**, collateral loss C **34/263 [9/190..34/185]** | `snapshot` · `R`, `C` |
| N13 | revert-culprit-only: R **3/5 [0..7/9]**, C **0 [0..0]**, honest items held **27 [1..29]** | `revert_culprit_only` · `R`, `C`, `fp_cost.held_honest_actions` |
| N14 | no-op (pause only, no recovery): R **1 [1..1]**, post-alert tainted effects **20 [5..46]** | `no_op` · `R`, `post_alert_tainted_effects` |

## 3. Honest conflict variant F2+x (system, H=6, T=40): disclose, "before resolver" [Fact]

BENCH-S3 §"F2+x, H=6, T=40", column `system`, plus Reading notes bullet 1. **Must travel with it:** (a) triage edits the price row crm wrote → write-write conflict → flagged, and the bench approver never resolves flags; (b) label **"before resolver"**: D-18's auditable resolver (S4-12 design, S4-13 build) is not built yet, so these values may change; CALL-04 decision 2 requires F2+x reported before and after; (c) quote all three values together, never R alone.

| ID | Value | Metric row |
|---|---|---|
| N15 | residual damage R **1/5 [0..1/5]** | `R` |
| N15 | collateral loss C **21/254 [0..44/243]** | `C` |
| N15 | honest items held **29 [0..35]** | `fp_cost.held_honest_actions` |

## 4. Hold window and the D10 contrast (T=40) [Fact]

| ID | Value | Source (BENCH-S3) | Must travel with it |
|---|---|---|---|
| N16 | F2+ at hold window **H=0**, system: R **0 [0..0]**, irreversible tainted effects released **0 [0..0]**, after operator releases **2 [1..2]** (0 honest) | §"F2+, H=0, T=40" · `system` | H=0 sets the hold window to 0; the **lineage hold stays on**. Do not describe H=0 as "no hold" |
| N17 | D10 contrast, pause with no recovery: lineage hold **off** → irreversible tainted payments released **12 [6..18]**, >0 on 20/20 seeds; lineage hold **on** → **0 [0..0]** | §"CONTRAST … F2+, H=0" · `no_op` · `irreversible_tainted_released`; §"F2+, H=0" · `no_op`; Reading notes bullet 3 | Label "contrast, not a security result" (BENCH-S3 line 123). Never aggregated with or quoted as a system result. The hold protects the gap before the operator decides; with recovery applied instantly the system contrast also reads 0 (Reading notes) |

## 5. Not allowed yet (⚑ pending, or misleading) [Fact]

| Item | Why | Owner |
|---|---|---|
| Any **F2+c** value (BENCH-S3 shows C 0 [0..0], R 0 [0..1/6]) | ⚑ Contradicts GUARDRAILS L8 (predicts C > 0). Fixture or guardrail is wrong; not decided here | anaya, S4-24 |
| **F3** residual damage R = 1 | Not exfiltration: it is honest emails comms never sent while suspended; F3 has no recovery plan (`no_plan` 20/20). If F3 is mentioned, only N-style detection values: TTI-detect 0 [0..0], TTC 1 [1..1], irreversible tainted released 0 [0..0] (§"F3, H=6"), with "pytest, not live" (F13) | BENCH-S3 Reading notes bullet 2 |
| F2+x after resolver | Does not exist yet | vikram, S4-13 |
| T=120 values | Not run | tara, S4-14 |
| Red-team pass values (RT1–RT14) | Measured values go in `org/reports/REDTEAM-S4.md` first (kabir S4-c); until then targets only | kabir |
| Seconds, %, "accuracy", "leaks" | No such measurement (G4; X20, X21) | n/a |
| Hero demo seed values (FACT-CARD O1–O4: seeds 0/1/2, B3-27 container runs) | Demo facts, not BENCH-S3. Fine on stage with D-17; the abstract cites BENCH-S3 medians | zoya, S4-10 |

## 6. Notes for the self-check [Our view]

- Every number of ours in the draft should map to an ID above. If it does not, cut it or ask.
- Tense: past tense ("measured") is fine **only** for values on this list, with G1–G3. Design parts (finale demo, jury break, resolver) stay future or design tense.
- R = 0 without the release clause (N4) is the single most likely jury attack (JURY-QA Q13).
