# Call #4 input: zoya (product & pitch) · 20 Nov 2026

Sources: HANDOFF.md, org/reports/BENCH-S3.md (T=40, H=6, seeds 1..20), CALL-02/resolutions.md B2-a/B2-b, tests/integration/test_hero_f2plus.py, scripts/demo.sh, src/ks/console/model.py, board/demo-sim.html. Facts only. No abstract prose: Aarav writes his own (due 22 Nov).

## 1. Abstract Kit: stale vs the built system [Fact]
| File:line | Says | Built / measured now |
|---|---|---|
| GUARDRAILS 11, 72–86 (§1.5), 116 (X21); JURY-QA 9; SKELETON 177, 182, 184, 212 | Our numbers are targets only, "nothing measured by 22 Nov", protocol "planned" | 20-seed bench exists (BENCH-S3). Whether the abstract may cite measured values is **D13, Aarav's call** ⚑ (raise as decision; don't change the rule silently) |
| TERMS 110 | Golden B2 re-runs "billing / payments / comms / reporter" | B2-a (D-16): re-run set is billing, payments, comms; reporter independent (test line 182–186) |
| SKELETON 142; GUARDRAILS F11 (42) wording for hero | Held payment → `cancel (outbox item)` | Hero plan has no cancel: payments re-run under the same `outbox:<id>` v+1, re-held, then **operator unhold** (demo.sh; B2-a) |
| GUARDRAILS L8 (69) | F2+c: C > 0 when crm works honestly in-window | Bench F2+c system: C 0 [0..0], c_culprit_window 0 [0..0], R 0 [0..1/6]. Either L8 or the F2+c fixture is wrong: needs anaya/vikram check |
| GUARDRAILS L9 (70); JURY-QA 151 | F2+x: R > 0 | Confirmed R 1/5 median, plus C 21/254 median and 29 held honest items (approver never resolves flags). L9 omits C and the held cost |
| JURY-QA 118, 125, 138; SKELETON 214 | Hold 0 → escaped payment scored as residual damage | System at H=0 (lineage hold on): R 0, irreversible released 0. The escape appears only with `--no-lineage-hold` and no recovery (D10 contrast) |
| TERMS 95 | R=0 claims state operator releases | Already current (D-17) |
| abstract/ABSTRACT.md 31 (ABS-07 comment only) | "targets, to be measured"; R = 0 and C = 0 with no release count | Measured values exist; D-17 requires N released / M honest with any R = 0 |

## 2. Finale demo story: demo-sim vs real `make demo` + console [Fact unless marked]
- Beats: real console has 5 (Break, Identify, Contain, Recover, Audit); demo-sim has 6 (extra "Setup"). Merge Setup into Break.
- demo-sim banner (line 60) "Nothing here runs; illustrative target": stale. Replace with seed-2 run values.
- Identify (line 102): "detect 1 tick" → real hero seed 2: tti_detect 2, tti_attribute 0; bench 2 [0..2]. TTC 1.
- Recover (lines 106–108): drop "reporter" from re-run; drop "cancel #77, #78"; SKU-9 price → S-22; add the **operator unhold step** (real demo.sh step 4). Score line "R 0/6 · C 0/42 [targets]" → real score.json values.
- **D10 toggle** (lines 132–137) shows "R 1/6, 1 payment escaped": not what we measured. Replace with the before-recovery contrast: pause, no recovery, lineage hold off → median 12 tainted payments released [6..18], >0 on 20/20 seeds; hold on → 0 [0..0]. Label "contrast, not a security result" (BENCH-S3). [Our view] Also say plainly that an instant apply makes the hold redundant for F2+; the hold protects the gap before the operator decides.
- **R = 0 with operator releases (D-17):** always pair R = 0 with "after the operator released N held items, M honest". Seed 2 (demo default): 9 released = 7 honest (sensitive-field hold) + 2 recovery re-holds with clean payloads. Bench: median 5 (3 honest, 2 tainted), max 9.
- Console gap: scorecard rows (model.py 64–66) omit `fp_cost.operator_unholds` and `held_honest_actions`, so the screen shows R = 0 without D-17's clause. Its H=0 note (line 85–88) prints "H=0 (no lineage hold)", but H=0 runs keep the lineage hold. Audit banner says "first bad index"; TERMS 35 says it's a **seq**.
- **F2+x disclosure:** one Q&A slide, no hiding: triage edits crm's price row → write-write conflict flagged → R 1/5, C 21/254, 29 honest items held (medians), because no one resolves the flag. [Our view] Frame it as "the system stops and asks; it does not guess".

## 3. Top 5 jury questions we're weakest on
1. "Is R = 0 just the human releasing things?" → BENCH-S3 F2+ fp_cost.operator_unholds; test_hero line 213–216; D-17. Need a one-line meaning of the "tainted" unholds (recovery re-holds with clean payloads, demo.sh).
2. "Your conflict case leaves 29 honest items stuck and C > 0." → BENCH-S3 F2+x + reading notes; L9.
3. "Forge the witness ack / fake an outbox origin." → no RT yet (S4-01 gaps); THREAT-MODEL wording only.
4. "F3 exfiltration: R = 1 and no plan?" → BENCH-S3 F3 notes (no_plan 20/20; R = emails not sent while suspended; revert_culprit_only cannot run). Baselines are oracle-assisted (given culprit + t_inject).
5. "Ticks, not seconds; deterministic agents, not LLMs; 10 agents?" → GUARDRAILS §1.5, L7, X25; HANDOFF (macOS = isolation VOID, Docker needed). LangGraph stretch undecided ⚑.

## Sprint 4 issues I want
| Title | Owner | Acceptance |
|---|---|---|
| Demo-sim to real seed-2 run (5 beats, D10 contrast, unhold step, D-17 line) | zoya | Every number in board/demo-sim.html traces to a score.json or BENCH-S3 cell; no "reporter" re-run, no cancel; panel review |
| Console shows operator releases + fix H=0 note + "seq" wording | kabir (dev on Sonnet) | Scorecard has operator_unholds total/honest and held_honest_actions; H=0 note only says "no lineage hold" when it was off; test added; pytest green |
| Kit refresh v5 (TERMS 110, SKELETON 142/214, GUARDRAILS L8/L9/§1.5, JURY-QA Q8/Q9/Q10 + Q on releases) | zoya; reviewer anaya | Each row in §1 above resolved or marked ⚑; no abstract prose |
| F2+c check: why C = 0 when L8 predicts > 0 | anaya | Written finding: fixture or guardrail corrected |
| D13 decision memo: may the abstract cite measured numbers? | zoya → Aarav ⚑ | Options + exact allowed values, by 21 Nov |
| ABS-07 comment-only review of Aarav's abstract | zoya, anaya | Comments only, cites lines; zero rewritten sentences |
| Panel jury dry run on Q1–Q5 above | panel | Each answer cites a file; gaps logged as issues |
