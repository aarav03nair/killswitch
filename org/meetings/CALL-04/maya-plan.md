# CALL-04 · maya: Sprint 4 plan (harden, prove, rehearse)

**20 Nov 2026** · Maya (Eng Lead) · Inputs: HANDOFF (ff86363), BENCH-S3 (T=40, 20 seeds), S4-01, ADR-06-metrics A4, CALL-02 resolutions.
**Rule for S4:** no new features. Every issue either closes a jury attack, fixes what the dry run finds, or makes the demo and numbers reproducible. Contracts change only additively (1.6.x). Code freeze **26 Nov 18:00 IST**. Day = D1 21 Nov … D6 26 Nov.

## Issues (each ≤1 day; Opus = leads, reviewers, vikram; Sonnet = the rest)

| Id | Title | Owner (model) | Reviewer | Acceptance (testable) | Day |
|---|---|---|---|---|---|
| S4-01 | Red-team gaps (exists): forged witness ack, outbox provenance RT, ttc unavailable | kabir (Opus) | panel | As written. Each defence disabled → a named RT test fails; F3 `ttc` = `{unavailable: reason}`, never null | D1–D2 |
| S4-02 | Fresh-Mac README: clone → `make demo` → `ks verify` passes in <10 min | ishaan (Sonnet) | maya | A non-author follows only README.md on a clean macOS account (OrbStack) and gets exit 0, `isolation=per_agent_uid`, `anchored=true`; time recorded. Stale "demo.sh runs the skeleton" note removed; expected output pasted; troubleshooting for daemon off / port / virtiofs | D1 |
| S4-03 | Docker Desktop (virtiofs) check of the `./runs` bind mount | ishaan (Sonnet) | arjun | `make smoke` passes on Docker Desktop, or README names the named-volume fallback and `make smoke-volume` passes | D2 |
| S4-04 | Jury dry run #1: hostile, tries to break the build | panel (Opus) | maya | Written report `org/reports/PANEL-JURY-01.md`: ≥15 attacks from the README alone (tamper, forge, replay, rogue agent, wrong claims vs THREAT-MODEL wording, numbers vs BENCH-S3), each with result + severity; every Must becomes an issue | D3 |
| S4-05..08 | Fix slots for PANEL-JURY-01 Musts (opened after D3) | per area: arjun/nisha/vikram/tara | kabir or maya | Each fix has a regression test that fails before the fix | D4–D5 |
| S4-09 | Jury dry run #2 (re-attack the fixed build, 2 h box) | panel (Opus) | maya | Every #1 Must re-tried and closed or written as a known limitation | D6 am |
| S4-10 | demo-sim D10 beat: before-recovery contrast | ishaan (Sonnet) | anaya | Toggle reads "pause, no recovery: hold off releases median 12 tainted payments [6..18], 20/20 seeds; hold on 0 (T=40)"; the old "R 1/6, #77 dispatched" text is gone; every number on the page matches BENCH-S3 and says T=40 | D2 |
| S4-11 | F2+x honest disclosure | anaya (Opus) | zoya | FACT-CARD + JURY-QA state: F2+x R 1/5, held honest median 29, because a flagged conflict waits for a human; wording checked against BENCH-S3 reading notes | D2 |
| S4-12 | Decision D-18 for Aarav: bench approver policy for flags (yes/no) | maya (Opus) | aarav | One-page option note: A = disclosure only (S4-11); B = bench approver resolves a flag by "keep current value" and releases held items whose only taint path is the flagged key, rerun F2+x, report both rows. Aarav picks | D2 |
| S4-13 | (only if D-18 = B) approver policy + F2+x rerun | vikram (Opus) | maya | Policy is bench-only and logged as an operator decision in the record; verify passes; new F2+x row next to the old one, not replacing it | D3–D4 |
| S4-14 | T=120 headline rerun (no perf work) | tara (Sonnet) | maya | F2+ and F2+x, H=6, system + snapshot + revert_culprit_only, seeds 1..20 (120 cells; est. 45–80 min from A4's 7.5–13 s × ~3) run overnight in the container; `BENCH-S4-T120.md` written; if it does not finish by D4, A4 stays and the deck says T=40 | D3 night |
| S4-15 | Bench report loose ends | tara (Sonnet) | nisha | F3 revert_culprit_only cells shown as "n/a: culprit wrote nothing landed", not under failures; F3 system "pause-only" label in the table, not only notes; the 1 xfailed test located and either fixed or given a reason string | D2 |
| S4-16 | Frozen-build tag + one-command reproducer | maya (Opus) | kabir | Tag `finale-freeze` at 26 Nov 18:00; `make bench-headline` reproduces BENCH-S3 F2+ rows bit-for-bit for seed 2; full pytest + container suite green on the tag | D6 |
| S4-17 | Finale rehearsal ×2 on the frozen build | pmo (Opus) with Aarav | panel | Run of show ≤ the finale slot, timed per beat; live `make demo` + demo-sim fallback both shown; panel asks 10 JURY-QA questions, answers logged | 28 Nov, 1 Dec |

## Critical path
S4-02 (README) → **S4-04 jury dry run (D3)** → S4-05..08 fixes (D4–D5) → S4-09 re-attack → **S4-16 freeze tag (D6 18:00)** → S4-17 rehearsals. S4-01 runs in parallel and must land by D2 so the jury attacks the hardened build. S4-10/11/12 are off the path but due D2 so Aarav's abstract (22 Nov) can cite final wording. Aarav is busy with the abstract until 22 Nov: only D-18 needs him before then.

## If time runs out, cut in this order
1. S4-14 T=120 (keep A4, say T=40 everywhere). 2. S4-13 approver (ship disclosure S4-11 only). 3. S4-03 Docker Desktop (document OrbStack only). 4. S4-09 shrinks to re-trying Musts only. **Never cut:** S4-01, S4-02, S4-04 + its Must fixes, S4-10, S4-16.

## Load
At most 4 agents at once; one `ks run` per machine (uid 60000+), so S4-14 runs overnight and nobody else runs container tests then. Opus: kabir, panel, anaya, vikram (only if D-18 = B), maya.
