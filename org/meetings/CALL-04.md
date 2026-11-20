# Call #4: Sprint 4 kickoff (harden, prove, rehearse)

**Date:** 20 Nov 2026 (IST) · **Chair:** Claude (PMO) · **Inputs:** CALL-04/maya-plan.md, CALL-04/kabir.md, CALL-04/zoya.md, org/reports/BENCH-S3.md · **Decisions by Aarav:** D-18, D-19

## Where we are
- Sprint 3 complete (54/54, ff86363, pushed). Hero F2+ runs end to end via `make demo` (anchored, per-agent uids). Red team RT1–RT13 wired. 20-seed bench at T=40: F2+ R=0 after a median 5 operator releases (3 honest), C=0, TTI 2, TTC 1; F2+x R 1/5 with 29 honest items held.

## Decisions
1. **Rule for Sprint 4:** every issue closes a jury attack, fixes what a dry run finds, makes the demo and numbers reproducible, or implements D-18. Contracts change only additively. Code freeze **26 Nov 18:00 IST**.
2. **D-18 (Aarav): auditable, reversible conflict resolver.** Each resolution of a flagged write-write conflict is a signed, recorded decision (rule, key, released items, rationale), checked by verify, shown in the console, reversible through recovery with its own trace. F2+x reported before and after. (S4-12 design, S4-13 build.)
3. **D-19 (Aarav, D13): the abstract may cite measured BENCH-S3 numbers** with their conditions (D-17 release count; F2+x disclosed). Zoya publishes the allowed list (S4-18).
4. **Overclaims to fix first** (kabir, zoya): demo-sim says "R 0/6" with no release count and shows an unmeasured hold-0 number; README still says demo.sh runs the skeleton; Kit says reporter re-runs and payments cancel.
5. **Known limits stated up front** (kabir): native macOS = attribution VOID; view-sourced self-read gap (t0 delta); verify without `--head` is "consistent, not anchored"; collusion/threshold splitting out of scope.
6. **Cut order if late:** T=120 rerun → Docker Desktop check → second jury dry run shrinks to Musts. Never cut: S4-01, README, jury dry run + Must fixes, demo-sim truth, freeze tag. D-18 is Aarav's call and stays; if it slips past D5 it ships behind its own flag with the before-row as headline.

## Sprint 4 issues
S4-01 red-team gaps (kabir) · S4-02 fresh-Mac README (ishaan) · S4-03 Docker Desktop check (ishaan) · S4-04 Panel jury dry run #1 (panel) · S4-09 jury dry run #2 (panel) · S4-10 demo-sim to real numbers, D10 before-recovery (zoya/ishaan) · S4-11 F2+x disclosure (anaya) · S4-12 resolver design (maya) · S4-13 resolver build (vikram) · S4-14 T=120 rerun (tara) · S4-15 bench report loose ends (tara) · S4-16 freeze tag + reproducer (maya) · S4-17 rehearsals (pmo + Aarav) · S4-18 Kit refresh v5 + D-19 allowed numbers (zoya) · S4-19 console shows operator releases (ishaan) · S4-20 RT14 view-sourced gap surfaced (tara) · S4-21 mutation gate (kabir) · S4-22 finale preflight (maya) · S4-23 claim audit (kabir) · S4-24 F2+c C=0 vs GUARDRAILS L8 (anaya) · S4-25 ABS-07 comment-only review (zoya, anaya). Fix slots S4-05..08 open after S4-04.

## Wave 1 (now)
S4-02 README · S4-10 demo-sim · S4-12 resolver design · S4-01 red-team gaps.
