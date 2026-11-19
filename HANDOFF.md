# Handoff: where work stopped (19 Nov 2026, ~10:50 IST)

Moved from the Claude app to Claude Code. The previous session hit the Opus 5-hour usage limit mid-wave; the interrupted items are below. Nothing is broken: `python3 -m pytest -q` gives 231 passed.

## Status by sprint
- **Sprint 0 Kickoff:** done.
- **Sprint 1 Research:** done. 11 reports + synthesis, all reviewed. Lacuna Research connector was used for RES-09/10/11.
- **Sprint 2 Frame & Design:** in its last step. Abstract Kit delivered to Aarav. Contracts v1.0.0 built. All 8 ADRs written, reviewed, and frozen in **Call #2** (`org/meetings/CALL-02.md` + `CALL-02/resolutions.md`).
- **Sprint 3 Build:** not started. Opens after CON-02 lands.

## Interrupted mid-task (resume these first)
| Issue | Owner | State | What's left |
|---|---|---|---|
| **CON-02** contracts v1.1.0 | maya (opus) | Started, **no code changes landed yet** | Implement the whole "CON-02 checklist" in `CALL-02/resolutions.md` + amendments X1, X2, X7, X8-F1 in `CALL-02.md` + Kabir's sign-off tests (see `CALL-02/kabir.md`, `org/reports/SEC-03.md` B1–B4). Then Kabir signs (closes CON-01 + SEC-03). **Critical path.** |
| **ADR-00** freeze amendments | maya | Amendments section written, uncommitted, not re-verified | Re-read against Panel M1–M7 + assignment table; set `in_review` |
| **ADR-05** freeze amendments | vikram (opus) | Amendments written, was trimming length | Finish trim; set `in_review` |
| **SEC-02 + THREAT-MODEL** freeze updates | kabir | Unknown progress | Apply N1–N5, D4, F7, H5, X6, X7, Maya's SEC-02 review items; THREAT-MODEL v4 (ks.operator, c-0, operator socket, repro ≠ security run) |
| **ABS-08** kit update for the freeze | zoya | Not started (agent died early) | Update TERMS, GUARDRAILS, SKELETON, JURY-QA, SYNTHESIS §6 for the new hero decision + D13 wording; apply Maya's ABS-04 name corrections. Then `python3 board/kit.py` |

## Waiting for review (freeze applied)
ADR-01, ADR-02 (reviewer kabir), ADR-03 (kabir), ADR-04 (maya), ADR-06 (anaya), ADR-07 (zoya). Each reviewer only re-checks their own must-fixes.

## Waiting on Aarav (Product Owner)
- ⚑ D-02 layered headline · ⚑ D-10 hero = field-level objects for sensitive fields · ⚑ D-11 revised D13 target wording (all on the board under Decisions).
- **ABS-07:** when Aarav pastes his abstract draft, run two comment-only review rounds (zoya framing, anaya facts). Never rewrite his sentences.

## Next, in order
1. Finish CON-02 → Kabir sign-off → commit.
2. Close ADR reviews; ABS-08 kit refresh (abstract due **22 Nov**).
3. **SKEL-01** walking skeleton: 2 agent subprocesses (own uids) → gateway stub → recorder → `ks verify`, plus the same-seed determinism test.
4. **Call #3**, Sprint 3 build kickoff. Leads open small build issues per module (ownership in `CALL-01/maya.md` §3 + ADR assignment table): arjun identity/recorder/witness/verify · nisha gateway/policy/monitor/containment · vikram state/taint/recovery (9.5-day estimate, so start early) · tara world/inject/oracle/score/bench · ishaan cli/console · maya runtime + integration.
5. Sprint 4: 10-agent benchmark (≥20 seeds), red-team RT1–RT12, Panel jury dry-run, 5-beat demo (`CALL-01/zoya.md` §4).

## Published pages (Claude app artifacts; may not open from Claude Code)
- Board: https://claude.ai/artifact/HSWLtXFe9GYB36whkxwhwL. Locally: `python3 board/render.py` → `board/index.html`.
- Abstract Kit: https://claude.ai/artifact/S7oNQViS1fy7pz7ZwLZw1f. Locally: `python3 board/kit.py` → `board/kit.html`.
- How it works: https://claude.ai/artifact/38FVafjkHf2vXLTm2z6uBF. Locally: `abstract/how-it-works.html`.

## Lessons from the first session
- Opus usage limits hit twice. Keep Opus for leads, reviews and the rollback engine; use Sonnet for most dev/research work.
- Reviews caught real bugs every round (anti-framing, epoch reuse, sibling ptrace hijack, oracle leaks). Keep the review gate.
