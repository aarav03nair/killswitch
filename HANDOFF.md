# Handoff: where work stopped (20 Nov 2026, early IST)

Running in **Claude Code in IntelliJ** on Aarav's Mac. All work committed; agents were stopped mid-task on Aarav's request. Tests at this commit: `.venv/bin/python -m pytest -q` gives 820 passed, 8 skipped, 1 xfailed (container suite not re-run at this commit; last container run 815 passed). Venv: `uv venv -p 3.13 .venv && uv pip install -p .venv -e . pytest jsonschema`. Native macOS = degraded isolation (attribution VOID); per-agent uids need Docker (OrbStack, `~/.orbstack/bin/docker`; one image tag per agent).

## Status
- **Sprint 3: complete (54/54 done).** Hero path B3-27 runs end to end (`make demo`, anchored, per-agent uids): all CALL-02 B2 targets met (as amended B2-a/B2-b). Red team RT1–RT13 wired (B3-35, 0 xfail). 20-seed bench B3-33: table in `org/reports/BENCH-S3.md` (raw in `runs/bench-b3-33/`, gitignored).
- **Headline numbers (T=40, H=6, 20 seeds, F2+):** R=0 after the operator released a median 5 held items (3 honest, 2 tainted; max 9 on seed 2) · C=0 · reemitted 0 · TTI detect 2 ticks [0..2] · TTC 1. Baselines: snapshot/revert-culprit-only R median 3/5. D10 contrast (pause, no recovery): hold off releases median 12 tainted payments (6–18, 20/20 seeds), hold on 0. F2+x leaves R 1/5 and 29 held honest items (conflict flagged, approver never resolves flags).
- **Decisions by Aarav:** D-15 `ks.seed` · B3-45 option C (read tags) · D-16 reporter independent (B2-a) · D-17 R=0 claims state operator releases (B2-b).
- Contracts now 1.6.0 (additive; 1.3–1.5 runs still verify).
- Board: `python3 board/render.py`.

## Next, in order
1. **Call #4: Sprint 4 kickoff.** Plan from: S4-01 (red-team gaps: forged witness ack, outbox provenance RT, ttc unavailable), Panel jury dry run, finale rehearsal (`board/demo-sim.html`: update D10 to the before-recovery contrast), README/demo polish.
2. Code freeze 26 Nov 18:00 IST.

## Waiting on Aarav
- ⚑ **D-21 (top priority once the deterministic demo is done): add one real LLM agent through the gateway?** The project targets AI agents; the bench uses deterministic agents only for oracle scoring (CALL-01 D4/D9, ADR-06). Options: local model offline / Claude API (breaks hard rule 4) / state as future work.
- ⚑ D-02 headline · ⚑ D-10 hero field objects · ⚑ D-11 D13 target wording.
- His own abstract (due **22 Nov**). Run ABS-07: comment-only reviews (zoya, anaya), and never rewrite his sentences.

## Gotchas learned
- **Only one `ks run` at a time per machine**: runs claim uids 60000+. Parallel test runs or parallel agents collide (the K2 guard refuses). Run pytest serially.
- Opus usage limits hit four times (once this session; resumed agents via SendMessage). Keep Opus for leads, reviews and vikram; Sonnet for the rest; at most about 4 agents at once.
- Agents never commit; the PMO commits after each wave.
- Reviews keep finding real bugs. Keep the gate.
