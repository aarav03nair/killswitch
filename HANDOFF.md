# Handoff: where work stopped (20 Nov 2026, early IST)

Running in **Claude Code in IntelliJ** on Aarav's Mac. All work committed; agents were stopped mid-task on Aarav's request. Tests at this commit: `.venv/bin/python -m pytest -q` gives 820 passed, 8 skipped, 1 xfailed (container suite not re-run at this commit; last container run 815 passed). Venv: `uv venv -p 3.13 .venv && uv pip install -p .venv -e . pytest jsonschema`. Native macOS = degraded isolation (attribution VOID); per-agent uids need Docker (OrbStack, `~/.orbstack/bin/docker`; one image tag per agent).

## Status (21 Nov)
- **Sprint 3 complete.** Sprint 4 (harden, prove, rehearse) in progress; code freeze **26 Nov 18:00 IST**.
- **Sprint 4 done:** S4-01, S4-02, S4-04, S4-09, S4-10..13, S4-15, S4-18..24, S4-26..29, S4-31..34. Two Panel jury dry runs: every Must fixed (reports org/reports/PANEL-JURY-01.md, -02.md). Mutation gate 12/12 (REDTEAM-S4.md).
- **D-18 resolver built** (opt-in `--resolver ww_rebase/1`, signed/verified/undoable): F2+x R 1/5→0, C 21/254→0, held honest 29→3 (container, 20 seeds). Contracts 1.8.0.
- **Kit for the abstract is final:** abstract/ALLOWED-NUMBERS.md (D-19), F2+c disclosed (D-20).
- **Open:** S4-03 Docker Desktop check · S4-14 T=120 rerun (run overnight, quiet host) · S4-16 freeze tag + reproducer (26 Nov) · S4-17 rehearsals (28 Nov, 1 Dec) · S4-25 ABS-07 comment-only review once Aarav shares his abstract · S4-30 F2+c fixture (after finale, D-20).
- Run the finale with `make finale` on a quiet machine (host load causes deadline misses; the preflight refuses).

## Waiting on Aarav
- ⚑ **D-21 (top priority once the deterministic demo is done): add one real LLM agent through the gateway?** The project targets AI agents; the bench uses deterministic agents only for oracle scoring (CALL-01 D4/D9, ADR-06). Options: local model offline / Claude API (breaks hard rule 4) / state as future work.
- ⚑ D-02 headline · ⚑ D-10 hero field objects · ⚑ D-11 D13 target wording.
- His own abstract (due **22 Nov**). Run ABS-07: comment-only reviews (zoya, anaya), and never rewrite his sentences.

## Gotchas learned
- **Only one `ks run` at a time per machine**: runs claim uids 60000+. Parallel test runs or parallel agents collide (the K2 guard refuses). Run pytest serially.
- Opus usage limits hit four times (once this session; resumed agents via SendMessage). Keep Opus for leads, reviews and vikram; Sonnet for the rest; at most about 4 agents at once.
- Agents never commit; the PMO commits after each wave.
- Reviews keep finding real bugs. Keep the gate.
