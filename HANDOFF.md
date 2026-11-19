# Handoff: where work stopped (20 Nov 2026, early IST)

Running in **Claude Code in IntelliJ** on Aarav's Mac. All work committed; agents were stopped mid-task on Aarav's request. Tests at this commit: `.venv/bin/python -m pytest -q` gives 820 passed, 8 skipped, 1 xfailed (container suite not re-run at this commit; last container run 815 passed). Venv: `uv venv -p 3.13 .venv && uv pip install -p .venv -e . pytest jsonschema`. Native macOS = degraded isolation (attribution VOID); per-agent uids need Docker (OrbStack, `~/.orbstack/bin/docker`; one image tag per agent).

## Status
- **Done this session (Sprint 3):** B3-04..12, B3-14..18, B3-21, B3-22 oracle, B3-26 score, B3-36..46 (incl. contracts 1.3 `ks.seed` and 1.4 read tags view|tool, additive). Decisions by Aarav: D-15 (`ks.seed`), B3-45 option C.
- **Stopped mid-task (uncommitted work is IN this commit, unreviewed):**
  - **B3-24 re-run simulation (vikram, critical path, slip rule 24 Nov 18:00):** hero dry-run passes on world F2+ records, but maya's review found the in-process driver (tests/recovery/world.py) skips the outbox release phase and the taint/sensitive holds. vikram was rewriting the driver over the real `ks.gateway.Gateway` when stopped.
  - **B3-23 outbox (nisha):** kabir's blocker: release phase must check each item against its creating record (outbox_ids + write_set ver/hash) and HOLD on failure. Probe: scratchpad test_zz_kabir_probe.py (outside repo). Partially done when stopped.
  - **B3-13 c-0 + operator socket (maya):** in progress, operator socket module not finished.
  - **B3-28 console (ishaan):** built, in review; maya to review (run it on vikram's real plan; decide ADR-07 `--pace` amendment).
- PMO fix: `ks verify` on a relative run path failed reconcile; fixed in src/ks/verify/core.py with a regression test (logged on B3-31).
- Board: `python3 board/render.py` then open `board/index.html`.

## Next, in order
1. Resume B3-24 (vikram), B3-23 (nisha), B3-13 (maya); review B3-28 (maya). Re-run the container suite.
2. → B3-19 containment, B3-30 apply (notes logged) → **B3-27 hero end-to-end (target 24 Nov)** → bench/console/red-team → **code freeze 26 Nov 18:00 IST**.
3. Sprint 4: 20-seed bench, red team RT1–RT13, Panel jury dry run, finale rehearsal (`board/demo-sim.html`).

## Waiting on Aarav
- ⚑ D-02 headline · ⚑ D-10 hero field objects · ⚑ D-11 D13 target wording.
- His own abstract (due **22 Nov**). Run ABS-07: comment-only reviews (zoya, anaya), and never rewrite his sentences.
- Stretch decision: one LangGraph agent running through our gateway (not yet in the plan).

## Gotchas learned
- **Only one `ks run` at a time per machine**: runs claim uids 60000+. Parallel test runs or parallel agents collide (the K2 guard refuses). Run pytest serially.
- Opus usage limits hit four times (once this session; resumed agents via SendMessage). Keep Opus for leads, reviews and vikram; Sonnet for the rest; at most about 4 agents at once.
- Agents never commit; the PMO commits after each wave.
- Reviews keep finding real bugs. Keep the gate.
