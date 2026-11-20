# Handoff: where work stopped (20 Nov 2026, early IST)

Running in **Claude Code in IntelliJ** on Aarav's Mac. All work committed; agents were stopped mid-task on Aarav's request. Tests at this commit: `.venv/bin/python -m pytest -q` gives 820 passed, 8 skipped, 1 xfailed (container suite not re-run at this commit; last container run 815 passed). Venv: `uv venv -p 3.13 .venv && uv pip install -p .venv -e . pytest jsonschema`. Native macOS = degraded isolation (attribution VOID); per-agent uids need Docker (OrbStack, `~/.orbstack/bin/docker`; one image tag per agent).

## Status
- **Done (Sprint 3):** B3-01..29, B3-31, B3-36..47 except as below. This session also closed B3-13 c-0 + operator socket, B3-19 containment, B3-20 decisions replay, B3-23 outbox/holds, B3-24 re-run simulation (critical path, green before the 24 Nov slip date), B3-28 console, B3-29 conflict rule, B3-31 verify F4/F6, B3-47 contracts 1.5 (replay_mismatch → exit 6 DIVERGED).
- **In progress (uncommitted WIP may be in the tree):** B3-30 recovery apply via c-0 (maya; long note list on the issue) · B3-48 rider items stay held on F2+x (vikram).
- **Next unblocked:** B3-25 F9 reexec_of verify (arjun) · B3-32 F8 flood budget (nisha) · B3-27 hero end-to-end (maya, after B3-30) · B3-33 bench, B3-34 console beats, B3-35 red-team wiring.
- Decisions by Aarav: D-15 (`ks.seed`), B3-45 option C. Board: `python3 board/render.py`.

## Next, in order
1. Finish B3-30 and B3-48; then B3-27 hero end-to-end.
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
