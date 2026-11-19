# Handoff: where work stopped (19 Nov 2026, night IST)

Running in **Claude Code in IntelliJ** on Aarav's Mac. Wave 4 checkpoint committed. Tests: `.venv/bin/python -m pytest -q` gives 716 passed, 8 skipped; container 724 passed (create the venv with `uv venv -p 3.13 .venv && uv pip install -p .venv -e . pytest jsonschema`; Homebrew python3.15 has no pytest). Native macOS runs in degraded mode (attribution VOID); per-agent uids need Docker (OrbStack installed, `~/.orbstack/bin/docker`). Linux-root tests: `docker build -t killswitch:<name> . && docker run --rm --network none killswitch:<name> python -m pytest -q` (one tag per agent).

## Status
- **Sprints 0–2: done.** Design frozen in Call #2 (amended: G1-a `ks.seed`, D-15). Build plan in Call #3.
- **Sprint 3 done so far:** B3-01..12, B3-14..18, B3-36..40, B3-42..44, SKEL-01. Wave 4 closed this session: B3-11 gateway pipeline · B3-12 CLI + `RunOptions` · B3-14 policy · B3-15 verify rules · B3-16 aggregate reads · B3-17 inject · B3-18 taint · B3-42 witness/signer follow-ups · B3-43 contracts 1.3 (`ks.seed`, `tool_error`) · B3-44 world matches CALL-02 B2/B3 (triage view tickets-only; `reports:` table).
- **In review:** B3-41 gateway set authority + runtime wiring (nisha → panel; includes the tool-read vs view-version decision) · B3-21 recovery planner (vikram → maya; **uncommitted**, in src/ks/recovery + tests/recovery).
- **Decisions by Aarav this session:** D-15 add `ks.seed` · B3-45 option C (read entries tagged view|tool; built as B3-46 after B3-41).
- Board: `python3 board/render.py` then open `board/index.html`.

## Next, in order (dependency graph in `python3 org/issue.py list --sprint 3`)
1. Close B3-41 and B3-21 reviews; commit recovery.
2. **B3-24 re-run simulation (vikram, critical path; slip rule: green by 24 Nov 18:00 IST, else maya pairs with him and B3-29 moves to Sprint 4).** Also ready: B3-13 c-0 + operator socket (maya), B3-23 outbox/holds (nisha), B3-22 oracle (tara), B3-46 (maya, after B3-41), B3-32 F8 (nisha), B3-28 console (ishaan).
3. → B3-19 containment, B3-26 score → **B3-27 hero end-to-end (target 24 Nov)** → apply/bench/console/red-team → **code freeze 26 Nov 18:00 IST**.
4. Sprint 4: 20-seed bench, red team RT1–RT13, Panel jury dry run, finale rehearsal (`board/demo-sim.html`).

## Waiting on Aarav
- ⚑ D-02 headline · ⚑ D-10 hero field objects · ⚑ D-11 D13 target wording.
- His own abstract (due **22 Nov**). Run ABS-07: comment-only reviews (zoya, anaya), and never rewrite his sentences.
- Stretch decision: one LangGraph agent running through our gateway (not yet in the plan).

## Gotchas learned
- **Only one `ks run` at a time per machine**: runs claim uids 60000+. Parallel test runs or parallel agents collide (the K2 guard refuses). Run pytest serially.
- Opus usage limits hit four times (once this session; resumed agents via SendMessage). Keep Opus for leads, reviews and vikram; Sonnet for the rest; at most about 4 agents at once.
- Agents never commit; the PMO commits after each wave.
- Reviews keep finding real bugs. Keep the gate.
