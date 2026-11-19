# Handoff: where work stopped (19 Nov 2026, ~16:10 IST)

Moving from the Claude app to **Claude Code in IntelliJ** on Aarav's Mac. Everything is committed. `python3 -m pytest -q` gives 462 passed. On macOS, run tests and demos inside Docker (see README "Run on macOS"), because the runtime uses Linux per-agent uids.

## Status
- **Sprints 0–2 (research, framing, design): done.** Abstract Kit delivered; reference draft at `abstract/REFERENCE-DRAFT.md` (model only; Aarav writes his own). Design frozen in Call #2. Build plan in Call #3.
- **Sprint 3 build: 9 of 40 issues finished** (B3-01 contracts 1.2 · B3-02 errata · B3-03 state store · B3-04 field objects/read rule/savepoints · B3-07 + B3-38 monitor · B3-37 refactor seams · B3-39 Docker · SKEL-01 skeleton). Reviews pending: B3-04 (maya), B3-37 (panel), B3-39 (kabir; Docker never executed in the cloud sandbox, so the first real run is on the Mac).
- Board: `python3 board/render.py` then open `board/index.html`. Abstract Kit: `python3 board/kit.py`. Demo rehearsal: `board/demo-sim.html`.

## Next, in order (dependency graph in `python3 org/issue.py list --sprint 3`)
1. Close the 3 reviews above.
2. **Wave 3** (all unblocked now): B3-05 world + view (tara) · B3-06 tool adapters (tara) · B3-08 witness fd handover (arjun) · B3-09 recorder txn + GatewayHooks (arjun) · B3-36 Panel skeleton fixes M1/M2/S2/S3 (arjun, after B3-08) · B3-10 10-agent runtime (maya, after B3-05).
3. Then gateway (B3-11 → B3-14 → B3-23), taint (B3-18), planner (B3-21), re-run simulation (B3-24, critical path), oracle/score (B3-22/26) → **B3-27 hero end-to-end (target 24 Nov)** → apply/bench/console/red-team → **code freeze 26 Nov 18:00 IST**.
4. Slip rule: if B3-24 is not green by 24 Nov 18:00, maya pairs with vikram and B3-29 moves to Sprint 4.
5. Sprint 4: 20-seed bench, red team RT1–RT13, Panel jury dry run, finale rehearsal (`board/demo-sim.html` is the script).

## Waiting on Aarav
- ⚑ D-02 headline · ⚑ D-10 hero field objects · ⚑ D-11 D13 target wording.
- His own abstract (due **22 Nov**). Run ABS-07: comment-only reviews (zoya, anaya), and never rewrite his sentences.
- Stretch decision: one LangGraph agent running through our gateway (not yet in the plan).

## Gotchas learned
- **Only one `ks run` at a time per machine**: runs claim uids 60000+. Parallel test runs or parallel agents collide (the K2 guard refuses). Run pytest serially.
- Opus usage limits hit three times. Keep Opus for leads, reviews and vikram; Sonnet for the rest; at most about 4 agents at once.
- Agents never commit; the PMO commits after each wave.
- Reviews keep finding real bugs. Keep the gate.
