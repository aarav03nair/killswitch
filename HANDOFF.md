# Handoff: where work stopped (19 Nov 2026, evening IST)

Running in **Claude Code in IntelliJ** on Aarav's Mac. Wave 3 is committed. Tests: `.venv/bin/python -m pytest -q` gives 515 passed, 8 skipped (create the venv with `uv venv -p 3.13 .venv && uv pip install -p .venv -e . pytest jsonschema`; Homebrew python3.15 has no pytest). Native macOS now runs in degraded mode (attribution VOID); per-agent uids need Docker (README "Run on macOS"). OrbStack is installed and running.

## Status
- **Sprints 0–2 (research, framing, design): done.** Abstract Kit delivered; reference draft at `abstract/REFERENCE-DRAFT.md` (model only; Aarav writes his own). Design frozen in Call #2. Build plan in Call #3.
- **Sprint 3 build: 16 of 43 issues done (incl. SKEL-01).** Wave 3 closed: B3-04 (after kabir's changes) · B3-05 world/agents/view · B3-06 tool adapters (after maya's changes) · B3-08 witness · B3-09 recorder txn + hooks · B3-10 10-agent runtime · B3-36 Panel skeleton fixes · B3-37 seams · B3-40 seam follow-ups. Decision **D-SEQ1** (maya, in `src/ks/ARCHITECTURE.md`): seq 1 is the seed record, agent actions start at seq 2.
- **B3-39 Docker: done.** `make smoke` verifies anchored (--head) on OrbStack arm64. Container suite: 523 passed, all 4 Linux-root tests green (B3-10's failure was a test bug: /proc/<pid> itself always shows the task uid; check /status and /fd).
- Linux-root tests: run in Docker with `docker build -t killswitch:<name> . && docker run --rm --network none killswitch:<name> python -m pytest -q`.
- New follow-up issues: **B3-41** (nisha, after B3-11) gateway is the authority on read/write sets, recorded denials, gateway-built outbox, lift the 1-tick world cap and extend the repro test, test-spy allowlist · **B3-42** (arjun) witness seq/head equivocation, signer drip, unbound-connection S3. Review notes also logged on B3-11 (seed record, int visible_to), B3-13 (all four uid fields, reject "."/".."), B3-15 (narrowed to value-vs-hash reconcile; edited state.db currently verifies OK).
- Board: `python3 board/render.py` then open `board/index.html`. Abstract Kit: `python3 board/kit.py`. Demo rehearsal: `board/demo-sim.html`.

## Next, in order (dependency graph in `python3 org/issue.py list --sprint 3`)
1. B3-11 gateway pipeline (nisha) in review with kabir; contract decision on a `ks.seed` system tool with maya.
2. Wave 4: B3-11 gateway pipeline (nisha) → B3-41 / B3-14 / B3-23; B3-12 CLI (ishaan); B3-13 c-0 + operator socket (maya); B3-15 verify (arjun) and B3-42; B3-16/B3-17 inject (tara); B3-18 taint (vikram).
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
