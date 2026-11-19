# Handoff: where work stopped (19 Nov 2026, evening IST)

Running in **Claude Code in IntelliJ** on Aarav's Mac. Wave 3 is committed. Tests: `.venv/bin/python -m pytest -q` gives 515 passed, 8 skipped (create the venv with `uv venv -p 3.13 .venv && uv pip install -p .venv -e . pytest jsonschema`; Homebrew python3.15 has no pytest). Native macOS now runs in degraded mode (attribution VOID); per-agent uids need Docker (README "Run on macOS"). **Docker/OrbStack is not installed yet**: Aarav agreed to install OrbStack.

## Status
- **Sprints 0–2 (research, framing, design): done.** Abstract Kit delivered; reference draft at `abstract/REFERENCE-DRAFT.md` (model only; Aarav writes his own). Design frozen in Call #2. Build plan in Call #3.
- **Sprint 3 build: 15 of 43 issues done (incl. SKEL-01).** Wave 3 closed: B3-04 (after kabir's changes) · B3-05 world/agents/view · B3-06 tool adapters (after maya's changes) · B3-08 witness · B3-09 recorder txn + hooks · B3-10 10-agent runtime · B3-36 Panel skeleton fixes · B3-37 seams · B3-40 seam follow-ups. Decision **D-SEQ1** (maya, in `src/ks/ARCHITECTURE.md`): seq 1 is the seed record, agent actions start at seq 2.
- **B3-39 Docker: in_review**, waiting on a real `make smoke` run (base tag `python:3.13.1-slim-bookworm` not yet pulled). Re-review by kabir once OrbStack is in.
- **Linux-root tests written but never executed** (must pass in the container before the demo): `test_witness_file_owned_by_witness_uid_mode_0600_and_gateway_holds_no_fd`, `test_shared_uid_run_as_root_uses_one_unprivileged_uid`, `test_cross_uid_ptrace_eperm_and_nondumpable_after_exec`, `test_forced_shared_uid_aborts_before_tick0`.
- New follow-up issues: **B3-41** (nisha, after B3-11) gateway is the authority on read/write sets, recorded denials, gateway-built outbox, lift the 1-tick world cap and extend the repro test, test-spy allowlist · **B3-42** (arjun) witness seq/head equivocation, signer drip, unbound-connection S3. Review notes also logged on B3-11 (seed record, int visible_to), B3-13 (all four uid fields, reject "."/".."), B3-15 (narrowed to value-vs-hash reconcile; edited state.db currently verifies OK).
- Board: `python3 board/render.py` then open `board/index.html`. Abstract Kit: `python3 board/kit.py`. Demo rehearsal: `board/demo-sim.html`.

## Next, in order (dependency graph in `python3 org/issue.py list --sprint 3`)
1. Once OrbStack is in: `make smoke`, run the 4 Linux-root tests in the container, kabir re-reviews B3-39.
2. Wave 4: B3-11 gateway pipeline (nisha) → B3-41 / B3-14 / B3-23; B3-12 CLI (ishaan); B3-13 c-0 + operator socket (maya); B3-15 verify (arjun) and B3-42; B3-16/B3-17 inject (tara); B3-18 taint (vikram).
3. Then gateway (B3-11 → B3-14 → B3-23), taint (B3-18), planner (B3-21), re-run simulation (B3-24, critical path), oracle/score (B3-22/26) → **B3-27 hero end-to-end (target 24 Nov)** → apply/bench/console/red-team → **code freeze 26 Nov 18:00 IST**.
4. Slip rule: if B3-24 is not green by 24 Nov 18:00, maya pairs with vikram and B3-29 moves to Sprint 4.
5. Sprint 4: 20-seed bench, red team RT1–RT13, Panel jury dry run, finale rehearsal (`board/demo-sim.html` is the script).

## Waiting on Aarav
- Install OrbStack (`brew install --cask orbstack`, open it once) so the Linux-root tests and `make smoke` can run.
- ⚑ D-02 headline · ⚑ D-10 hero field objects · ⚑ D-11 D13 target wording.
- His own abstract (due **22 Nov**). Run ABS-07: comment-only reviews (zoya, anaya), and never rewrite his sentences.
- Stretch decision: one LangGraph agent running through our gateway (not yet in the plan).

## Gotchas learned
- **Only one `ks run` at a time per machine**: runs claim uids 60000+. Parallel test runs or parallel agents collide (the K2 guard refuses). Run pytest serially.
- Opus usage limits hit three times. Keep Opus for leads, reviews and vikram; Sonnet for the rest; at most about 4 agents at once.
- Agents never commit; the PMO commits after each wave.
- Reviews keep finding real bugs. Keep the gate.
