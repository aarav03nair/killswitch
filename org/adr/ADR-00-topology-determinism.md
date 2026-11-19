# ADR-00: Topology, tick barrier and determinism

Owner: maya · Status: in review · Binding: CALL-01, THREAT-MODEL v3, contracts 1.0.0, PANEL-ENG-00

## Context

The oracle scores R/C against S\*, a clean run with the same seed. If scheduling noise changes order, time or ids, S\* diverges and re-runs do not reproduce (CALL-01 top risk).

## Decision

**Processes.** `ks run` becomes the gateway (uid 0, non-dumpable). It hosts the TCB modules (policy, state, recorder, monitor, containment, outbox, recovery) and the signer endpoints, and spawns:
- the **witness**: uid 60000, own key, own head store `<run>/witness-heads/` (0700);
- one **agent per entry of `RunConfig.agents`**: index i, uid 60001+i, `conn_id = c-(i+1)`.

Each agent gets two path-less `socketpair`s (gateway, signer), `close_fds`, env `{PYTHONHASHSEED=0}` only, per-uid rlimits, and argv `agent_id` plus its stream seed. The template sets `PR_SET_DUMPABLE=0` before agent code. ADR-01 may split out the signer; the barrier is unchanged. At start the gateway checks cross-uid `ptrace` → EPERM, and the console prints the mode, including any degraded mode.

Key isolation, verbatim: **"enforced in production (uid/container), detected here by reconciliation"**.

**Tick barrier (gateway = scheduler).** For tick n:
1. *Control phase*: run queued system envelopes (`ks.monitor`, `ks.console`, `ks.recovery`) in (principal, queue) order. Auto-suspends from n−1 land before any agent frame.
2. *Open*: send `TickFrame(n)` to every live connection.
3. *Collect* one `SubmitFrame` or `NoopFrame` per agent, until all agents answer or `--tick-deadline-ms` passes (wall clock, default 2000).
   - A missing frame becomes a no-op plus a `barrier.deadline` anomaly (never hard).
   - Earlier-tick frames become `deny/expired`; extra frames `deny/over_quota` (capped per connection).
   - EOF means no-op from then on.
4. *Execute* in `agent_id` order, then send `ReplyFrame`s.
5. *Dispatch* due outbox items (holds re-checked). *Monitor* runs detectors and reconciliation and queues Controls for n+1.
6. *Flush* `record.jsonl`, then checkpoint with the witness.

**The gateway alone assigns** `seq`, `ts_us`, `record_id` and `conn_id`. Confirmed conventions:
- `seq` starts at 1 and increments by one per received envelope (exec, deny, hold, unparseable, Control), with no gaps.
- `record_id = record_id_for(seq)` = `r-%06d`. Seq 1 has `prev_hash = GENESIS_HASH`.
- `ts_us = start_ts_us + tick·tick_us + slot`, where slot is the record's 0-based position in its tick. Startup rejects `tick_us` ≤ the maximum records per tick.
- `claimed_seq`/`claimed_ts_us` are evidence only. `WitnessCheckpoint.seq` is the seq of `head`. `VerifyReport.first_bad` is a seq (= line number).

**Witness cadence.** After the flush the gateway sends `(seq, head, tick)`. The witness bumps its monotonic `count`, signs, appends to its head store and to `witness.jsonl` (owned by the witness uid), and acks. Tick n+1 waits for the ack: one checkpoint per tick from the first tick with a record. No-op ticks repeat `(seq, head)` with a new count. No ack within the deadline raises `witness_stall`.

**Sources of determinism.**
- The tick is the only clock. Wall clock goes only to `timing.jsonl`.
- Per-consumer RNG streams `sha256(seed‖name)` (world, each agent, injector): a culprit's divergence shifts nobody else's draws.
- One canonical serializer, sorted sets, SQL `ORDER BY`, one writer per file.
- Keys are `HKDF(key_secret, salt=seed, info="ks/key/v1/"‖principal)`, and Ed25519 signatures are deterministic. `key_secret` lives in gateway memory only; the witness receives its own key over its socketpair. Live runs use a fresh random secret. Tests and bench pass `--repro-secret FILE` (outside the run dir), and the console prints "not a security run".

**Run-dir lifecycle.**
1. `RunDir.create` refuses an existing dir. `config.json` and `keys.json` (public keys only) are written once; `workspace/` is 0700 uid 0.
2. Append-only during ticks.
3. After `RunConfig.ticks`: agents get EOF, then SIGKILL; a final checkpoint is taken; the console prints the final signed head and count (the off-filesystem anchor).
4. After exit the dir is evidence only (`verify`, `score`, dry-run plans). Keys die with the gateway, so recovery executes only inside a live run.

## Consequences

- Arrival order is discarded. A stalling, looping or forking rogue costs one deadline per tick, and the others keep ticking.
- Determinism breaks only on a deadline miss or a live console click, and both are visible. Bench console decisions are scripted.
- Fresh-key runs are identical only in their key-stripped projection (records without `envelope.sig`, `hash`, `prev_hash`, `gw_sig`; checkpoints without `head`, `sig`).
- The key-isolation paragraph in the contracts README (v2, "enforced here") must take the wording above.

## Interface touched

Consumes C1 (claimed fields; expiry and epoch in ticks), C2 (seq/tick/ts_us/record_id/conn_id), C6 (`agents` order, `tick_us`, `start_ts_us`, `ticks`, `seed`, `DETERMINISTIC_FILES`) and Transport. Change requests (CON-02, bump `CONTRACTS_VERSION`):
- C2: add `count` to `WitnessCheckpoint`.
- C6: add `fault_tick` (t0) to `RunConfig`, because the scorer reads only the run dir.
- C4: allow empty `evidence_seqs` for `barrier.deadline` anomalies.

## Tests that prove it

- **T1 same seed → byte-identical**: two runs with the same seed and repro secret, clean and F2+. `DETERMINISTIC_FILES`, `plans/**` and `sidestore/**` are byte-identical, with 0 deadline misses. CI uses 3 seeds, bench ≥20. **T1b**: fresh keys give an identical key-stripped projection.
- **T2 faulty run ≡ S\* before t0**: per fault, clean vs faulty with the same seed. Records and checkpoints with `tick < t0` are byte-identical, there are no alerts before t0, and the state digest at t0−1 is equal.
- **T3 jitter**: random arrival delays below the deadline give T1-identical records.
- **T4 stall**: a sleeping or forking agent costs one deadline per tick, and the other agents' records are unchanged.
- **T5 conventions**: seq 1..n with no gaps, `record_id_for`, the `ts_us` formula, one checkpoint per tick, conn_ids in spawn order.
