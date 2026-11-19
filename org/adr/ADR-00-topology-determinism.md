# ADR-00: Topology, tick barrier and determinism

Owner: maya · Status: in review · Binding: CALL-01, **CALL-02 freeze** (resolutions, X1–X9), THREAT-MODEL v3, contracts **v1.1.0**, Panel ADR-00 review

## Context

If scheduling noise, a human click or a key changes order, time or ids, re-runs diverge (CALL-01 top risk).

**S\*** (A1, X3a): same seed and config, fault disabled (the culprit runs its honest step; a `--rogue` slot no-ops from `fault_tick`); pure world (monitor, containment, recovery off; outbox dispatches at `release_tick`); the culprit also stops from the tick it was suspended in the faulty run. Formulas: ADR-06.

## Decision

**Processes.** `ks run` is the gateway (uid 0, non-dumpable, `oom_score_adj −1000`). It hosts the TCB modules (policy, state, recorder, monitor, containment, outbox, recovery) and the signer endpoints (`MAX_SIGN_PER_TICK`, ADR-01), and spawns:
- the **witness**: uid 60000, `oom_score_adj −1000`, head store `<run>/witness-heads/` (0700, witness uid). In fresh mode it generates its own key and the gateway never holds it (E4);
- one **agent per entry of `RunConfig.agents`**: index i, uid 60001+i, `conn_id = c-(i+1)`. `c-0` is reserved for in-gateway system envelopes; system agent_id ⇔ `c-0` in both directions (X7).

Each agent gets two path-less, **non-blocking** `socketpair`s (gateway, signer), `close_fds`, env `{PYTHONHASHSEED=0}` only, `PR_SET_DUMPABLE=0`, `oom_score_adj +1000`, `RLIMIT_NPROC` (K2, K3); the `--rogue` slot also runs at nice 19, `SCHED_IDLE`, `RLIMIT_CPU`. Outbound queues cap at 64 KiB per connection (overflow → EOF); the reader is bounded by `MAX_FRAME_BYTES` and never waits for an LF (K1). At start the gateway refuses to run if any process with uid 60000..6000N exists (K2), checks cross-uid `ptrace` → EPERM, and the console prints `key_mode` and any degraded mode.

**Operator channel** (J1): `/run/ks/<run_id>/operator.sock` in a 0700 uid-0 dir, `SO_PEERCRED` uid == 0. `ks contain`, `ks recover --apply` and `ks console --live` reach the gateway only here; it turns requests into `ks.operator`-signed Controls (E2; `ks.console` no longer exists).

**Ground-truth blinding** (A3): TCB modules receive `RunConfig.tcb_view()`, with `fault`, `culprit` and `fault_tick` blanked. Only `ks.world`'s injector and the scorer read them.

Key isolation, verbatim: **"enforced in production (uid/container), detected here by reconciliation"**.

**Tick barrier (gateway = scheduler).** For tick n:
0. *Gate* (C1): if a plan awaits approval and n = plan_tick + L (`RunConfig.decision_latency_ticks`), tick n does not open until the decision arrives; an earlier click waits for that tick.
1. *Control phase*: queued system envelopes (`ks.monitor` incl. `ks.alert`, `ks.operator`, `ks.recovery`) in (principal, queue) order, at most 32, surplus carried over in order. Other operator Controls land at the next control phase. Auto-suspends from n−1 land before any agent frame. The view is snapshotted (M2).
2. *Open*: send `TickFrame(n, epoch, view)` to every live connection. `epoch` is None while suspended or revoked (D3). `view` = `[ViewEntry{obj, ver, hash, value}]` from the scenario's per-agent scope (≤ `MAX_VIEW_ENTRIES` = 64), ids per `row_obj_id`/`field_obj_id`; entries join that tick's read_set, and a row entry omitting a sensitive field reads only the row (I1, X1, X2).
3. *Collect* **exactly one frame per connection, FIFO** (C2), until every live connection delivered one or `--tick-deadline-ms` passes (wall clock, default 2000; demo 250).
   - A frame tagged ≠ n becomes `deny/late_frame` in that agent's execute slot. Surplus frames stay queued.
   - A missing frame becomes a no-op plus a soft `barrier.deadline` anomaly (carries `conn_id`; empty `evidence_seqs`, evidence and `root_candidates`: it names a connection, never an agent). After 3 consecutive misses the connection gets EOF: an anomaly, not a suspend, no epoch bump (K4).
   - EOF means no-op from then on.
4. *Execute* in `agent_id` order, then send `ReplyFrame`s. Execution is sequential: an action at seq s sees a version written at seq w iff s > w, so same-tick earlier writes reach adapter reads but not the view (M2).
5. *Dispatch* due outbox items as `ks.dispatch` records (at most 32, carried over). *Monitor* runs detectors and reconciliation and queues alerts and Controls for n+1.
6. *Flush* `record.jsonl`, then checkpoint (below).

**The gateway alone assigns** `seq`, `ts_us`, `record_id` and `conn_id`:
- `seq` starts at 1, one per received envelope (exec, deny, hold, unparseable, Control, alert, dispatch), no gaps, assigned at the start of the step's txn (ADR-03).
- `record_id = record_id_for(seq)` = `r-%06d`; seq 1 has `prev_hash = GENESIS_HASH`.
- `ts_us = start_ts_us + tick·tick_us + slot` (slot = 0-based position in the tick). Records per tick ≤ 32 + |agents| + 32; startup asserts `tick_us` exceeds it (C7).
- `claimed_*` fields are evidence only.

**Witness cadence** (F6). After the flush the gateway sends `(seq, head, tick)`; the witness signs `WitnessCheckpoint(seq, head, tick, count)` (`count` from 1, +1 per line), appends to its head store and to `witness.jsonl` (created and owned by the witness uid) and acks. Tick n+1 waits for the ack **up to the deadline, then proceeds** and queues `witness_stall` (W = 1, never hard; ADR-02). No-op ticks repeat `(seq, head)` with a new `count`.

**Sources of determinism.**
- The tick is the only clock; wall clock goes only to `timing.jsonl`.
- One RNG derivation everywhere: `sha256(canonical([seed, name, tick]))` per consumer (world, each agent, injector) (M1). A culprit's divergence or a dropped step shifts nobody's later draws.
- One canonical serializer, sorted sets, SQL `ORDER BY`, one writer per file.
- **Keys** (C3): `RunConfig.key_mode = fresh|repro`. *Fresh* (live, security runs): random keys in gateway memory; the witness makes its own. *Repro* (tests, bench): `HKDF(secret, salt=seed, info="ks/key/v1/"‖principal)`, deterministic Ed25519, from `--repro-secret FILE` (0600 uid 0, outside the run dir). Repro forces `anchored=false`, is refused with `--rogue`, is banned for D11/RT2/RT8, and is labelled "not a security run" (X7).
- **Replay** (C1, X6): `ks run --decisions RUN` replays recorded operator Controls at their recorded ticks. The source must pass `verify --head`, approvals must match `plan_hash`, and it is refused with `--rogue`.

**Run-dir.** Modes per SEC-03 F1 (X8, contracts K7): run dir 0711; `record.jsonl` 0600, gateway only (the witness is pushed `(seq, head, tick)` and never reads it); side store 0700/0600; agents get EACCES on every run-dir file. After `RunConfig.ticks`: agents get EOF, SIGKILL, then **kill by uid** (K2); a final checkpoint; the console prints the `RunAnchor` (ADR-02). After exit the dir is evidence only (dead-run dry-runs write outside it, C7); keys die with the gateway, so recovery executes only live.

## Consequences

- Arrival order is discarded. A flooding, stalling or forking rogue delays only itself, plus at most three deadlines before EOF.
- Plan approvals land at a fixed tick. Other live Controls land at a wall-clock tick but are recorded, so `--decisions` reproduces the run. Deadline misses show as anomalies. Bench decisions are scripted with the same L.
- Fresh-key runs are equal only through `determinism_view()`; "byte-identical" is claimed only for repro bench runs.
- The contracts README takes the key-isolation wording above (CON-02 K12).

## Interface touched

Consumes the contracts v1.1.0 names landed by CON-02 (not edited here): `RunConfig` fields and `tcb_view()`, `RunAnchor`, `determinism_view()`, `DETERMINISTIC_FILES` (C4), `LATE_FRAME`, `WitnessCheckpoint.count`, soft `barrier.deadline`, `TickFrame.epoch`/`view`, `MAX_VIEW_ENTRIES`, `MAX_SIGN_PER_TICK` = 2, `ks.operator`.

## Tests that prove it

- **T1 same seed → byte-identical**: repro mode, clean and F2+, gateway under 3 PYTHONHASHSEEDs; all `DETERMINISTIC_FILES` byte-identical, 0 deadline misses. CI 3 seeds, bench ≥20.
- **T1b fresh keys**: projected files equal, the rest byte-identical unstripped. `test_fresh_keys_differ`, `test_witness_key_not_in_gateway`, `test_ks_repro_fresh_pair` (ADR-07).
- **T2 faulty ≡ S\* before t_inject**: per fault, records and checkpoints with `tick < fault_tick` byte-identical, no earlier alerts, equal state digest at `fault_tick − 1`; `test_oracle_self`.
- **T3 jitter** below the deadline → T1-identical. **T3b** flooding, pre-sent, wrong-tick frames → T1-identical, `late_frame` in the slot.
- **T4 stall**: sleep, fork, non-reader, CPU spin, memory bomb: per-agent projection (tick, tool, args_hash, decision, read/write sets) of honest agents unchanged, 0 honest misses, wall time bounded by K4. `test_fork_survivor_killed`.
- **T5 conventions**: seq 1..n, `record_id_for`, `ts_us` and caps, one checkpoint per tick, `count` chain, conn_ids in spawn order, system ⇔ `c-0`.
- `test_replay_decisions_identical`, `test_tcb_blind` + AST guard, `test_operator_sock_rejects_agent`, `test_hung_witness`, `test_same_tick_visibility`, `test_crm_record_reads_T3`.

## Amendments (Call #2)

- **A1**, **X3a** S\* and culprit stop (X3b–d: ADR-05/06). **A3** `tcb_view()`. **C1**, **X6** decision gate, replay. **C2** one frame per tick. **C3**, **X7** `key_mode`, repro rules, `ks.console` removed. **C4** files. **C5** projection. **C7** hash seeds, caps, dry-run outside run dir.
- **D3** epoch. **E4**, **E2** witness key, `ks.operator`. **F6** witness stall. **I1**, **X1/X2** view and read rule. **J1** operator socket. **K1–K4** I/O, kill by uid, oom/nice, EOF after 3 misses. **M1** RNG. **M2** snapshot, visibility. **X8** run-dir modes. **X9** noted, no design change. X4, X5: not ADR-00.
- Panel must-fixes: **M1** → C1; **M2** → A1/A3; **M3** → C2; **M4** → K1, F6; **M5** → K2–K4; **M6** → C3–C5, E4; **M7** → J1. Should-fixes: **S1** → M1; **S2**, **S4**, **S6** → C7; **S3** → M2; **S5** → C4.
- Trimmed: run-dir creation, append-only steps (ADR-02).
- Integration pass: `barrier.deadline` anomaly has `conn_id` and empty `root_candidates`; `record.jsonl` is 0600 gateway-only.
