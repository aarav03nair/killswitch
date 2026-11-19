# ADR-00: Topology, tick barrier and determinism

Owner: maya · Status: in review · Binding: CALL-01, **CALL-02 freeze** (resolutions + X1–X9), THREAT-MODEL v3, contracts **v1.1.0** (CON-02), PANEL-ENG-00, Panel ADR-00 review

## Context

If scheduling noise, a human click or a key changes order, time or ids, S\* diverges and re-runs do not reproduce (CALL-01 top risk).

**S\*** (A1, X3a): same seed and config, fault disabled (the culprit runs its honest step; a `--rogue` slot no-ops from `fault_tick`); pure world (monitor, containment, recovery off; outbox dispatches at `release_tick`); the culprit also stops from the tick it was suspended in the faulty run. Formulas: ADR-06.

## Decision

**Processes.** `ks run` becomes the gateway (uid 0, non-dumpable, `oom_score_adj −1000`). It hosts the TCB modules (policy, state, recorder, monitor, containment, outbox, recovery) and the signer endpoints (`MAX_SIGN_PER_TICK`, refusals per ADR-01), and spawns:
- the **witness**: uid 60000, `oom_score_adj −1000`, head store `<run>/witness-heads/` (0700, witness uid). In fresh mode it generates its own key and the gateway never holds it (E4);
- one **agent per entry of `RunConfig.agents`**: index i, uid 60001+i, `conn_id = c-(i+1)`. `c-0` is reserved for in-gateway system envelopes; system agent_id ⇔ `c-0` in both directions (X7).

Each agent gets two path-less, **non-blocking** `socketpair`s (gateway, signer), `close_fds`, env `{PYTHONHASHSEED=0}` only, argv `agent_id`, `PR_SET_DUMPABLE=0`, `oom_score_adj +1000`, `RLIMIT_NPROC`; the `--rogue` slot also runs at nice 19, `SCHED_IDLE`, `RLIMIT_CPU` (K3). Outbound queues are capped at 64 KiB per connection, overflow → EOF; the reader is bounded by `MAX_FRAME_BYTES` and never waits for an LF (K1). At start the gateway refuses to run if any process with uid 60000..6000N exists (K2), checks cross-uid `ptrace` → EPERM, and the console prints the mode, including `key_mode` and any degraded mode.

**Operator channel** (J1): `/run/ks/<run_id>/operator.sock` in a 0700 uid-0 dir, `SO_PEERCRED` uid == 0. `ks contain`, `ks recover --apply` and `ks console --live` reach the gateway only here; it turns requests into `ks.operator`-signed Controls (E2; `ks.console` no longer exists).

**Ground-truth blinding** (A3): TCB modules receive `RunConfig.tcb_view()`, with `fault`, `culprit` and `fault_tick` blanked. Only `ks.world`'s injector and the scorer read them.

Key isolation, verbatim: **"enforced in production (uid/container), detected here by reconciliation"**.

**Tick barrier (gateway = scheduler).** For tick n:
0. *Gate* (C1): if a plan awaits approval and n = plan_tick + L (`RunConfig.decision_latency_ticks`), tick n does not open until the decision arrives; an earlier click waits for that tick.
1. *Control phase*: queued system envelopes (`ks.monitor` incl. `ks.alert`, `ks.operator`, `ks.recovery`) in (principal, queue) order, at most 32, surplus carried over in order. Other operator Controls land at the next control phase. Auto-suspends from n−1 land before any agent frame. The view is then snapshotted (M2).
2. *Open*: send `TickFrame(n, epoch, view)` to every live connection. `epoch` is None while suspended or revoked (D3). `view` = `[ViewEntry{obj, ver, hash, value}]` from the scenario's narrow per-agent scope (≤ `MAX_VIEW_ENTRIES` = 64), ids per `row_obj_id`/`field_obj_id`; the entries join the read_set of that tick's submission, and a row entry that omits a sensitive field reads only the row (I1, X1, X2).
3. *Collect* **exactly one frame per connection, FIFO** (C2), until every live connection delivered one or `--tick-deadline-ms` passes (wall clock, default 2000; demo 250).
   - A frame tagged ≠ n becomes `deny/late_frame` in that agent's execute slot. Surplus frames stay queued.
   - A missing frame becomes a no-op plus a soft `barrier.deadline` anomaly (empty `evidence_seqs`, agent in `root_candidates`). After 3 consecutive misses the connection gets EOF: an anomaly, not a suspend, no epoch bump (K4).
   - EOF means no-op from then on.
4. *Execute* in `agent_id` order, then send `ReplyFrame`s. Execution is sequential: an action at seq s sees a version written at seq w iff s > w, so same-tick earlier writes are visible to adapter reads but not in that tick's view (M2).
5. *Dispatch* due outbox items as `ks.dispatch` records (at most 32, carried over). *Monitor* runs detectors and reconciliation and queues alerts and Controls for n+1.
6. *Flush* `record.jsonl`, then checkpoint (below).

**The gateway alone assigns** `seq`, `ts_us`, `record_id` and `conn_id`:
- `seq` starts at 1, one per received envelope (exec, deny, hold, unparseable, Control, alert, dispatch), no gaps, assigned at the start of the step's txn (ADR-03).
- `record_id = record_id_for(seq)` = `r-%06d`; seq 1 has `prev_hash = GENESIS_HASH`.
- `ts_us = start_ts_us + tick·tick_us + slot`, slot = 0-based position in the tick. Records per tick ≤ 32 + |agents| + 32, and startup asserts `tick_us` > that sum (C7).
- `claimed_*` fields are evidence only; `WitnessCheckpoint.seq` and `VerifyReport.first_bad` are seqs.

**Witness cadence** (F6). After the flush the gateway sends `(seq, head, tick)`; the witness signs `WitnessCheckpoint(seq, head, tick, count)` (`count` from 1, +1 per line), appends to its head store and to `witness.jsonl` (created and owned by the witness uid) and acks. Tick n+1 waits for the ack **up to the deadline, then proceeds** and queues `witness_stall` (W = 1, never hard; recovery freeze by kind, ADR-02). No-op ticks repeat `(seq, head)` with a new `count`.

**Sources of determinism.**
- The tick is the only clock; wall clock goes only to `timing.jsonl`.
- One RNG derivation everywhere: `sha256(canonical([seed, name, tick]))` per consumer (world, each agent, injector) (M1). A culprit's divergence or a dropped step shifts nobody's later draws.
- One canonical serializer, sorted sets, SQL `ORDER BY`, one writer per file.
- **Keys** (C3): `RunConfig.key_mode = fresh|repro`. *Fresh* (live, security runs): random keys in gateway memory; the witness makes its own. *Repro* (tests, bench): `HKDF(secret, salt=seed, info="ks/key/v1/"‖principal)`, deterministic Ed25519, from `--repro-secret FILE` (0600 uid 0, outside the run dir). Repro forces `anchored=false`, is refused with `--rogue`, is banned for D11/RT2/RT8 and labelled "not a security run" (X7).
- **Replay** (C1, X6): `ks run --decisions RUN` replays recorded operator Controls at their recorded ticks. The source must pass `verify --head`, approvals must match `plan_hash`, and it is refused with `--rogue`.

**Run-dir.** Modes per SEC-03 F1 (X8, contracts K7): run dir 0711; `record.jsonl` 0640, group = witness gid; side store 0700/0600; agents get EACCES on every run-dir file. After `RunConfig.ticks`: agents get EOF, SIGKILL, then **kill by uid** (K2); a final checkpoint; the console prints the `RunAnchor` (ADR-02). After exit the dir is evidence only; a dead-run dry-run writes outside it (C7). Keys die with the gateway, so recovery executes only live.

## Consequences

- Arrival order is discarded. A flooding, stalling, looping or forking rogue delays only itself, plus at most three consecutive deadlines before EOF; the others keep ticking.
- Plan approvals land at a fixed tick. Other live operator Controls land at a wall-clock tick but are recorded, so `--decisions` reproduces the run. Remaining breaks (deadline misses) are visible as anomalies. Bench decisions are scripted with the same L.
- Fresh-key runs are equal only through `determinism_view()`; "byte-identical" is claimed only for repro bench runs.
- The contracts README key-isolation paragraph takes the wording above (CON-02 K12).

## Interface touched

Consumes contracts v1.1.0 names (landed by CON-02, not edited here): **C1** claimed fields, `MAX_EXPIRY_TICKS`; **C2** seq/tick/ts_us/record_id/conn_id, `SYSTEM_CONN`, `WitnessCheckpoint.count`, `LATE_FRAME`, `determinism_view()`; **C4** soft `barrier.deadline` with empty evidence, `witness_stall` hard=False; **C6** `agents`, `tick_us`, `start_ts_us`, `ticks`, `seed`, `fault_tick`, `key_mode`, `decision_latency_ticks`, `tcb_view()`, `RunAnchor`, `WITNESS_HEADS_DIR`, `Exit.DIVERGED`, `DETERMINISTIC_FILES` = config, record\*, witness\*, alerts, effects.jsonl, oracle/\*\*, score.json, plans/\*\*, sidestore/\*\* (\* = via projection; no keys.json); **Transport** `TickFrame.epoch`, `TickFrame.view`/`ViewEntry`, `MAX_VIEW_ENTRIES`, `MAX_SIGN_PER_TICK`; **ids** `ks.operator`.

## Tests that prove it

- **T1 same seed → byte-identical**: repro mode, clean and F2+, gateway under 3 PYTHONHASHSEEDs; all `DETERMINISTIC_FILES` byte-identical, 0 deadline misses. CI 3 seeds, bench ≥20.
- **T1b fresh keys**: projected files equal; the rest byte-identical without stripping. `test_fresh_keys_differ`, `test_witness_key_not_in_gateway`, `test_ks_repro_fresh_pair` (`ks repro A B`, ADR-07).
- **T2 faulty ≡ S\* before t_inject**: per fault, records and checkpoints with `tick < fault_tick` byte-identical, no alerts before it, equal state digest at `fault_tick − 1`; `test_oracle_self` (B = ∅).
- **T3 jitter** below the deadline → T1-identical. **T3b** flooding, pre-sent and wrong-tick frames → T1-identical, `late_frame` in the slot.
- **T4 stall**: sleep, fork, non-reader, CPU spin, memory bomb: per-agent projection (tick, tool, args_hash, decision, read/write sets) of honest agents unchanged, 0 honest misses, wall time bounded by the K4 eviction. `test_fork_survivor_killed`.
- **T5 conventions**: seq 1..n no gaps, `record_id_for`, `ts_us` formula and caps, one checkpoint per tick, `count` chain, conn_ids in spawn order, system ⇔ `c-0`.
- `test_replay_decisions_identical`, `test_tcb_blind` (blanking fault fields leaves the record identical) + AST guard, `test_operator_sock_rejects_agent`, `test_hung_witness`, `test_same_tick_visibility`, `test_crm_record_reads_T3`.

## Amendments (Call #2)

- **A1** S\* definition (Context); **X3a** culprit stops at its suspend tick in S\*; T2 at `fault_tick`.
- **A3** `tcb_view()`, `test_tcb_blind` + AST guard.
- **C1** decision gate (step 0), `decision_latency_ticks`, `--decisions` replay; **X6** replay preconditions.
- **C2** one frame per connection per tick, FIFO, `deny/late_frame`, T3b (replaces `expired`/`over_quota` for frames).
- **C3** `key_mode`, repro-secret rules; **X7** repro ⇒ `anchored=false`, refused with `--rogue`, `ks.console` removed, system ⇔ `c-0`.
- **C4** new `DETERMINISTIC_FILES`, keys.json removed. **C5** `determinism_view()`.
- **C7** 3 PYTHONHASHSEEDs, per-agent T4 projection, caps 32/32 + `tick_us` assert, dead-run dry-run outside the run dir.
- **D3** `TickFrame.epoch`. **E4** witness owns its fresh key (with **E2** rename to `ks.operator`).
- **F6** witness stall: wait to the deadline, proceed, alert; `witness-heads/` 0700.
- **I1** `TickFrame.view` joins the read_set; **X1/X2** view ids and row/field read rule.
- **J1** operator socket. **K1** non-blocking I/O, 64 KiB cap. **K2** kill by uid, refuse start, `RLIMIT_NPROC`. **K3** oom/nice/`SCHED_IDLE`/`RLIMIT_CPU`. **K4** EOF after 3 misses, demo 250 ms.
- **M1** RNG `sha256(canonical([seed, name, tick]))`. **M2** view snapshot after control phase, in-tick visibility.
- **X8** run-dir file modes (SEC-03 F1), landed in CON-02 K7.
- **X9** noted: the I1 view is on the build critical path; no design change. X4, X5: not applicable to ADR-00 (ADR-06/07).
- Panel must-fixes: **M1** → C1; **M2** → A1/A2/A3 (t0 naming per ADR-05/06); **M3** → C2; **M4** → K1, `MAX_SIGN_PER_TICK`, F6; **M5** → K2–K4; **M6** → C3–C5, E4; **M7** → J1. Should-fixes S1–S6 → M1, C7, M2, C7, `barrier.deadline` evidence (C4), C7.
- Trimmed: run-dir creation and append-only steps (ADR-02, contracts).
