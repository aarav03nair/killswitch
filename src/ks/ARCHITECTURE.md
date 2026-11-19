# ks: modules, owners, seams (B3-37)

The ownership comes from Call #3. Each seam is the **only** way the two sides reach each other, so owners can build in parallel without editing each other's files. `tests/skeleton/test_boundaries.py` enforces the seams.

| Module | Owner | Does | Interface it exposes / consumes |
|---|---|---|---|
| `ks.contracts` | maya | Data shapes C1–C6 and the one canonical serializer | Imported by everyone. Imports no other `ks` module. |
| `ks.rng` | maya | The one RNG derivation, `sha256(canonical([seed, name, tick]))` (ADR-00 M1) | `draw`, `draw_hex`, `draw_int`. Depends only on `ks.contracts`. |
| `ks.runtime` | maya | Processes, uids, **tick barrier (I/O + timing only)**, teardown | Consumes `Gateway.open(tick, agents) -> {agent: TickFrame}` and `Gateway.tick(tick, [InFrame]) -> [(conn_id, ReplyFrame)]`. Does frame collection, deadlines, K-miss and oversize close, and the witness push. It never decodes a frame. `run.py` is the wiring point; `runtime/setup.py` resolves the scenario (skeleton or the 10-agent world), picks the world's dispatcher, and checks the isolation readback before tick 0 (B3-10). |
| `ks.gateway` | nisha | Reference monitor: control/epoch, view, admission (ADR-01 §8), dispatch, and later policy, monitor hook and outbox | Behind `open`/`tick`. Owns no tool table. Calls `ToolDispatcher` (`ks.gateway.dispatch`): `classify(env) -> ActionClass` and `execute(env, txn) -> Execution(result, read_set, write_set)`. |
| `ks.world` | tara | Scenario, agent behaviour (`skeleton.step`, inside agent processes) and tools (`tools.SkeletonDispatcher`, gateway side), plus the injector | Implements `ToolDispatcher`. **Never imports `ks.runtime`.** Gets randomness from `ks.rng`. |
| `ks.state` | vikram | Versioned object store (ADR-05) | Becomes the `txn` passed to `ToolDispatcher.execute`. The skeleton passes `None` (`StateTxn` placeholder). Gateway-only. |
| `ks.monitor` | nisha | Detectors, attribution, alerts (ADR-04) | Pure functions over records, a `StateView` and the side store. |
| `ks.identity` | arjun | Keys, signer handle service | `SignerService.begin_tick/handle`, called by the barrier for signer I/O. |
| `ks.recorder` | arjun | Hash-chained record and side store | Only the gateway appends. The barrier reads `seq`/`head` for the checkpoint. |
| `ks.witness` | arjun | Separate witness process and its link | `WitnessLink.push(seq, head, tick, timeout)`. |
| `ks.verify` | arjun | Offline verification | Never imports `ks.recorder`. |
| `ks.cli` | ishaan | The `ks` command | `ks run`, `ks verify`. |

## Rules
- Allowed dependency direction: `runtime → gateway → (dispatch protocol) ← world`. Only `runtime/run.py` wires `world` into `gateway`.
- The gateway runs frames in agent_id order (`Gateway.tick` sorts them) and ignores arrival order.
- A tool the dispatcher does not know is class U and is denied (rule 6). A dispatcher reads and writes only through `txn`, so read/write sets are what the store saw.

## Decision D-SEQ1 (maya, 19 Nov, B3-05 review): the seed is record seq 1
Every `ks.state` version carries the record `seq` that wrote it, and every seq must have a record (otherwise a version has no evidence behind it, and an agent's log is testimony, not evidence).
- **Record seq 1 is the seed record**: one gateway-authored record (author `ks.gateway`, tick 0, `SYSTEM_CONN`) whose `write_set` is exactly the versions `ks.world.scenario.seed_state(store, seq=1)` wrote. It is appended before tick 1 opens. Owner: nisha (gateway, B3-11); vikram's `ks.state` needs no change (`seq >= 1` stays).
- **Agent action seqs start at 2.** The tick-1 view uses `visible_to = 2`, so the seed is visible and nothing written in tick 1 is (M2).
- Rejected: seeding at seq 0 (would need a schema change to `CHECK (seq >= 1)` and leaves seed versions with no record to verify against) and a reserved seq with no record (same gap).
- Recovery: the backward walk stops at seed versions (author `ks.gateway`, seq 1; ADR-05 §5). The planner never restores or re-runs seq 1.
- Until B3-11 lands, harnesses (`tests/world/harness.py`, the runtime) seed at seq 1 and start actions at seq 2. That is the same numbering, so nothing changes when the gateway takes over.

## Views (M2)
`ViewProvider.view(agent, tick, state)` gets a snapshot carrying `visible_to` = the first seq of the tick (the seq the tick's first action would take). A view must never default to "all heads".
