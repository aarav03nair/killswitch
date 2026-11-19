# ks: modules, owners, seams (B3-37)

The ownership comes from Call #3. Each seam is the **only** way the two sides reach each other, so owners can build in parallel without editing each other's files. `tests/skeleton/test_boundaries.py` enforces the seams.

| Module | Owner | Does | Interface it exposes / consumes |
|---|---|---|---|
| `ks.contracts` | maya | Data shapes C1–C6 and the one canonical serializer | Imported by everyone. Imports no other `ks` module. |
| `ks.rng` | maya | The one RNG derivation, `sha256(canonical([seed, name, tick]))` (ADR-00 M1) | `draw`, `draw_hex`, `draw_int`. Depends only on `ks.contracts`. |
| `ks.runtime` | maya | Processes, uids, **tick barrier (I/O + timing only)**, teardown | Consumes `Gateway.open(tick, agents) -> {agent: TickFrame}` and `Gateway.tick(tick, [InFrame]) -> [(conn_id, ReplyFrame)]`. Does frame collection, deadlines, K-miss and oversize close, and the witness push. It never decodes a frame. `run.py` is the wiring point: it picks the world's dispatcher. |
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
