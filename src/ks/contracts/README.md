# ks.contracts: C1–C6 reference (CON-01 → CON-02, contracts **1.1.0**, frozen 22 Nov)

Import from `ks.contracts`, never from submodules. Every type is a frozen pydantic model that rejects unknown
fields. Each one has `to_canonical()` / `from_canonical()` (strict: the bytes must already be canonical) and
`to_obj()`. Documents also have `signing_bytes()` and `content_hash()`. Field docs, including the OTel
`gen_ai.*` / `ks.*` mapping, are in the code and in `schema/*.schema.json`. Regenerate the schemas with
`python -m ks.contracts.schema_gen`. A test fails if they drift, and any field change bumps `CONTRACTS_VERSION`.

| Contract | Types | Run dir file |
|---|---|---|
| C1 Envelope | `Envelope` (on the socket, raw `args`), `EnvelopeHeader` (signed + recorded, `args_hash`), `ActLink`; `MAX_EXPIRY_TICKS`, `expiry_ok()` | in `record.jsonl` |
| C2 Record | `Record` (+`reexec_of`), `WitnessCheckpoint` (+`count`), `Decision` exec/deny/hold, `Reason`, `ActionClass` R/C/I1/I2/U; `determinism_view()`, `witness_chain_problems()` | `record.jsonl`, `witness.jsonl` |
| C3 State | `StateView`/`StateWriter`/`SideStore` protocols; `ObjVer`, `VersionRef`, `ReadEntry`, `ViewEntry`, `WriteEntry`, `StateRead`, `HistoryEntry`, `OutboxItem`, `SideEntry`; `make_obj_id`/`field_obj_id`/`row_obj_id`/`split_obj_id`; `idempotency_key()` | `sidestore/xx/<hash>.json` |
| C4 | `Alert` (`root_candidates` ranked; no `suspect`; H3 hard table), `Control` (target `agent:`/`conn:`/`action:`/`outbox:`), `EpochFold` | `alerts.jsonl` (copy); Alerts and Controls inside records |
| C5 | `RecoveryPlan` (`t0_seq_est`), `TaintSet`, steps `restore`/`rerun`/`replan`/`cancel_outbox`/`compensate`/`flag`, `DiffEntry`; `Approval`, `RecoverArgs` | `plans/<plan_id>.json` |
| C6 | `RunConfig` (seed, `fault_tick`, `key_mode`, `decision_latency_ticks`, `hold_window_ticks`, `sensitive_fields`, agents; `tcb_view()`), `Keyring`, `RunAnchor`, `RunDir`, `Exit`, `VerifyReport` (+`anchored`) | `config.json`, `keys.json` |
| Transport | `TickFrame` (+`epoch`, `view`), `SubmitFrame`, `NoopFrame`, `ReplyFrame`, `SignRequest`, `SignReply`; `MAX_VIEW_ENTRIES`, `MAX_SIGN_PER_TICK`, `signer_refusal()` | JSON lines over Unix sockets |

## One serializer
`ks.contracts.canonical` (`dumps`, `loads`, `dumps_line`, `loads_line`) is the only encoder that signer,
gateway, recorder and verify may use. Its rules:
- sorted keys (UTF-16 order), UTF-8, no whitespace
- integers only, within ±(2^53−1)
- **no floats** (use minor units or ticks)
- **no bytes** (hex-encode them)

- **nesting depth ≤ `MAX_DEPTH` = 32** (v1.1). `loads` pre-scans before parsing; `dumps` checks while recursing.
- **every decode failure is a `CanonicalError`** (v1.1): `loads`, `decode_frame` and `from_canonical` never raise
  anything else (`NonCanonicalError` for non-canonical bytes, `ContractError` for schema/validator failures). The
  gateway maps `CanonicalError` to `deny/schema`; a deep or huge frame can no longer escape as `RecursionError`.

On this domain the output is byte-identical to RFC 8785 JCS. A test greps `src/ks` for `json.dumps` and similar
calls.

## Sign-ready bytes and hashes
`signing_bytes() = DOMAIN_TAG + 0x00 + canonical(doc minus sig/hash fields)` and `content_hash() = sha256(signing_bytes)`.
Each type has its own tag (`ks/envelope/v1`, `ks/record/v1`, ...), so a signature from one type can't be replayed as another.
```python
env = Envelope(agent_id="crm", action_id="crm-7", parent_action_id=None, act_chain=(), tool="crm.update_supplier",
               args={...}, nonce=rng_hex32, expiry_tick=t + 2, epoch=e, claimed_ts_us=None, claimed_seq=None, sig=None)
env = env.with_sig(signer.sign(env.signing_bytes()))   # agent signs the HEADER (args -> args_hash)
rec = Record.seal(prev_hash=last.hash, seq=n, record_id=record_id_for(n), envelope=env.header(),
                  envelope_hash=env.content_hash(), sig_ok=True, ...)       # gateway only
rec = rec.with_gw_sig(gw_key.sign(rec.signing_bytes()))
```
- Records start at `seq = 1` with `prev_hash = GENESIS_HASH`.
- The witness signs a `WitnessCheckpoint(seq, tick, head=rec.hash)` once per tick.
- `rec.integrity_problems()` gives the per-record checks. Chain, signature and witness checks belong to `ks.verify`, which uses `Exit.*` codes and prints a `VerifyReport` as its last line.

## What NOT to put in records (rule 9)
- No raw values, args, results, or free-text summaries.
- Records carry `(obj, ver, hash)` and `args_hash` / `result_hash` only. The values go to the side store as a `SideEntry` keyed by that hash, and can be redacted.
- `StateRead.value` is raw, so it stays inside the gateway.
- Plain hashes of low-entropy values (IBANs) can be reversed with a dictionary. Records are **pseudonymised, not anonymised**. Redaction removes the value; the hash remains guess-confirmable. Keyed commitments are deferred to 2.0 (SEC-03 §5). Do not export the value hashes of `sensitive_fields` via OTel (N10).
- No wall-clock time anywhere in records. `ts_us` is logical time derived from the tick. Wall clock goes only in `timing.jsonl`, the one file that is allowed to differ between runs.

## Rules the types enforce (kabir §4; the rest live in the gateway)
- **Unknown action class is rejected.** `class U` ⇒ `deny` (rule 6).
- **Every decision has a reason code.** `reason` must fit the `decision` (`REASONS_FOR`), and `exec` ⇒ `ok`.
- **Denials have no effects.** `deny` carries no read set, write set, outbox items or result. `hold` carries no writes or result (rule 11: denials are still recorded).
- **Attribution (Q9).** The record embeds the claimed `agent_id` and `act_chain` plus `sig_ok`. Read attribution **only** through `rec.attributed_agent`, which is `None` for `bad_sig`/`schema`. A forged envelope is never counted against the agent it claims to be.
- **Anti-framing (D7).**
  - A `signature` alert names only `conn_id`.
  - `tamper`, `witness_stall` and `reconcile` alerts name nobody. A `barrier.deadline` alert may name a connection (`conn_id`), never an agent (PMO S5).
  - **Hard table (H3):** `hard` ⇔ detector ∈ `HARD_DETECTORS` = {`inv.beneficiary_changed_then_paid`, `inv.ledger_balance`, `inv.iban_checksum`, `inv.pii_egress`, `scope`, `reconcile`, `sig`}. `tamper`/`witness_stall` are never hard (the freeze follows from their kind); anomalies and rate are soft. Each well-known detector must report its kind (`DETECTOR_KIND`).
  - `root_candidates[0]` is the writer of `evidence_versions`; two or more writers, or none, means no auto-suspend; agents reached only through reads are never auto-suspended (M9, H1, H2).
  - `revoke` is never `auto` and is issued only by `ks.operator`.
  - Suspending, revoking or releasing an agent sets a **new, strictly higher** epoch (D1; `EpochFold`). Release never restores the pre-suspend epoch, and lifts only suspension holds.
- **Signed, recorded controls (rule 10).** Controls are envelopes with `tool="ks.control"` and `args = control.to_obj()`, signed by `issued_by` (validator: `issued_by == envelope.agent_id`). The record carries the Control in clear, bound to it by `args_hash`.
- **System principals and `c-0` (E1, K4, X7).** A system `agent_id` is verified only on `c-0`; on `c-1..` it is `deny/bad_sig`, unverified. Every c-0 envelope claims a system principal. An agent's `ks.*` envelope is always denied (`out_of_scope`). A system principal executes only its own tools (table below).
- **Expiry and admission (D2, F3).** Order: sig, expiry, nonce. An admitted (exec/hold) envelope satisfies `tick ≤ expiry_tick ≤ tick + 8`; only an unhold re-execution (`reexec_of` set, M10) is exempt. A reused `(agent_id, action_id)` is `deny/nonce_reused`. `sig_ok` ⇒ `envelope.sig` present (N1).
- **Anti-replay vs dedupe.**
  - `nonce` is for anti-replay only.
  - Dedupe uses the `OutboxItem.idempotency_key` from `idempotency_key(agent, action, sink, n)`. The gateway derives it and agents never choose it. A re-run of the same action derives the same key, so the effect is never sent twice.
- **Envelope time and claimed fields.** `expiry_tick` and `epoch` are integers counted in ticks. Unknown envelope keys ⇒ `deny/schema`. Agent-claimed time or seq goes in `claimed_ts_us`/`claimed_seq` and is never used for ordering.
- **Lineage is never agent-declared.** `act_chain` is used only to deny revoked ancestors. Taint and lineage hold use the recorded `read_set` (`OutboxItem.lineage`).
- **Write-write conflict rule.** `RestoreStep.expect` is the culprit's after-version and must still be the head, or the step fails closed (`hold/stale_plan`). No restore over a tainted head (B6). A *taint-scoped revert* is the set of `restore` steps in a plan.
- **Field objects (B1, X1, X2).** Each `sensitive_fields` entry is its own object `table:pk.field`; a pk never contains `.` (validator on every `ObjId`; `OBJ_ID_RE` unchanged). `RunConfig.check_obj` requires a `.suffix` to name a sensitive field of that table. A whole-row read lists the row and its field objects (`RunConfig.field_objs_of`); a projection without the field lists only the row; field-only edits do not bump the row. Aggregates enumerate rows.
- **View (I1).** `TickFrame.view` (≤ 64 `ViewEntry`, value hash checked) joins the read_set of that tick's submission. `TickFrame.epoch` is `None` while suspended/revoked.
- **Approval binding (G6).** `ks.approve` args = `plan.approval()` (`plan_hash` = `content_hash()`); each `ks.recover.<op>` carries `plan.recover_args(n)`.
- **Ground truth (A3).** `fault`, `culprit`, `fault_tick` are scorer-only; the TCB gets `RunConfig.tcb_view()`.

## Reserved `ks.*` tools (K13)
Each is a recorded envelope on `c-0`. Every outbox status change carries a `write_set`, so `state = fold(record)` holds.

| Tool | May execute | Args | Notes |
|---|---|---|---|
| `ks.control` | `ks.monitor`, `ks.gateway` (auto); `ks.operator`, `ks.recovery` (manual) | `Control.to_obj()` | Control in clear on the record; `issued_by == agent_id` |
| `ks.dispatch` | `ks.gateway` | dispatch | read_set = lineage ∪ `outbox:<id>@ver`; write_set = status change (G4, F4) |
| `ks.alert` | `ks.monitor` | `Alert.to_obj()` | binds every alert into the chain; FROZEN and TTI come from these (F6) |
| `ks.approve` | `ks.operator` | `Approval` | binds a plan by hash and step list (G6, F5) |
| `ks.recover.<op>` | `ks.recovery` | `RecoverArgs` | `<op>` ∈ `StepOp`; `hold/stale_plan` if `expect` moved; `deny/recovery_frozen` while frozen |

## Run dir, determinism and verify (C6)
- **Modes (F1, X8).** Run dir 0711; files 0600 (`record.jsonl` 0640, group = witness gid); subdirectories 0700 (`sidestore/`, `plans/`, `oracle/`, `baselines/`, `workspace/`, `witness-heads/` owned by the witness uid). Set explicitly, independent of the umask. Agents (uid 60001+) get EACCES on every file. `RunDir.perm_problems()` checks it; `RunDir.write()` writes other files (effects, score, oracle) the same way.
- **Determinism (C4, C5).** `DETERMINISTIC_FILES` = config, record\*, witness\*, alerts, effects.jsonl, oracle/\*\*, score.json, plans/\*\*, sidestore/\*\*. `keys.json` is **not** deterministic: private keys are never a function of the seed. \* = compared through `determinism_view()` (records without `hash`, `prev_hash`, `gw_sig`, `envelope.sig`; checkpoints without `head`, `sig`). `RunDir.determinism_files()` gives the bytes to compare; `ks repro` exits `Exit.DIVERGED` when they differ.
- **Anchor (F1, K1).** `RunAnchor{seq, head, tick, count, keyring_hash, config_hash}`, one canonical line. `ks verify --head` checks the hashes first (`keyring_mismatch`/`config_mismatch` → WITNESS; RT8(h)), then the last checkpoint (`truncated`/`head_mismatch`). `VerifyReport.anchored` is true only with a matching anchor in fresh key mode; **the C1 claim holds only when anchored**. `key_mode="repro"` is never anchored (`unanchored_reason="repro_keys"`) and is refused with `fault="rogue"`.
- **Verify reasons (K16).** Closed vocabulary `VERIFY_REASONS`, each tied to its exit: a bad record line is TAMPER `parse_error` (not IO); a re-hashed side entry is TAMPER `side_entry_mismatch`; witness problems are WITNESS; IO only for missing/unreadable config, keys or record.
- **Keyring (E3, K5).** Exactly one key each for the five system principals (validator) and every agent, nothing else (`Keyring.problems(config)`; `RunDir.create` refuses an incomplete keyring).

## Key isolation (THREAT-MODEL v3, CALL-01)
- **Public claim, verbatim (THREAT-MODEL C2):** key isolation is **"enforced in production (uid/container), detected here by reconciliation"**. Nothing in code, console text or docs may say more than this.
- **Live setup (THREAT-MODEL v3, ADR-00).** The container runs as uid 0.
  - The gateway runs as uid 0 and the witness under its own uid (60000).
  - **Each agent runs under its own numeric uid**: 60001 + its index in `RunConfig.agents`. No passwd entry is needed.
  - The agent template sets `PR_SET_DUMPABLE=0` before any agent code runs. The gateway, witness and signer are non-dumpable as well.
  - Each agent gets path-less `socketpair`s (one to the gateway, one to the signer), a clean env, `close_fds` and per-uid rlimits. The signer (`SignRequest` → `SignReply`) signs only envelope headers for its own principal.
- **Key mode (C3, E4).** `fresh` (every security run): keys are generated **in memory**, per run; the witness generates its own key and the gateway never holds it. `repro`: keys derive from a secret outside the run dir (0600, uid 0) so a replay is byte-identical; the run is labelled "not a security run", is never anchored, and is banned for D11/RT2/RT8 and with `--rogue`.
- Keys are generated **in memory** on the gateway/signer side and are never written to disk. `keys.json` holds public keys only, and `RunDir.validate()` flags any private-key material. `workspace/` is 0700 and `state.db` is 0600, both owned by the gateway uid.
- **When the uids separate**, the uid boundary blocks key theft (RT2), sibling hijack (RT3b) and a `state.db` bypass (RT1a) for that run. At startup the gateway checks that cross-uid `ptrace` returns EPERM, and the console prints the mode. The RTs measure this, but the public claim stays the C2 wording above.
- **When they do not separate**, isolation is **detected only**, and the console prints the degraded mode:
  - **Gateway uid shared with agents.** A key read from the rogue subprocess is the admitted gap. It voids C1/C4 for that run, and reconciliation does not see it (RT2).
  - **Per-agent uids fail (shared agent uid).** **Per-agent attribution is void for that run**, because a sibling can act through an honest agent's socket and signer handle (RT3b).
  - Reconciliation (`AlertKind.RECONCILE`, detector `reconcile`, class U) catches unmediated writes to `state.db`, both in these modes and in relaxed-permission runs (RT1b). It detects writes, not key reads.

## Left to ADR owners (not in the contract)
Metric and score keys and the `effects.jsonl` schema (tara, ADR-06); policy rule ids (nisha, ADR-03); the store implementation (vikram, ADR-05); side-store and verify internals (arjun, ADR-02).

## Changelog

### 1.1.0 (CON-02, 19 Nov; CALL-02 design freeze)
Implements the CON-02 checklist in `org/meetings/CALL-02/resolutions.md`, amendments X1, X2, X7 and X8-F1 from
`org/meetings/CALL-02.md`, Kabir's sign-off items (SEC-03 B1–B4, R1, R4, F1) and PMO S5. Tests:
`tests/contracts/test_con02_checklist.py`, `tests/contracts/test_signoff_kabir.py`.

- **C1:** `MAX_EXPIRY_TICKS = 8`, `expiry_ok()`; canonical `MAX_DEPTH = 32`; every decode failure is a `CanonicalError` (`ContractError` new). Integers longer than 17 chars are rejected before `int()`.
- **Transport:** `TickFrame.epoch`, `TickFrame.view` / `ViewEntry`, `MAX_VIEW_ENTRIES = 64`, `MAX_SIGN_PER_TICK = 2`, `signer_refusal()`.
- **C2:** `WitnessCheckpoint.count` (signed; from 1, +1 per line) and `witness_id == "ks.witness"`; `Record.reexec_of` (M10 unhold re-execution); reasons `late_frame`, `stale_plan` (`over_quota` existed); validators K4 (system ⇔ c-0, ks.* tools, `issued_by`, `ks.recover.*` by recovery), F3 (admitted expiry window), N1; `determinism_view()`, `witness_chain_problems()`.
- **C3:** field objects `table:pk.field`; `field_obj_id`, `row_obj_id`; `split_obj_id` now returns `(table, pk, field | None)` (**breaking** for callers of the 2-tuple); `.` banned in pks on every `ObjId`; X2 read rules, M11 and "aggregates enumerate rows" documented.
- **C4:** tamper/witness_stall never hard (dropped from `HARD_ALLOWED`); H3 hard table (`HARD_DETECTORS`, `DETECTOR_KIND`); reconcile names nobody; empty evidence allowed for `barrier.deadline` and `reconcile`; `barrier.deadline` may carry `conn_id`, never an agent (PMO S5); `EpochFold` (D1); M9, M10, K15 docs.
- **C5:** `t0_seq` → `t0_seq_est` (**renamed**); M14; `Approval`, `RecoverArgs`, `recover_tool()`, `APPROVE_TOOL`; M13 dropped.
- **C6:** `RunConfig.fault_tick` (iff fault, in [T/4, T/2]), `key_mode`, `decision_latency_ticks`, `tcb_view()`; `fault` also accepts `F2+x`, `F2+c`, `rogue`; `RunAnchor`, `anchor_status()`; `VerifyReport.anchored` + `unanchored_reason`, closed `VERIFY_REASONS`; `Keyring` requires all system principals and has `problems(config)`; `Exit.DIVERGED = 6`; `WITNESS_HEADS_DIR`, `BASELINES_DIR`; F1 file modes; new `DETERMINISTIC_FILES` (+`PROJECTED_FILES`), `RunDir.determinism_files()`, `perm_problems()`, `write()`.
- **ids:** `ks.console` → `ks.operator`, no alias (`PRINCIPAL_RE` now accepts only the five system principals); `SYSTEM_CONN = "c-0"`, `SYSTEM_TOOLS`, `RECOVER_TOOL_PREFIX`, `system_tool_signers()`.
- **Schemas:** regenerated; new `c5.approval`, `c5.recover_args`, `c6.run_anchor`.

**Golden hashes (`tests/contracts/golden.json`), re-pinned on purpose.** The canonical format and domain tags did
not change: the format vectors (`value_hash({})`, `tombstone`, `tagged`) are unchanged, and so are the document
hashes of samples whose type did not change: envelope, envelope_header, outbox_item, side_\*, alert_signature,
control_suspend, control_suspend_conn, control_hold. Changed, each for a stated reason:
`record_exec`, `record_forged`, `record_garbage`, `record_control` (new field `reexec_of`); `witness` (new field
`count`); `run_config` (new fields `fault_tick`, `key_mode`, `decision_latency_ticks`); `keyring` (`ks.operator`
replaces `ks.console`, and every agent now has a key, as K5 requires); `control_revoke` (issued by `ks.operator`);
`alert_invariant` (detector renamed to the H3 spelling `inv.beneficiary_changed_then_paid`); `plan` (field renamed
`t0_seq_est`). New: `alert_barrier`.

**Not in contracts (owners):** `decisions_from` in config and the X6 replay checks (R3), the verify window check (F4,
arjun), TTI from chained alerts (F6, tara/arjun), adapter-level read tests (vikram), gateway enforcement of all
of the above.

### 1.0.0 (CON-01)
Initial C1–C6.
