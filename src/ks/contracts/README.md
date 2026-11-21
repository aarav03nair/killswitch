# ks.contracts: C1–C6 reference (CON-01 → CON-02 → B3-01 → B3-43 → B3-46 → B3-47 → B3-51 → S4-13, contracts **1.7.0**, frozen 22 Nov)

Import from `ks.contracts`, never from submodules. Every type is a frozen pydantic model that rejects unknown
fields. Each one has `to_canonical()` / `from_canonical()` (strict: the bytes must already be canonical) and
`to_obj()`. Documents also have `signing_bytes()` and `content_hash()`. Field docs, including the OTel
`gen_ai.*` / `ks.*` mapping, are in the code and in `schema/*.schema.json`. Regenerate the schemas with
`python -m ks.contracts.schema_gen`. A test fails if they drift, and any field change bumps `CONTRACTS_VERSION`.

| Contract | Types | Run dir file |
|---|---|---|
| C1 Envelope | `Envelope` (on the socket, raw `args`), `EnvelopeHeader` (signed + recorded, `args_hash`), `ActLink`; `MAX_EXPIRY_TICKS`, `expiry_ok()` | in `record.jsonl` |
| C2 Record | `Record` (+`reexec_of`), `WitnessCheckpoint` (+`count`), `Decision` exec/deny/hold, `Reason`, `ActionClass` R/C/I1/I2/U; `determinism_view()`, `witness_chain_problems()` | `record.jsonl`, `witness.jsonl` |
| C3 State | `StateView`/`StateWriter`/`SideStore` protocols; `ObjVer`, `VersionRef`, `ReadEntry` (+`source` view|tool), `ViewEntry`, `WriteEntry`, `StateRead`, `HistoryEntry`, `OutboxItem`, `SideEntry`; `make_obj_id`/`field_obj_id`/`row_obj_id`/`split_obj_id`; `idempotency_key()`; `check_read_set()`, `merge_read_set()` | `sidestore/xx/<hash>.json` |
| C4 | `Alert` (`root_candidates` ranked; no `suspect`; H3 hard table), `Control` (target `agent:`/`conn:`/`action:`/`outbox:`), `EpochFold` | `alerts.jsonl` (copy); Alerts and Controls inside records |
| C5 | `RecoveryPlan` (`t0_seq_est`, `t0_seq_est_literal`), `TaintSet`, steps `restore`/`rerun`/`replan`/`cancel_outbox`/`compensate`/`flag`/`resolve`/`unresolve` (+`RevertEntry`), `DiffEntry`; `Approval`, `RecoverArgs` | `plans/<plan_id>.json` |
| C6 | `RunConfig` (seed, `fault_tick`, `key_mode`, `decision_latency_ticks`, `hold_window_ticks`, `sensitive_fields`, agents, `isolation`, `decisions_from`, `lineage_hold`, `resolver`; `tcb_view()`, `resolver_label`), `Keyring`, `RunAnchor`, `RunDir`, `Exit`, `VerifyReport` (+`anchored`, `isolation`, `lineage_hold`) | `config.json`, `keys.json` |
| Transport | `TickFrame` (+`epoch`, `view`), `SubmitFrame`, `NoopFrame`, `ReplyFrame`, `SignRequest`, `SignReply`, `SignRefusal`; witness link `WitnessInit/Pub/Files/Ready/Head/Close` (`decode_witness_frame`); `MAX_VIEW_ENTRIES`, `MAX_SIGN_PER_TICK`, `SIGN_REFUSAL_REASONS`, `signer_refusal()` | JSON lines over Unix sockets |

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
- **A tool that raises is still recorded (rule 11, v1.3).** Admitted envelope, tool/dispatcher exception: roll back the state txn, record `deny/tool_error` with `sig_ok=true`, no read/write set, no outbox ids, no `result_hash`. The exception text is not recorded.
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
- **Read sources (1.4, B3-46).** Each read-set entry is tagged `source`: `view` (delivered) or `tool` (adapter read); the gateway sets it via `merge_read_set(view, tool)`. A read set is sorted by `(obj, ver)`, unique per `(obj, ver)` and per `(obj, source)`: one object appears twice only when the view and the tool saw different versions (both kept). Same rule for `OutboxItem.lineage`.
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
| `ks.seed` | `ks.gateway` | `{"seed": <scenario>}` | v1.3, D-15 (amends G1). Record seq 1 only: tick 0, `c-0`, read_set and outbox empty, write_set == `seed_state` at seq 1 (`Record.seed_problems()`; verify → `seed_invalid`). A denied `ks.seed` (agent) is an ordinary denial |
| `ks.recover.<op>` | `ks.recovery` | `RecoverArgs` | `<op>` ∈ `StepOp`; `hold/stale_plan` if `expect` moved; `deny/recovery_frozen` while frozen |

## Run dir, determinism and verify (C6)
- **Modes (F1, X8).** Run dir 0711; files 0600 (`record.jsonl` included: gateway-only; the witness is pushed (seq, head, tick) and never reads it); subdirectories 0700 (`sidestore/`, `plans/`, `oracle/`, `baselines/`, `workspace/`, `witness-heads/` owned by the witness uid). Set explicitly, independent of the umask. Agents (uid 60001+) get EACCES on every file. `RunDir.perm_problems()` checks it; `RunDir.write()` writes other files (effects, score, oracle) the same way.
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

### 1.7.0 (S4-13, 21 Nov; D-18, ADR-05a, CALL-02 amendment B5-a approved by Aarav 21 Nov) — additive only
Nothing renamed or removed; no field changed. Tests: `tests/contracts/test_contracts_17.py`,
`tests/recovery/test_resolver.py`.

- **C5:** `StepOp.RESOLVE` / `StepOp.UNRESOLVE`; `ResolveStep` (`rule`, `rule_version`, `obj`, `culprit_ver`, `expect`,
  `to`, `rebased`, `rebased_hash`, `unblocked`, `rationale`), `UnresolveStep` (`resolution`, `resolution_plan_hash`,
  `reverts: RevertEntry[]`, `reheld`, `rationale`), `RevertEntry` (`obj`, `expect`, `to`). Both run as
  `ks.recover.resolve` / `ks.recover.unresolve` signed by `ks.recovery` on c-0 (the existing `system_tool_signers`
  rule). Plans without them parse and hash as before. Step order: cancel_outbox, restore, resolve, rerun, compensate,
  replan, flag. `needs_approval` unchanged (a resolve is approved with the plan, like a restore).
- **C6:** `RunConfig.resolver: "off" | "ww_rebase/1" = "off"` (additive: omitted at `off`, so 1.1–1.6 configs keep their
  bytes and hashes). Set by `ks run --resolver ww_rebase/1`; covered by `config_hash`; not scorer-only. `resolver_label()`
  gives the one label text (`resolver: off` / `resolver: ww_rebase/1 (on)`).
- **C6:** verify reason `resolution_invalid` → TAMPER: an executed resolve/unresolve the rule does not support (unknown
  rule, a failing check, fields the record does not imply, a landed write that is not `rebased_hash` over `expect`, a
  replay, a resolve after an undo of the same (obj, action), out of order, a bad or second undo). Logic:
  `ks.verify.recovery.resolution_pass`. A replayed resolve/unresolve step is reported here, not as `recovery_unbound`.
- **Schemas:** regenerated (version string; new step types; `resolver` in run_config, not required).
- **Fixture:** `tests/contracts/fixtures/run-1.6-world-s0` (1.6.0 world run); 1.3–1.6 runs verify under 1.7.

**Golden hashes.** Only `doc:run_config` moved (`contracts_version` = 1.7.0).

### 1.6.0 (B3-51, 20 Nov; kabir's B3-51 ruling, ADR-04 §7 amended) — additive only
Nothing renamed or removed; no field changed. Tests: `tests/contracts/test_contracts_16.py`,
`tests/redteam/test_rt10_irreversible.py`.

- **C6:** `RunConfig.lineage_hold: bool = True` (additive: omitted from the canonical bytes at `True`). `False` marks
  the D10 **NO-LINEAGE-HOLD contrast run** (`ks run --hold 0 --no-lineage-hold`, the only setter): the alert-driven
  lineage hold (ADR-04 §5) is switched off, which H alone never does. It is in config.json, so `config_hash` and the
  RunAnchor cover it. Validator: `False` needs `hold_window_ticks == 0`. Not scorer-only (the gateway reads it).
- **C6:** `VerifyReport.lineage_hold: bool = True` (additive): echo of the config. On `False`, `ks verify` skips
  **only** the taint flag in the F4 dispatch-window pass (unrecorded items, double dispatch, release tick, recorded
  holds and author suspensions are still `window_violation`), and verify, console and `ks score` print
  `NO_LINEAGE_HOLD_BANNER`. The same records under `lineage_hold = True` still fail F4; relabelling an anchored run
  gives `config_mismatch`.
- **Schemas:** regenerated (version string; `lineage_hold` in run_config and verify_report, not required).
- **Fixture:** `tests/contracts/fixtures/run-1.5-world-s0` (1.5.0 world run); 1.3, 1.4 and 1.5 runs verify under 1.6.

**Golden hashes.** Only `doc:run_config` moved (`contracts_version` = 1.6.0).

### 1.5.0 (B3-47, 20 Nov; kabir's B3-20 ruling) — additive only
Nothing renamed or removed; no field changed. Tests: `tests/contracts/test_contracts_15.py`.

- **C6:** verify reason `replay_mismatch` → DIVERGED, exit 6 (`VERIFY_REASONS["replay_mismatch"]`): re-deriving the recorded
  decisions (the `ks.verify.decisions` replay, or the `RunConfig.decisions_from` source run) gives a different
  result. The hash chain may be intact, so `hash_mismatch` was misleading; `hash_mismatch` keeps its meaning (a
  record that fails the chain/content checks in `ks verify`). Not TAMPER: an honest but divergent replay must not
  read as tampering; `Exit.DIVERGED` now means "a re-derived result differs from its source" (`ks repro` or replay).
- **C6 (B3-30, G6/F5):** verify reason `recovery_unbound` → TAMPER: an admitted `ks.recover.<op>` record with no
  prior matching `ks.approve` (`plan_id`, `plan_hash`, `n` listed), whose `plans/<plan_id>.json` no longer hashes to
  the approved `plan_hash` (edited plan file), or a step applied twice. Logic: `ks.verify.recovery`.
- **Additivity:** 1.3 and 1.4 runs still verify (`test_additive_13_run.py`; `test_contracts_15.py` with
  `fixtures/run-1.4-world-s0`, a checked-in 1.4 world run with `source: "view"` read entries).
- **Schemas:** regenerated (version string only; `VerifyReport.reason` is a pattern, not an enum).

**Golden hashes.** Only `doc:run_config` moved (`contracts_version` = 1.5.0).

### 1.4.0 (B3-46, 19 Nov; B3-45 option C) — additive only
Nothing renamed or removed. Tests: `tests/contracts/test_contracts_14.py`, `tests/gateway/test_b346.py`.

- **C3:** `ReadEntry.source: "view" | "tool" = "tool"` (`ReadSource`, `READ_SOURCES`). `ViewEntry.read_entry()`
  tags `view`. `check_read_set()` is the rule for `Record.read_set` and `OutboxItem.lineage`: sorted by `(obj, ver)`,
  unique `(obj, ver)` and `(obj, source)`. So the same object at two versions (view vs tool) keeps both (Panel,
  B3-41 review). `merge_read_set(view, tool)` builds it and re-tags by position; the same version in both = one
  `tool` entry. A 1.3 read set (one entry per obj) sorts the same.
- **C5:** `RestoreStep.to: VersionRef | None`; `None` = the culprit created the object, restore to absent (tombstone);
  `RestoreStep.to_absent`. `RecoveryPlan.t0_seq_est_literal: Seq | None = None` (literal-walk t0, `<= t0_seq_est`),
  `RecoveryPlan.t0_delta`. Replace the planner's tombstone marker and `Planned.t0_delta`.
- **ks.taint:** the t0 walk follows the suspect's self-reads only through `tool` entries (ADR-05 §4, CALL-02 A8-a).
- **Schemas:** regenerated (version string; optional `source` on read entries, nullable `to`, optional
  `t0_seq_est_literal`).

- **Additivity rule (canonical form, `_base.additive`).** A field added in a minor version is declared with
  `additive(default)` and is **omitted from the canonical form when it equals its default** (nested values too):
  `source == "tool"` and `t0_seq_est_literal is None` are not written, so every 1.3 document keeps its bytes, hashes
  and signatures, and 1.3 runs still verify (`tests/contracts/test_additive_13_run.py`, a checked-in 1.3 world run).
  Non-default values (`source: "view"`, an integer literal t0) are written and round-trip. Strict parse is unchanged:
  an explicit default in the bytes is not canonical (`NonCanonicalError`). Schemas list these fields as optional.

**Golden hashes.** Only `doc:run_config` moved (`contracts_version` = 1.4.0). All other documents are byte-identical
to 1.3.

### 1.3.0 (B3-43, 19 Nov; D-15) — additive only
Nothing renamed or removed. Tests: `tests/contracts/test_contracts_13.py`.

- **ids:** `SEED_TOOL = "ks.seed"` in `SYSTEM_TOOLS`, executed by `ks.gateway` only. Aarav's D-15 (19 Nov) amends
  CALL-02 G1; the seed record (D-SEQ1) stops borrowing `ks.dispatch`, which G4 reserves for outbox dispatch.
- **C2:** `Record.seed_problems()`: an admitted `ks.seed` must be exec at seq 1, tick 0, verified `ks.gateway` on
  `c-0`, empty read_set and outbox, no `reexec_of`. Deny reason `tool_error` (B3-11 finding 3): an admitted
  envelope whose tool raised, recorded with no effects (rule 11).
- **C6:** verify reason `seed_invalid` → TAMPER: `seed_problems()` non-empty, or write_set differs from
  `ks.world.scenario.seed_state` on an empty store at seq 1 (`ks.verify.core.expected_seed_writes`).
- **Schemas:** regenerated (version string; `c2.record` reason enum gains `tool_error`).

**Golden hashes.** Only `doc:run_config` re-pinned (`contracts_version` = 1.3.0 in the sample).

### 1.2.0 (B3-01, 19 Nov; CALL-03/maya-plan §2) — additive only
Closes SKEL-01 findings 2–4 and the contract parts of R3 and F9. Nothing renamed or removed: every 1.1 type,
field, reason and export is unchanged. Tests: `tests/contracts/test_contracts_12.py`.

- **Transport, witness link (finding 2):** `WitnessInit{key_seed}` (null = fresh, the witness makes its own key;
  repro = derived seed), `WitnessPub{pub}`, `WitnessFiles` (+ `WITNESS_FILES_FDS = 2` by SCM_RIGHTS),
  `WitnessReady`, `WitnessHead{seq, head, tick}` (head ≠ genesis), `WitnessClose`; the ack stays the signed
  `WitnessCheckpoint` line. A separate union decoded by `decode_witness_frame`, so witness and agent frames never
  cross. `ks.witness` uses them; `witness/protocol.py` keeps only `HEADS_FILE`.
- **Transport, `SignRefusal{reason}` (finding 3):** the signer answers every refusal; closed vocabulary
  `SIGN_REFUSAL_REASONS` = the `signer_refusal()` reasons + `schema`. Not a record. The agent template no-ops on it.
- **C6 `RunConfig.isolation` ∈ {`per_agent_uid`, `degraded`} (finding 4):** default `degraded` (a config that does
  not say claims nothing); fixed before spawn, covered by `config_hash`. `VerifyReport.isolation` echoes it
  (`None` only if config.json is unreadable); verify logs "per-agent attribution VOID" when degraded. The /proc
  readback abort is runtime code (B3-10).
- **C6 `RunConfig.decisions_from: Hash | None` (R3):** default `None`; the anchored source run for `--decisions`.
  Refused with `fault == "rogue"` and with `key_mode == "repro"` (validator). X6 replay checks stay gateway code (B3-20).
- **C6 verify reason `reexec_invalid` → TAMPER (F9).** Verify logic is B3-25.
- **Schemas:** regenerated under `/schema/1.2.0/`; `c6.run_config` and `c6.verify_report` gain the new properties.
  Frames have no schema files (unchanged policy: only `DOCUMENTS`).

**Golden hashes, re-pinned on purpose.** Only `doc:run_config` changed (new fields `isolation`,
`decisions_from`, and `contracts_version` = 1.2.0 in the sample). Format vectors and every other document hash
are unchanged. `test_contracts_version_bumped` (CON-02) now checks the current version rather than pinning 1.1.0.

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
