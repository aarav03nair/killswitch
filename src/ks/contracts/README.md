# ks.contracts: C1–C6 reference (CON-01, contracts 1.0.0)

Import from `ks.contracts`, never from submodules. Every type is a frozen pydantic model that rejects unknown
fields. Each one has `to_canonical()` / `from_canonical()` (strict: the bytes must already be canonical) and
`to_obj()`. Documents also have `signing_bytes()` and `content_hash()`. Field docs, including the OTel
`gen_ai.*` / `ks.*` mapping, are in the code and in `schema/*.schema.json`. Regenerate the schemas with
`python -m ks.contracts.schema_gen`. A test fails if they drift, and any field change bumps `CONTRACTS_VERSION`.

| Contract | Types | Run dir file |
|---|---|---|
| C1 Envelope | `Envelope` (on the socket, raw `args`), `EnvelopeHeader` (signed + recorded, `args_hash`), `ActLink` | in `record.jsonl` |
| C2 Record | `Record`, `WitnessCheckpoint`, `Decision` exec/deny/hold, `Reason`, `ActionClass` R/C/I1/I2/U | `record.jsonl`, `witness.jsonl` |
| C3 State | `StateView`/`StateWriter`/`SideStore` protocols; `ObjVer`, `VersionRef`, `ReadEntry`, `WriteEntry`, `StateRead`, `HistoryEntry`, `OutboxItem`, `SideEntry`; `idempotency_key()` | `sidestore/xx/<hash>.json` |
| C4 | `Alert` (`root_candidates` ranked; no `suspect`), `Control` (target `agent:`/`conn:`/`action:`/`outbox:`) | `alerts.jsonl`; Controls inside records |
| C5 | `RecoveryPlan`, `TaintSet`, steps `restore`/`rerun`/`replan`/`cancel_outbox`/`compensate`/`flag`, `DiffEntry` | `plans/<plan_id>.json` |
| C6 | `RunConfig` (seed, `hold_window_ticks`, `sensitive_fields`, agents), `Keyring` (public keys), `RunDir`, `Exit`, `VerifyReport` | `config.json`, `keys.json` |
| Transport | `TickFrame`, `SubmitFrame`, `NoopFrame`, `ReplyFrame`, `SignRequest`, `SignReply` | JSON lines over Unix sockets |

## One serializer
`ks.contracts.canonical` (`dumps`, `loads`, `dumps_line`, `loads_line`) is the only encoder that signer,
gateway, recorder and verify may use. Its rules:
- sorted keys (UTF-16 order), UTF-8, no whitespace
- integers only, within ±(2^53−1)
- **no floats** (use minor units or ticks)
- **no bytes** (hex-encode them)

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
- Plain hashes of low-entropy values (IBANs) can be reversed with a dictionary. Records are **pseudonymised, not anonymised**; keyed commitments are deferred (open for SEC-03).
- No wall-clock time anywhere in records. `ts_us` is logical time derived from the tick. Wall clock goes only in `timing.jsonl`, the one file that is allowed to differ between runs.

## Rules the types enforce (kabir §4; the rest live in the gateway)
- **Unknown action class is rejected.** `class U` ⇒ `deny` (rule 6).
- **Every decision has a reason code.** `reason` must fit the `decision` (`REASONS_FOR`), and `exec` ⇒ `ok`.
- **Denials have no effects.** `deny` carries no read set, write set, outbox items or result. `hold` carries no writes or result (rule 11: denials are still recorded).
- **Attribution (Q9).** The record embeds the claimed `agent_id` and `act_chain` plus `sig_ok`. Read attribution **only** through `rec.attributed_agent`, which is `None` for `bad_sig`/`schema`. A forged envelope is never counted against the agent it claims to be.
- **Anti-framing (D7).**
  - A `signature` alert names only `conn_id`.
  - `tamper` and `witness_stall` alerts name nobody.
  - `anomaly` and `rate` alerts are never hard.
  - `revoke` is never `auto` and is issued only by `ks.console`.
  - Suspending an agent requires a new `epoch`.
- **Signed, recorded controls (rule 10).** Controls are envelopes with `tool="ks.control"` and `args = control.to_obj()`. The record carries the Control in clear, bound to it by `args_hash`.
- **Anti-replay vs dedupe.**
  - `nonce` is for anti-replay only.
  - Dedupe uses the `OutboxItem.idempotency_key` from `idempotency_key(agent, action, sink, n)`. The gateway derives it and agents never choose it. A re-run of the same action derives the same key, so the effect is never sent twice.
- **Envelope time and claimed fields.** `expiry_tick` and `epoch` are integers counted in ticks. Unknown envelope keys ⇒ `deny/schema`. Agent-claimed time or seq goes in `claimed_ts_us`/`claimed_seq` and is never used for ordering.
- **Lineage is never agent-declared.** `act_chain` is used only to deny revoked ancestors. Taint and lineage hold use the recorded `read_set` (`OutboxItem.lineage`).
- **Write-write conflict rule.** `RestoreStep.expect` must still be the current version, or the step fails closed. A *taint-scoped revert* is the set of `restore` steps in a plan.

## Key isolation (THREAT-MODEL v2)
- The container runs as uid 0, and a `nobody` user exists. So `ks.runtime` runs each agent subprocess **under a separate unprivileged uid**.
- Each agent holds only its gateway socket and a signer handle (`SignRequest` → `SignReply`). The signer signs only envelope headers for its own principal.
- Keys are generated **in memory** by the gateway/signer side and never written to disk. `keys.json` holds public keys only, and `RunDir.validate()` flags any private-key material.
- `workspace/state.db` is 0700 and owned by the gateway. So key isolation and gateway bypass are **enforced** here, not only detected. Reconciliation (`AlertKind.RECONCILE`, detector `reconcile`, class U) still catches any bypass in relaxed-permission runs (RT1b).

## Left to ADR owners (not in the contract)
Metric and score keys and the `effects.jsonl` schema (tara, ADR-06); policy rule ids (nisha, ADR-03); the store implementation (vikram, ADR-05); side-store and verify internals (arjun, ADR-02).
