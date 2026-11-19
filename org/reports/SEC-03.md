# SEC-03: Security review of contracts C1–C6 (contracts 1.0.0) against the 11 day-one rules

Reviewer: kabir (Security) · 19 Nov · Reviews: CON-01 (maya) · Inputs: CALL-01/kabir.md §4, THREAT-MODEL v3, tests/redteam/SPEC.md §1.3, ADR-01…04, ADR-06
**Verdict on CON-01: changes.** There are 4 blockers. Each is small (a field, a constant, a docstring or about 10 lines of code), but all four change fields, constants, canonical rules or a stated semantic, so they have to land before the 22 Nov freeze. There are also 8 fix-before-S4 items and 10 notes. Everything else passes. The contracts are strong: every model is frozen and rejects unknown fields, the strict canonical parse rejected all 18 non-canonical byte inputs and all 8 malformed frames I tried (nesting aside, see B4), domain tags are distinct and prefix-free, and the record shape gives attribution with anti-framing built in.

**Severity:** **blocker** = must change before the freeze (field, constant, canonical rule, or a contract semantic an ADR already builds on unsafely). **fix-before-S4** = a validator, code, ADR or doc change that must land before the Sprint 4 red team because an RT depends on it. **note** = record it and fix it when convenient.

**Evidence:** `/tmp/sec03/probe.py` (64 probes, run with `PYTHONPATH=src`), `/tmp/sec03/depth.py` and `/tmp/sec03/perms.py`. All probes import `ks.contracts` only. The existing suite is green (231 passed).

---

## 1. Grid: 11 rules × C1–C6

C1 = Envelope + transport + canonical · C2 = Record + WitnessCheckpoint · C3 = State, Outbox, SideStore · C4 = Alert + Control · C5 = RecoveryPlan · C6 = RunConfig, Keyring, RunDir, Exit/VerifyReport. Gap ids refer to §2.

| Rule | C1 | C2 | C3 | C4 | C5 | C6 |
|---|---|---|---|---|---|---|
| **1** Subprocess per agent; gateway owns workspace, record, keys (0600) | pass: agent holds only gateway and signer frames; no paths in any frame | pass: `conn_id` is gateway-assigned and never agent-supplied | pass: `StateView`/`StateWriter` are gateway-only; `StateRead.value` stays inside the gateway | n.a.: no process or file boundary | n.a.: planner runs gateway-side | **gap F1**: `RunDir.create` makes the run dir 0755 and record/keys/config/side store 0644; only `workspace/` is 0700 |
| **2** Keys never enter the agent; signer handle | pass: `SignRequest{header}` → `SignReply{sig}`, header domain only (see N2) | n.a.: gateway and witness keys are gateway-side | n.a. | n.a.: Controls are signed by system principals | n.a.: the recovery key is gateway-held | **gap B2**: `DETERMINISTIC_FILES` includes `keys.json` and signed records, which forces seed-derived private keys |
| **3** Gateway assigns `seq`, `ts`, `record_id` | pass: `claimed_ts_us`/`claimed_seq` are evidence only; unknown keys are rejected (probe) | pass: `seq≥1`, `record_id == record_id_for(seq)` is enforced; `ts_us` is logical (N5) | pass: `HistoryEntry.seq`, `outbox_id` and `created_seq` come from the gateway | pass: alert `seq`/`tick` come from the monitor, not agents | n.a. | pass: `tick_us` and `start_ts_us` define `ts_us` |
| **4** Nonce, expiry, epoch, full act chain; one canonical serializer | **gap B3 + B4**: fields are present and strict, but `expiry_tick` is uncapped and there is no depth limit (RecursionError) | **gap F3**: an exec record with `envelope.expiry_tick < tick` validates; N1 | pass: `idempotency_key` is separate from `nonce` and gateway-derived | pass: Controls travel as signed envelopes (`ks.control`) | n.a.: steps run as envelopes (binding is under rule 10) | pass: every run-dir read goes through strict `from_canonical` |
| **5** Epoch and deny-list in the write txn; holds re-checked at dispatch | pass: `epoch` is inside the signed header | pass: total order lets verify prove "0 exec by A after suspend seq q" | **gap F4**: dispatch has no defined record, so the dispatcher re-check leaves no evidence | **gap B3**: `RELEASE` "restores (sets) the epoch"; ADR-04 §6 restores the *pre-suspend* epoch, which revives presigned envelopes | pass: `RestoreStep.expect` fails closed; `as_of_seq` forces stale plans to be recomputed | n.a. |
| **6** Fail closed: unknown → U → deny | **gap B4**: a 6 KB nested frame raises `RecursionError` (not a `ValueError`), which escapes the deny/schema path. Otherwise pass: `extra=forbid` everywhere, defaulted `contract` rejected | pass: closed `ActionClass`/`Reason`; U ⇒ deny; `envelope=None` ⇒ U + schema | pass: closed `OutboxStatus` and `OutboxClass` (I1/I2 only) | pass: closed `AlertKind`; `HARD_ALLOWED`; op × target table | pass: discriminated step union; unknown op rejected | pass: closed `Exit`; `validate` checks structure |
| **7** Adapters emit read/write sets; aggregates record coarse reads | n.a.: agents declare nothing | pass: `read_set (obj,ver,hash)`, `write_set` before/after ver+hash | **gap F7**: there is no coarse read (`OBJ_ID_RE` rejects `table:*`, probe) and no absence read (`ver≥1`) | pass: `evidence_versions` are `ObjVer` | pass: `TaintSet` comes from recorded sets | n.a. |
| **8** Only the gateway writes the record; alert on witness stall | n.a. | **gap B1**: `WitnessCheckpoint` has no signed `count`; the anchor does not cover `keys.json` | n.a. | **gap F6**: `alerts.jsonl` is unsigned and unchained, so deleting a tamper alert unfreezes recovery. Also N4 | n.a. (plans are bound by F5) | **gap F1**: `witness.jsonl` is created by the gateway with mode 0644, so the witness uid cannot append to it |
| **9** Log holds hashes; values in the side store | pass: the header carries `args_hash`; raw `args` exist only on the socket (N3) | pass: no raw values; `result_hash`; the Control in clear holds no PII. Low-entropy caveat in §5 | pass: `SideEntry` is redactable and hash-checked (N3: obj pk) | pass: alerts carry seqs and versions only | pass: `DiffEntry` is hash-only | **gap F1**: side store entries are 0644 in 0755 dirs, readable by every agent uid (F3 fails) |
| **10** Suspend, release, revoke, recover are signed, recorded actions | pass: `CONTROL_TOOL` envelope, signed header | **gap F2**: the record accepts an exec `ks.control`/`ks.recover.*` signed by agent `crm`, and `control.issued_by ≠ envelope.agent_id` (probes) | n.a. | pass: revoke is never auto and only `ks.console`; auto/manual issuers fixed; agent targets require an epoch | **gap F5**: plan approval is not a recorded action; recovery envelopes are not bound to `plan_hash` and step `n` | pass: `Keyring` holds system principals' keys (N7) |
| **11** Denials are recorded | **gap F8**: frame reads and oversize raw capture are unbounded, and floods have no budget (otherwise pass: garbage → `deny/schema` + `raw_hash`) | pass: deny/hold records carry a reason and no effects; `attributed_agent=None` on bad_sig/schema | pass: `SideDomain.RAW` holds unparseable bytes | pass: signature alert per conn | pass: `recovery_frozen` deny reason | n.a. |

Totals: 35 pass, 16 n.a., 15 gap cells. The gap cells cover 12 distinct gaps (B1–B4, F1–F8). B3 and F1 each appear in several cells.

---

## 2. Gaps and fixes

### Blockers (before the 22 Nov freeze)

**B1. The witness anchor is incomplete (rule 8; C2, C6).** THREAT-MODEL v3 and ADR-02 rely on a signed monotonic `count`, but `WitnessCheckpoint` has no such field (probe; ADR-02 also flags this). Separately, `keys.json` is an editable run-dir file (B4 boundary) and nothing binds it. An insider can replace the witness and gateway public keys with their own, re-sign the rewritten chain and checkpoints, and `ks verify` without `--head` returns OK. That defeats RT8 variant (e) as written in SPEC.
*Fix:* (a) add `count: NonNeg` (signed) to `WitnessCheckpoint`. (b) Add a `RunAnchor` value `{seq, head, tick, count, keyring_hash, config_hash}`. The console prints `keyring_hash` and `config_hash` at start and the full anchor at end, and `ks verify --head` parses it. (c) Add `VerifyReport.anchored: bool`; it is false when no anchor is given, and the C1 claim is stated only for anchored runs. Optional: make the genesis `prev_hash = tagged_hash(Domain.RUN, {config, keyring})` so a chain cannot be spliced across runs.

**B2. Determinism forces seed-derived private keys (rule 2; C6).** `DETERMINISTIC_FILES = (config, keys, record, witness, alerts)` and ADR-06 require byte-identical files for the same seed. Records embed `envelope.sig`, and `hash`/`gw_sig` chain over it, so byte-identical records need identical keys across runs. ADR-01 generates keys in memory. The only way to satisfy both is to derive private keys from the seed (the test samples already do `sha256("test-key:"+principal)`). The seed is public: seeds 0/1/2 are in CI, and the seed is in `config.json`. Anyone could then derive the gateway and witness keys, which voids RT2, RT3 and RT8.
*Fix:* drop `keys.json` from `DETERMINISTIC_FILES`. Add `determinism_view()` to contracts: `Record` minus `{hash, prev_hash, gw_sig, envelope.sig}`, `WitnessCheckpoint` minus `{head, sig}`. The determinism tests (SKEL-01, ADR-00, ADR-06) compare that view. ADR-01 adds a test that two runs with the same seed produce different `keys.json`, and states "private keys are never a function of the seed".

**B3. Epoch semantics on release, and an uncapped expiry (rules 4, 5; C1, C4).** `ControlOp.RELEASE` is documented as "restores (sets) the epoch", and ADR-04 §6 says "restoring the pre-suspend epoch". A suspended rogue can presign envelopes at epoch e with `expiry_tick = 2^53−1` (accepted, probe). After release (for example, an operator clearing a false positive), all of them are valid again. RT4 ("pre-suspend epoch → stale_epoch") and RT5 (presigned flood) then fail. An uncapped expiry also means the nonce store can never be pruned safely (ADR-01: "pruned by the expiry window"), which leaves a choice between unbounded memory and replay after pruning.
*Fix:* make per-agent epochs strictly monotonic. The initial epoch is 0. Every agent `suspend`/`revoke`/`release` sets `epoch > every earlier epoch` for that target. Fix the docstring ("release sets a fresh epoch; never reuses an old one") and ADR-04 §6. `ks verify` checks monotonicity by folding Control records. Add the constant `MAX_EXPIRY_TICKS` (proposed 8) in `envelope.py`. The gateway denies `expiry_tick > tick + MAX_EXPIRY_TICKS` with `deny/expired`, and the nonce store keeps exactly that window.

**B4. The canonical parser crashes on deep nesting (rules 4, 6, 11; C1).** A 6 KB frame of about 1000 nested `{"a":` (far under `MAX_FRAME_BYTES`) makes `canonical.loads` and `decode_frame` raise `RecursionError`, which is not a `ValueError` (`/tmp/sec03/depth.py`). `dumps` does the same at depth 1000. A 5000-digit integer raises a plain `ValueError`, not a `CanonicalError`. A gateway that maps `ValueError` to `deny/schema` (the natural reading of the transport docstring) lets these through. The result is an unrecorded denial (rule 11) and, at worst, a crashed tick barrier, which is a live D11 DoS against all agents. Any rogue can write raw bytes to its socket.
*Fix:* add the canonical rule `MAX_DEPTH = 32` (arrays plus objects). `loads` pre-scans the bytes for nesting depth before calling `json.loads`, `dumps` enforces it while recursing, and `loads`/`decode_frame` wrap every exception (`RecursionError`, `ValueError`, `ValidationError`) in `CanonicalError`. Contract text: "any exception from `decode_frame` is `deny/schema`". This is a canonical-rule change, hence a blocker; it costs about 10 lines plus 3 tests.

### Fix-before-S4

| # | Rule / contract | Gap | Concrete change |
|---|---|---|---|
| F1 | 1, 8, 9 / C6 | `RunDir.create`/`write_side` use the umask: run dir 0755; record, keys, config, alerts and side store 0644 (`/tmp/sec03/perms.py`). Agents run as uids 60001+ and can read IBANs from `sidestore/` (F3 fails) and the cross-agent history. The witness uid cannot append to the root-owned `witness.jsonl` | Run dir 0711, owner gateway. `record.jsonl` 0640 with group = witness gid. `sidestore/` dirs 0700, files created with `os.open(..., 0o600)`. `witness.jsonl` is created and owned by the witness uid. Unit test: a process at uid 60001 gets EACCES on every run-dir file |
| F2 | 10 / C2 | `Record` accepts an exec `ks.control` whose envelope is signed by `crm`, an exec `ks.control` from `ks.console` carrying `issued_by=ks.monitor`, and an exec `ks.recover.restore` from `crm` (3 probes) | Validator: `tool` starting with `ks.` and `decision == exec` ⇒ `envelope.agent_id ∈ SYSTEM_PRINCIPALS`. `ks.control` ⇒ `control.issued_by == envelope.agent_id`. `ks.recover.*` ⇒ `agent_id == "ks.recovery"`. Gateway: `ks.*` tools from agent principals give `deny/out_of_scope` |
| F3 | 4 / C2 | An exec or hold record with `envelope.expiry_tick < record.tick` validates (probe), so verify cannot spot an accepted expired envelope | Validator: `sig_ok and decision ∈ {exec, hold}` ⇒ `envelope.expiry_tick ≥ tick`. verify also folds epochs (B3) and checks `envelope.epoch == current` for exec |
| F4 | 5 / C3 | `OutboxItem.dispatched_seq` points to an unspecified record, and the ADR-03 §5 re-check (epoch, hold, lineage, sensitive fields) leaves no evidence | Define the dispatch record: principal `ks.gateway`, tool `ks.dispatch`, `read_set = lineage ∪ {outbox:<id>@ver}`, `write_set` = the status change. verify checks that no hold Control, taint seed or author suspend lies in `(created_seq, dispatched_seq)` without an unhold or release. RT5 and RT10 assert on it |
| F5 | 10 / C5 | Console approval of a plan is not a recorded action (`ControlOp` has no approve). Recovery envelopes are not bound to the approved `plan.content_hash()`, so an edited `plans/*.json` is undetectable | Add a `ks.approve` envelope by `ks.console` with `args {plan_id, plan_hash, steps:[n…]}`. Every `ks.recover.<op>` carries `args {plan_id, plan_hash, n, step}`. verify checks each recovery record against a prior approval and the plan file's hash. I2 approval = `unhold action:<record_id>` by `ks.console` (document it) |
| F6 | 8 / C4 | `alerts.jsonl` is unsigned and outside the chain. An insider can delete a tamper alert, which unfreezes recovery (Q8), or shift alert ticks, which changes TTI in `score.json` | The monitor submits every alert as a `ks.alert` envelope (`args = alert.to_obj()`), so the record binds it by `args_hash` (no new Record field). verify cross-checks `alerts.jsonl` ↔ records. FROZEN is derived from records, not from `alerts.jsonl` |
| F7 | 7 / C3 | There is no way to record an aggregate (coarse) read or a read that found nothing. An adapter that scans a table must either list every row or under-taint (RT10 risk). An absence read cannot be recorded at all | Decide at freeze (doc-only today): "aggregates enumerate every row read" (valid now), with an adapter test that asserts it. For absence reads, propose `ReadEntry(ver=0, hash=TOMBSTONE_HASH)` in 2.0. ADR-05 owns this |
| F8 | 11 / C1, transport | `MAX_FRAME_BYTES` is checked only after a full line is read, and the raw capture of an oversize frame is undefined. Every surplus frame becomes a record, so a flood is a record and witness DoS | Gateway reads at most `MAX_FRAME_BYTES+1`. Oversize gives `deny/schema` with `raw_hash` over the prefix and the connection closed. Per-connection budget: K recorded denials per tick, then auto `Control{suspend, conn:<id>, reason=flood}` from `ks.gateway`, then close. ADR-03 |

### Notes

- **N1:** a record with `sig_ok=True` and `envelope.sig=None` validates (probe). verify catches it through the signature check. Add the validator anyway.
- **N2:** `SignRequest` accepts a header whose `agent_id` differs from the bound principal, a `ks.*` tool, or a non-null `sig` (probes). The ADR-01 signer must refuse all three; add a unit test.
- **N3:** agent-chosen strings (`action_id` up to 64 chars, the 128-bit `nonce`, act-chain ids) and obj pks enter the chain and can never be redacted. An IBAN as `action_id` or pk is accepted (probe). ADR-06: pks are opaque surrogates. The F3 test greps `record.jsonl` for every side-store value.
- **N4:** ADR-02 says `witness_stall` is never hard, while ADR-04 and `HARD_ALLOWED` allow it. Pick one. I suggest a validator `kind ∈ {tamper, witness_stall} ⇒ hard=False`, with the recovery freeze automatic by kind.
- **N5:** `ts_us` is not checked against `tick`. verify should check it is monotonic and equals `start_ts_us + tick·tick_us + slot`.
- **N6:** `RunDir.validate` finds PEM keys only, not raw hex keys. The RT2 harness scan (with known key bytes) is the real control.
- **N7:** `Keyring` does not require `ks.gateway`, `ks.witness`, `ks.console`, `ks.recovery` and `ks.monitor`. verify must fail closed when one is missing; add a validator.
- **N8:** `config.json` carries `culprit` (scorer ground truth). Add an import or read guard test so that `ks.monitor` never reads it.
- **N9:** the models are not `strict=True` globally, so bools are lax. That is safe only because `from_canonical` and `decode_frame` re-encode and compare. The gateway must never call `model_validate` on wire data; add a grep test.
- **N10:** the OTel export (`ks.write_set` hashes) sends guess-confirmable hashes to the telemetry backend. Do not export the value hashes of `sensitive_fields` until keyed commitments exist (§5).

---

## 3. Explicit checks: rules 4, 5, 6, 11

**Rule 4: envelope fields and one serializer.** Present and strict:
- `nonce`: 128-bit lowercase hex. Uppercase is rejected (probe).
- `expiry_tick` and `epoch`: strict integers. `True` and `"1"` are rejected (probes).
- `act_chain`: full, root-first, at most 16 hops, `parent_action_id == act_chain[-1]`, no self-reference.

One serializer:
- `ks.contracts.canonical` is the only encoder, and `test_single_serializer` greps for others.
- `loads` is strict and re-encodes. It rejected all 18 non-canonical byte inputs in the probe: whitespace, key order, duplicate keys, `1.0`, `1e2`, `-0`, `01`, `NaN`, an escaped plain letter (backslash-u-0041), `\/`, uppercase `\u001F`, lone surrogate, overlong UTF-8, BOM, trailing LF, 2^53, a 5000-digit integer (wrong exception type, B4) and CRLF. `decode_frame` rejected all 8 malformed frames: three unknown keys (envelope, ActLink, frame), a missing defaulted `contract`, a bool epoch, a string epoch, an uppercase nonce, and an oversize frame.
- Output matches JCS: DEL and U+2028 stay literal, and non-BMP keys sort in UTF-16 order.

Cross-type signature reuse:
- The 17 domain tags are distinct and contain no `0x00`, so `tag‖0x00‖canonical` is prefix-free across types.
- Envelope and header signing bytes are identical by construction.
- A header object does not parse as a Control or a WitnessCheckpoint.
- The signer signs only the header domain.

Result: the serializer passes, and so does reuse. **Open:** B3 (expiry cap), B4 (depth and exceptions), F3 (expiry-vs-tick invariant).

**Rule 5: epoch and deny-list in the write txn; dispatcher re-check.** The epoch sits inside the signed header. `StateWriter` is documented as in-txn only, and ADR-03 step 8 re-reads epoch and deny-list in the SQLite txn. The global total order lets verify prove RT5 ("0 exec by A with seq > q"). **Open:** B3. Release reusing the pre-suspend epoch re-opens exactly the TOCTOU and presign window that rule 5 closes. F4: the dispatcher re-check exists in ADR-03 §5 but leaves no recorded evidence.

**Rule 6: fail closed.** Unknown keys are rejected at the envelope, ActLink and frame levels (probes). Every enum is closed. Class U ⇒ deny, and unparseable ⇒ U + `schema`, both by validator. The step union is discriminated. **Open:** B4. Deep nesting raises `RecursionError` instead of a deny, which is a fail-open path through an uncaught exception.

**Rule 11: denials recorded.** Every outcome is a record: deny and hold carry a reason that fits the decision and no effects, and garbage gets `envelope=None` with `raw_hash` and the raw bytes in the side store. `attributed_agent` is `None` for bad_sig and schema, so a forged denial is never counted against the claimed agent (probe). **Open:** B4 (a crash records nothing), F8 (oversize and flood policy), F6 (the tamper alert that drives the freeze is not in the chain).

---

## 4. SPEC §1.3 contract requests Q1–Q10

| Q | Status | Note |
|---|---|---|
| Q1 denial reason | done | `Reason` ⊇ the requested set, plus `out_of_scope`, `recovery_frozen` and the hold reasons; `REASONS_FOR` enforced |
| Q2 connection identity | done | `Record.conn_id`; Control `conn:<id>`; `Alert.conn_id` for signature alerts only |
| Q3 ticks | done | `expiry_tick` and `epoch` are integers (cap: B3) |
| Q4 unknown or claimed keys | done: reject | `deny/schema`; claims go in `claimed_*`. RT6 covers the reject branch |
| Q5 verify output | done | `Exit` adds FROZEN and USAGE. `VerifyReport` adds `exit`; add `anchored` (B1) |
| Q6 score keys | deferred, accepted | ADR-06 (tara) |
| Q7 ranked candidates | done | `root_candidates` is ordered; there is no `suspect` field |
| Q8 freeze under tamper | done, but depends on F6 | `Exit.FROZEN`; the freeze must come from chained alerts |
| Q9 attribution | done | embedded header + `sig_ok` + `attributed_agent` |
| Q10 outbox fields | done (renamed) | `author`, `status` (was `state`), `lineage[].hash` (was `read_hashes`), `dispatched_seq` (dispatch record: F4) |

SPEC follow-up (mine, SEC-02): use `attributed_agent` instead of `r.agent_id`, `root_candidates[0]` instead of `Alert.suspect`, `status` instead of `state`, `lineage` instead of `read_hashes`, and add RT8 variant (h), a `keys.json` swap that must fail when anchored.

---

## 5. Maya's open items

**Pseudonymised low-entropy hashes: accept as a note for S2–S4, with conditions.**
- *Risk:* `value_hash` of a supplier row (`{"name","iban"}`) is guess-confirmable with one hash per guess, and the name is known. IBANs for one bank and country have a small search space. Records are pseudonymised, not anonymised.
- *Who is exposed:* in this build, everyone who can read records (gateway, witness, operator, jury) can also read the side store, so a hash adds no exposure, provided F1 lands so that agents can read neither. Exposure is real in two places:
  - OTel export (N10).
  - Erasure. `redact()` keeps the hash, so a redacted IBAN stays confirmable. "Redactable" must be worded "value removed; hash remains guess-confirmable".
- *Conditions:* the wording "pseudonymised" goes in the README, THREAT-MODEL and the F3 criterion. F3 means "no cleartext reachable", not "no reversible hash". N10 holds.
- *Production:* keyed commitments, `HMAC-SHA256(k_commit, tag‖0x00‖canonical)` with a gateway-held per-run key. The chain, signatures and witness still verify publicly over the commitments. Only the side-store re-hash needs the key, and destroying the key gives real erasure. This changes hash semantics, so it is a 2.0 change. Don't reserve fields now.

**Global-only chain: accept, no per-agent chains.**
- One total order is what rule 5 and RT5 need ("seq > q" across agents), and one head is one witness anchor (B1). Per-agent chains would need cross-chain ordering, N heads and N anchors, which means more to tamper with and more to verify.
- Costs: there are no per-agent inclusion proofs (D6 refused Merkle anyway), and one stall stalls everyone (the witness_stall alert covers that).
- Per-agent views are derived by filtering on `attributed_agent`.
- Condition: since the chain is the full cross-agent history, only the gateway, witness and operator may read it, never agents (F1).

---

## 6. Sign-off

CON-01: **changes**, for B1–B4 only. When those four land with tests, I sign off the 11 day-one rules for CON-01. F1–F8 are tracked to S4: F1 and F2 go to maya (contracts and runtime), F3 and F6 to arjun (verify), F4 and F8 to nisha (ADR-03), F5 to vikram and ishaan, F7 to vikram (ADR-05). The notes are optional before S4. Maya may accept a blocker instead of fixing it, but B2 and B4 are not acceptable to me as-is. B2 voids C1 and C4 outright, and B4 is a live jury DoS.
