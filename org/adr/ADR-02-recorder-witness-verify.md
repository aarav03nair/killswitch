# ADR-02: Recorder, witness, `ks verify` and the PII side store


## Context
Insiders can edit run-dir files (B4): we detect, not prevent. A bare hash chain fails against someone who recomputes the whole file (RT8). Records must also keep raw values such as IBANs out of the evidence (rule 9).  D6 rejected the Merkle checkpoints RES-04 suggests.

## Decision
1. **Recorder.** `record.jsonl` is append-only, one canonical C2 line per envelope, denials included (rule 11). Only the gateway process opens it for writing (rule 8, 0600, gateway uid). The gateway assigns `seq` (from 1, no gaps), `ts_us` and `record_id`. Each record sets `prev_hash` to the previous `hash` (`GENESIS_HASH` for seq 1), computes `hash = sha256(signing_bytes)`, and signs `gw_sig` with the in-memory gateway key.
2. **Agent signature.** The envelope header is agent-signed. The gateway checks it and records `sig_ok`. `verify` re-checks it from `keys.json`.
3. **Witness.** A separate process under its own uid, with its own in-memory key and a 0700 store dir. It reads the record read-only. Once per tick it signs `WitnessCheckpoint(seq, head, tick)` and appends it to `witness.jsonl`. It keeps its own monotonic checkpoint `count`. At run end the console prints the final signed head `(seq, head, tick, count)` to stdout and the run summary, which sit off the file system.
4. **Stall alert.** The monitor raises `Alert{kind: witness_stall}` when the newest checkpoint is more than W ticks old. It names nobody, suspends nobody, and is never hard (D7).
5. **`ks verify <run> [--head ...] [--state ...]`** works in this order and stops at the first failure:
   - Parse every file canonically (strict). Failure: `Exit.IO`.
   - For each record, in order: `integrity_problems()` is empty; `seq == i`; `prev_hash` equals the previous hash; `gw_sig` valid; for parseable envelopes, the agent signature is consistent with `sig_ok`. Failure: `Exit.TAMPER`, `first_bad = seq` of the first failing line. A deleted line fails at the first missing seq.
   - For each checkpoint: witness sig valid; seq and ticks monotonic; `head == record[seq].hash`; `seq <= n`. Failure: `Exit.WITNESS`, `first_bad = checkpoint.seq` (the first witnessed seq whose head differs). A missing or empty `witness.jsonl` on a run with records fails closed with `Exit.WITNESS`, `first_bad = 1`.
   - If the printed head is given, it must match: its `seq <= n` and equals the file's last checkpoint, and its `count` equals the number of witness lines. This catches truncating both files to an older valid prefix. No printed head: out of scope (production: WORM).
   - Reconcile: `fold(record)` (the last `write_set.after` per obj) goes through `state_digest` and is compared with the digest of the live `state.db` heads. A mismatch is `Exit.RECONCILE`, `first_bad = None`.
   - Last stdout line is `VerifyReport`: `{ok, exit, first_bad, reason, last_witnessed_seq}`. Reasons include `hash_mismatch`, `seq_gap`, `gw_sig_invalid`, `witness_mismatch`, `head_mismatch`, `reconcile_mismatch`.
6. **Tamper response.** A verify failure on a live run raises `Alert{kind: tamper}`, which freezes recovery (`ks recover` returns `Exit.FROZEN`) and suspends nobody (D7).
7. **Side store.** `sidestore/<h[:2]>/<h>.json` holds `SideEntry` values keyed by the hash that the record carries (value). It is gateway-owned, 0600,. `redact(h)` erases the value, keeps the hash; chain and sigs still verify. A redacted entry is reported as unrecoverable. `verify` also re-hashes live entries, and an entry whose value does not match its hash is a `Exit.TAMPER` finding (RT7b).
8. **Claim:** "tamper-evident up to the last witnessed head". No Merkle trees or proofs. Records after the last checkpoint are uncovered, hence the stall alert.

## Consequences
- Line edits, deleted lines and chain rewrites without the witness key are detected. A gateway-key holder who rewrites only records after the last witnessed seq is **not** detected (RT8g), and this is deliberate.
- Insiders holding both keys, or host/root access, are out of scope (HSM, WORM in production).
- Records are pseudonymised, not anonymised: a plain hash of an IBAN can be reversed with a dictionary (SEC-03 keyed commitments deferred).
- Contract gap, for CON-01/maya: `WitnessCheckpoint` has no `count` field. THREAT-MODEL v3 relies on it. Request: add signed `count`. Fallback: `count` = line number in `witness.jsonl`, compared with the printed head. Weaker: the file itself can be truncated.

## Interface touched
- **C2** (Record, WitnessCheckpoint): read and written, with the `count` request above.
- **C3** (`SideStore`, `state_digest`, heads): implemented here and read by reconciliation.
- **C4**: raises `witness_stall` and `tamper` alerts.
- **C6**: `Exit`, `VerifyReport`, run-dir layout, `keys.json` public keys. No change.
- **C1**: read only. **C5**: not touched.

## Tests that prove it
- `test_rt07_line_edit`: (a) edit the IBAN after-hash, (b) edit the side-store value, (c) delete line k, (d) truncate the last m lines. a, b, c: `TAMPER`, `first_bad == k`. d: `TAMPER` or `WITNESS`, `first_bad == last_kept_seq + 1`. Clean copy: `OK`. `ks recover --dry-run` returns `FROZEN`, and no agent's status changes.
- `test_rt08_rewrite`: recompute the chain with the gateway key; `Exit.WITNESS` with `first_bad == min(w.seq for w in witness if w.seq >= k)`. Variants (e) edited witness heads give a bad witness sig, `WITNESS`; (f) deleted `witness.jsonl` gives `WITNESS`; (g) rewriting only records after `last_witnessed_seq` returns `OK`, as the claim boundary.
- `test_rt08_tail_truncation`: truncate the record only (`WITNESS`); truncate both files to an older prefix (caught only with the printed head, `head_mismatch`).
- `test_witness_stall`: stop the witness for W ticks; a `witness_stall` alert exists and no agent is suspended.
- `test_reconcile`: edit `state.db`; `Exit.RECONCILE`.
- `test_sidestore_redact`: after `redact`, verify is still `OK` and `get` returns a redacted entry.
- `test_no_values_in_record`: no raw value in `record.jsonl`.
