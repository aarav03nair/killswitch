# ADR-02: Recorder, witness, `ks verify` and the PII side store

Owner: arjun · Reviewer: kabir · Binding: CALL-01 (D6, D7), CALL-02 resolutions (F1-F7), THREAT-MODEL v3, contracts v1.1.0

## Context
Insiders can edit run-dir files (B4): we detect, not prevent. A bare hash chain fails against someone who recomputes the whole file (RT8), and `keys.json` is itself editable. Records keep raw values such as IBANs out of the evidence (rule 9). D6 rejected Merkle checkpoints.

## Decision
1. **Recorder.** `record.jsonl` is append-only, one canonical C2 line per envelope, denials included. Only the gateway writes it (`0640`, group = witness gid; run dir 0711). The gateway assigns `seq` (from 1, no gaps), `ts_us`, `record_id`. `prev_hash` chains from `GENESIS_HASH`; `hash = sha256(signing_bytes)`; `gw_sig` uses the in-memory gateway key. `seq` is assigned at the start of the write txn and appended after commit (a crash is abort plus RECONCILE). Every state change is a record with a `write_set`, including dispatch and recovery writes, so `state = fold(record)` holds.
2. **Agent signature.** The gateway records `sig_ok`; `verify` re-checks it from `keys.json`.
3. **Witness.** A separate uid process. In fresh mode it generates its own key and sends only the public key; the gateway never holds it (E4). The gateway sends `(seq, head, tick)` as ADR-00 specifies; the witness signs what it is sent (anchoring, not re-verification) and appends `WitnessCheckpoint(seq, head, tick, count)` to `witness.jsonl`, which it creates and owns. `count` starts at 1 and rises by 1 per line. Head store: `<run>/witness-heads/` (0700, witness uid). A final checkpoint is taken at run end.
4. **Anchor (F1).** The console prints `keyring_hash` and `config_hash` at start and `RunAnchor{seq, head, tick, count, keyring_hash, config_hash}` at the end, off the file system. `ks verify --head <anchor>` checks both hashes **before any signature**. `VerifyReport.anchored` says whether that happened. Repro mode forces `anchored=false`.
5. **Witness stall (F6).** The tick waits for the witness ack up to its deadline, then proceeds and raises `Alert{kind: witness_stall}` (W = 1). It names nobody, suspends nobody and is never hard (D7); the recovery freeze is tied to the kind.
6. **`ks verify <run> [--head ANCHOR] [--state DB]`**, in this order, stopping at the first failure:
   - **IO** only if `config.json`, `keys.json` or `record.jsonl` is missing or unreadable.
   - **Keyring** complete (E3); anchored: `keyring_hash` and `config_hash` match, else `WITNESS`, `keyring_mismatch`.
   - **Record pass**, per line: parse and validate (failure: `TAMPER`, `parse_error`, first_bad = that line); `seq == i`; `count` chain; `prev_hash`; `hash`; `gw_sig`; agent signature consistent with `sig_ok`. Per-record rules: an exec `ks.control` or `ks.recover.*` is by a system principal on `c-0` with `issued_by == agent_id`; epochs fold monotonically; `expiry_tick >= tick` on exec/hold; `ts_us` follows the formula. Failure: `TAMPER`, first_bad = seq. A deleted line fails at the first missing seq.
   - **Dispatch window check (F4).** For every `ks.dispatch` record, no hold Control, taint seed or author suspension lies in `(created_seq, dispatched_seq)` without an intervening unhold or release. Failure: `TAMPER`, `dispatch_window`, first_bad = the dispatch seq.
   - **Side-store pass.** Entries parse without their validator and are re-hashed. Mismatch: `TAMPER`, `side_entry_mismatch`, first_bad = lowest referencing seq.
   - **Witness pass.** Missing or empty `witness.jsonl` on a run with records: `WITNESS`, `witness_missing`, first_bad = 1. A bad line or signature: `WITNESS`, `witness_sig_invalid`. `count_mismatch` unless `w[i].count == i`; ticks strictly increase, seq non-decreasing (no-op ticks repeat), seq <= n; `head == record[seq].hash`, else `witness_mismatch`. A checkpoint with seq > n: `WITNESS`, `truncated`, first_bad = n + 1.
   - **Anchor match.** Anchor `count` and `head` equal the last checkpoint's. Mismatch: `WITNESS`, `head_mismatch`, first_bad = min(anchor.seq, n) + 1.
   - **Reconcile.** `state_digest(fold(record))` against `--state` (default `<run>/workspace/state.db`). A mismatch is `RECONCILE`, first_bad None. No state file: skip, reason `no_state`, ok=true, reported.
   - Last stdout line is `VerifyReport{ok, exit, first_bad, reason, last_witnessed_seq, anchored}`.
7. **Freeze (F5).** `ks recover`, including `--dry-run`, runs verify first; any non-OK result is `Exit.FROZEN`. Live, the monitor compares `record.jsonl` with the in-memory head every tick and raises `tamper` on mismatch. The monitor submits every alert as a chained `ks.alert` envelope (`args = alert.to_obj()`). The freeze is derived from those records, never from `alerts.jsonl`, and lasts until run end. `verify` cross-checks `alerts.jsonl` against the records.
8. **TTI (F6).** Time-to-intervention is computed from chained `ks.alert` records only. The unsigned `alerts.jsonl` is never an input to `score.json`.
9. **Side store.** `sidestore/<h[:2]>/<h>.json` (0700 dirs, 0600 files, gateway-owned) holds `SideEntry` values keyed by the record's hash. `redact(h)` erases the value, keeps the hash; chain and signatures still verify.
10. **Claim:** "tamper-evident up to the last witnessed head"; **anchored** verification is required for the keyring and truncation guarantees; unanchored is "consistent, not anchored". No Merkle trees.

## Consequences
- Line edits, deleted lines, chain rewrites and keyring swaps (anchored) are detected without the witness key. A gateway-key holder who rewrites only records after the last witnessed seq is not detected before the final checkpoint exists; RT8(g) shows it, and the anchor catches it afterwards.
- Insiders holding both keys, or root, are out of scope (HSM, WORM in production).
- Records are pseudonymised, not anonymised: a plain IBAN hash can be reversed by dictionary (keyed commitments deferred).
- A jury edit in an editor (case, space, blank line) gives `TAMPER` with a first_bad line, never a bare IO error.

## Interface touched
**C2** (Record, `WitnessCheckpoint.count`). **C3** (`SideStore`, `state_digest`). **C4** (`witness_stall`, `tamper` as hard=False, freeze by kind; `ks.alert`). **C6** (`Exit`, `RunAnchor`, `VerifyReport.anchored` and reasons, `RunDir`, `WITNESS_HEADS_DIR`, Keyring). **C1** read only. **C5** untouched.

## Tests that prove it
- `test_rt07_line_edit`: (a) edit an IBAN after-hash; (b) edit a side-store value; (c) delete line k; (d) truncate below the last checkpoint. a, c: `TAMPER`, first_bad k; b: `TAMPER` `side_entry_mismatch`; d: `WITNESS` `truncated`, first_bad n+1. Uppercase-hex and blank-line edits: `TAMPER` `parse_error`. Clean copy `OK`. `ks recover --dry-run` on each: `FROZEN`, no status changes.
- `test_rt08_rewrite`: recompute with the gateway key; `WITNESS`, first_bad = first witnessed seq >= k. (e) edited heads: bad witness sig. (f) deleted `witness.jsonl`: `WITNESS`. (g) via `GatewayHooks.skip_checkpoint`, rewrite after the last checkpoint: `OK` unanchored, caught once the final anchor exists. (h) keyring swap: `WITNESS` anchored, documented out of claim unanchored.
- `test_rt08_tail_truncation`: record only (`WITNESS`); both files to an older prefix (anchored: `head_mismatch`).
- `test_count_chain`, `test_frozen_dead_dir`, `test_live_edit_freezes`, `test_hung_witness` (alert raised, nobody suspended), `test_dispatch_window` (F4), `test_alerts_cross_check` and `test_tti_from_chained_alerts` (F6).
- `test_clean_run_reconciles` (OK incl. reconcile), `test_reconcile`, `test_crash_commit_append`, `test_sidestore_redact`, `test_no_values_in_record`.

## Amendments (Call #2)
Applied: **F1, F2, F3, F4, F5, F6, F7** (resolutions); **X6, X7, X8** (F4 dispatch-window check and F6 TTI from chained alerts, both mine); Kabir M1-M8 plus should-fixes (anchor, `count`, strict-parse split, truncation first_bad, freeze trigger, witness topology and key, stall semantics, RT8(g) hook, per-record checks, reasons, header line). Contracts v1.1.0 names used throughout.
