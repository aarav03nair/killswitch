# Call #2: Design freeze, binding resolutions

**19 Nov 2026** · Maya (Eng Lead) · ⚑ = needs Aarav · Inputs: reviews of ADR-00…07, CON-01, SEC-02, ABS-04; SEC-03; CON-02-requests; CALL-01; THREAT-MODEL v3.
**Rules.** Every row binds, and this file wins over any review. "Adopt X" means the review fix is binding exactly as written. Contracts go to **v1.1.0**, frozen 22 Nov. ADRs are revised by 21 Nov, ≤900 words, with detail moved into test names.

## A. Oracle and S\*

| id | Issue | Resolution | Edit | Test |
|---|---|---|---|---|
| A1 | S\* definition | **Same seed and config, fault disabled** (the culprit runs its honest step). Pure world: monitor, containment and recovery off; outbox dispatches at `release_tick`. Rogue-slot runs: the slot no-ops from `fault_tick` | ADR-06, ADR-00 | `test_oracle_self` (B=∅); T2 |
| A2 | Three t0s | `RunConfig.fault_tick` = t_inject (seeded, in [T/4, T/2]). Oracle t0 = min tick over B ≥ t_inject. ADR-05 uses `t0_seq_est`. Drop `injected` | C5, C6, ADR-05, ADR-06 | `test_t0_ge_inject` |
| A3 | Ground-truth leak | fault/culprit/fault_tick are scorer-only. TCB gets `RunConfig.tcb_view()` with them blanked | C6, ADR-00 | `test_tcb_blind` (record identical) + AST guard |
| A4 | Ledger | **Harness-side** (ks.world): a per-tick state.db diff keyed per **(table, pk, field)**, plus sink deliveries. Adds seq (null = bypass), agent, idempotency_key | ADR-06 | `test_bypass_enters_B`, `test_ledger_per_field` |
| A5 | Self-grading | ks.score/ks.oracle never import ks.taint/monitor/policy/recovery. Both tainted-effect metrics come from the ledger | ADR-06 | `test_import_lint` |
| A6 | B/G/R/C, metrics, protocol | Adopt ADR-06 review #4, #7, #9. Keys: `post_alert_tainted_effects`, `irreversible_tainted_released`. T=120, demo H=6 (asserted ≥ max detection latency). The bench approver never resolves flags. F7 is the honest failure | ADR-06, TERMS | `test_score_schema_golden`, `test_held_at_T_left`, `test_f7_null` |
| A7 | Invariants vacuous | World-side supplier registry; price bound 2× tick-0 price; `invariants_ok` in score.json | ADR-06 | `test_registry_nonvacuous` |
| A8 | Culprit's honest post-fault writes | The seed is every culprit write in [t0_seq_est, suspend]. That is conservative, and the honest ones count in C, reported | ADR-05 | `test_culprit_honest_write_in_C` |

## B. Hero result: supplier row and triage conflict

**Decision: (3), field-level objects for sensitive fields.** ⚑

| Option | Hero R | Verdict |
|---|---|---|
| (1) keep flag | >0 | Rejected. The conflict is an artefact of row granularity: triage edits `risk_note`, crm swapped `iban`, and they share no datum. It gives up D13 on our own hero |
| (2) restore + re-run triage | 0 | Rejected. It needs a new `expect` semantic (M13), restores over a tainted head, and redoes honest work that never read the IBAN, which contradicts "kept without redo". It is the most code on the critical path |
| **(3) field objects** | **0** | Planner granularity matches the per-field ledger (A4) where it matters. Driven by the same `sensitive_fields` config as the early hold, so it stays generic. Taint is more precise and still conservative. One id convention, one adapter rule |

| id | Resolution | Edit | Test |
|---|---|---|---|
| B1 | Each `sensitive_fields` entry is its own versioned object `table:pk.field`; the rest of the row stays `table:pk`. Actions write only changed objects. Pks contain no `.`. OBJ_ID_RE is unchanged | C3 helper `field_obj_id`; ADR-05; ADR-03 adapters | `test_sensitive_field_object` |
| B2 | **F2+ outcome.** crm writes `suppliers:S-17.iban` v2 at t_inject and `suppliers:S-22` (price ×10) at t_inject+1. triage edits `suppliers:S-17` (`risk_note`) without the iban in its view. Plan: restore iban and S-22; re-run billing, payments (same `outbox:<id>`, v+1, back on hold), comms and reporter; triage is **kept without redo**; **no flag**. Targets: R=0, C=0, both tainted-effect metrics 0, reemitted 0 | ADR-05, ADR-06 | `test_hero_f2plus_golden` |
| B3 | **Demo** dry-run diff lanes: restore · re-run · **kept** (triage's note on the same supplier) · independent (inventory, docs). Line: "triage edited the same supplier; we kept its edit and restored only the bank account" | ADR-07, script | console golden, 0 flags |
| B4 | **D13** ⚑: "Targets, to be measured: on the hero scenario R = 0 and C = 0, with zero post-alert tainted effects and zero irreversible tainted effects released. If an honest agent later changed the same field, the conflict goes to a person and counts in R." | ABS kit | guardrail check |
| B5 | **Honest flag kept**: bench fault **F2+x**, where triage edits S-22, a non-sensitive row crm wrote. This gives `flag(write_write_conflict)`, unresolved, R>0, and serves as the jury Q&A backup | ADR-06, ADR-05 | `test_triage_conflict` on F2+x |
| B6 | No restore-over-tainted-head. `RestoreStep.expect` = the culprit's after-version. M13 dropped | C5 | `test_restore_expect_head` |

## C. Determinism

| id | Resolution | Edit | Test |
|---|---|---|---|
| C1 | `RunConfig.decision_latency_ticks` L. Plan approval blocks the barrier: tick plan_tick+L does not open until the decision arrives, and an early click waits. Other operator Controls land at the next control phase. `ks run --decisions RUN` replays recorded operator Controls | ADR-00, C6 | `test_replay_decisions_identical` |
| C2 | **One frame per connection per tick**, FIFO. A wrong tick gives `deny/late_frame` in that agent's slot. Surplus frames wait, so a flooder only delays itself | ADR-00, C2 | T3b |
| C3 | `key_mode = fresh\|repro`. In fresh mode the witness makes its own key. The repro secret is 0600 uid 0, outside the run dir, labelled "not a security run", and banned for D11/RT2/RT8 | C6, ADR-00/01 | `test_fresh_keys_differ` |
| C4 | DETERMINISTIC_FILES = config, record\*, witness\*, alerts, effects.jsonl, oracle/\*\*, score.json, plans/\*\*, sidestore/\*\*; **keys.json removed**. \* = via projection; the rest is byte-identical even in fresh mode | C6 | T1, T1b |
| C5 | Projection `ks.contracts.determinism_view()`: records without {hash, prev_hash, gw_sig, envelope.sig}, checkpoints without {head, sig} | C2/C6 | T1b |
| C6 | `ks repro A B`: diffs the projection; exit OK or new `Exit.DIVERGED` | ADR-07, C6 | `test_ks_repro_fresh_pair` |
| C7 | T1 runs under 3 PYTHONHASHSEEDs. T4 uses a per-agent projection. Per-tick caps (control 32, dispatch 32); startup asserts `tick_us` > the sum. A dead-run dry-run writes outside the run dir | ADR-00, ADR-07 | T1, T4, T5 |

## D. Epochs and expiry

| id | Resolution | Edit | Test |
|---|---|---|---|
| D1 | Epochs start at 0 and are **strictly monotonic per principal**; suspend, revoke and release each set a new maximum. verify folds them | ADR-01/04, C4 | `test_epoch_monotonic` |
| D2 | `MAX_EXPIRY_TICKS=8`, with the nonce window equal to it. Order: sig, expiry, nonce. A reused `(agent_id, action_id)` gives `nonce_reused` | C1/C2, ADR-01/03 | RT4 (presigned, unsent), `test_action_id_reuse` |
| D3 | `TickFrame.epoch` (None while suspended or revoked) | Transport | RT11b |
| D4 | **Release** = active again at a fresh epoch; it lifts only suspension holds, and lineage/sensitive holds survive. TERMS: "restores the agent's permissions (fresh epoch)". Reword THREAT-MODEL C6 | ADR-03/04, THREAT-MODEL, TERMS | RT11b |
| D5 | Connection deny-list checked at step 5 (before the agent) and in the step-8 txn. Conns are 1:1, with no reconnect | ADR-01/03 | RT3: 0 exec from c-R after suspend |

## E. Identity and system principals

| id | Resolution | Edit | Test |
|---|---|---|---|
| E1 | `c-0` is for in-gateway system envelopes only. On `c-1..`, a system agent_id gives `bad_sig` unverified, and an agent `ks.*` tool gives `out_of_scope` | C2 validator, ADR-01/03 | **RT3c** forged Control: 0 applied |
| E2 | **Rename signer `ks.console` → `ks.operator`.** "Incident console" = the read-only page | ids, all ADRs, TERMS | grep test |
| E3 | Keyring: exactly one key each for gateway, witness, monitor, operator, recovery and every agent, failing closed. Controls are signed by `issued_by` | C6, ADR-01 | `test_keyring_complete` |
| E4 | Fresh mode: the witness generates its key and the gateway never holds it | ADR-00/01/02 | `test_witness_key_not_in_gateway` |
| E5 | Signer: `MAX_SIGN_PER_TICK=2`; refuses foreign agent_id, `ks.*` tool, non-null sig, stale epoch, suspended principal | Transport, ADR-01 | `test_signer_refusals` |

## F. Recorder and verify (adopt kabir's ADR-02 M1–M8)

| id | Resolution | Test |
|---|---|---|
| F1 | `RunAnchor{seq, head, tick, count, keyring_hash, config_hash}`; `ks verify --head`; `VerifyReport.anchored`. C1 holds only when anchored | RT8(h) keyring swap → WITNESS |
| F2 | `count` from 1, +1 per line, matching the anchor | `test_count_chain` |
| F3 | IO only for missing config/keys/record. Bad record line → TAMPER `parse_error`. Witness missing or bad → WITNESS. Side entry re-hashed → TAMPER `side_entry_mismatch`. Order: record, side, witness, reconcile | RT7(b), RT8(f) |
| F4 | Truncation: WITNESS `truncated`, first_bad = n+1; anchor mismatch → `head_mismatch` | RT7(d) below last checkpoint |
| F5 | **Freeze trigger**: `ks recover` runs verify first (non-OK → FROZEN). The live monitor compares record.jsonl with the in-memory head every tick. The freeze derives from chained `ks.alert` records and lasts until run end | `test_frozen_dead_dir`, `test_live_edit_freezes` |
| F6 | Witness stall: wait to the deadline, proceed, alert (W=1). `<run>/witness-heads/` 0700, witness uid | `test_hung_witness` |
| F7 | RT8(g) via `GatewayHooks.skip_checkpoint`; RT8(h) keyring swap. Per-record checks per kabir's should-fix list | RT8(g,h), `test_clean_run_reconciles` |

## G. Gateway and catalogue

| id | Resolution | Edit | Test |
|---|---|---|---|
| G1 | **Catalogue.** R: `ticket.set_priority`, `supplier.set_risk_note`, `crm.update_supplier`, `crm.upsert_customer`, `crm.delete_customer`, `billing.draft_invoice`, `ledger.post`, `compliance.record_finding`, `inventory.adjust`, `docs.write`, `<table>.read`. C: `ticket.create`, `billing.issue_credit`. **I1: `payments.send`, `comms.send_email`** (ADR-06 changes to I1). I2: `docs.purge`. System: `ks.control`, `ks.dispatch`, `ks.alert`, `ks.approve`, `ks.recover.<op>` | ADR-03, ADR-06 | `test_catalogue_covers_world` |
| G2 | **Role→tool (per field)**: intake {ticket.create}; triage {ticket.set_priority, supplier.set_risk_note}; crm {crm.\*}; billing {billing.\*, ledger.post}; payments {payments.send, ledger.post}; comms {comms.send_email}; reporter, docs {docs.write}; docs also {docs.purge}; compliance {compliance.record_finding}; inventory {inventory.adjust, ticket.create}. A sig_ok `out_of_scope` denial is the `scope` evidence | ADR-03 | `test_scope_table` |
| G3 | **Early hold**: at creation, a lineage sensitive version from tick v sets `release_tick = max(tick+H, v+2H)`. The dispatcher holds on a post-creation change via `Control{hold, outbox, reason=sensitive_field}`. Off at H=0. The hero is caught by `beneficiary_changed_then_paid` + lineage hold | ADR-03, C6 doc | `test_early_hold_non_iban`, RT10 |
| G4 | Dispatch = `ks.dispatch` record on c-0 (lineage read_set, status write_set); holds and unholds are Controls | ADR-03 | `test_clean_run_reconciles` |
| G5 | **seq is assigned at the start of the `BEGIN IMMEDIATE` txn**, appended after commit. A crash → abort + RECONCILE | ADR-03 | `test_crash_commit_append` |
| G6 | `ks.approve{plan_id, plan_hash, steps}` binds every `ks.recover.<op>`. Unhold re-executes without nonce/expiry (M10) | ADR-03/05, C4/C5 | `test_recover_bound_to_approval` |
| G7 | RT5 hook `between_check_and_txn`. Oversize/deep frames → `deny/schema` + close | ADR-03, C1 | RT5, `test_depth_6kb_denied` |

## H. Monitor and attribution

| id | Resolution | Edit | Test |
|---|---|---|---|
| H1 | **`root_candidates[0]` = the writer of `evidence_versions`.** Then backward taint, with a bounded walk. Two or more writers, or none, means no suspend | ADR-04/05, C4 doc | RT9 (crm [0], intake top 3) |
| H2 | Agents reached only through reads are **never auto-suspended**. A laundered honest writer is suspended and counted in false_accusations | ADR-04 | RT9, RT11a |
| H3 | **Hard**: beneficiary_changed_then_paid, ledger_balance, iban_checksum (it guards a sensitive field that feeds I1), pii_egress, scope, reconcile (names nobody, so suspends nobody), sig (conn only). **Soft**: price_vs_history, rate, barrier.deadline. **Never hard**: tamper, witness_stall (freeze by kind) | ADR-04, C4 validator | `test_hard_table` |
| H4 | Beneficiary alert: evidence_versions = the payee field only; the payment goes in evidence_seqs | ADR-04 | RT10 |
| H5 | **F3 = rogue comms emails PII.** Detector `inv.pii_egress`, owner **nisha**. The cleartext pytest stays kabir's | ADR-04/06, SPEC | `test_f3_pii_egress_held` |

## I–M. View, operator, hygiene, CLI, RNG

| id | Resolution | Edit | Test |
|---|---|---|---|
| I1 | `TickFrame.view: [ViewEntry{obj, ver, hash, value}]` from the scenario's narrow per-agent scope (≤64). The entries **join the read_set** of that tick's submission | Transport, ADR-05/06 | `test_crm_record_reads_T3` |
| J1 | Operator socket `/run/ks/<run_id>/operator.sock` in a 0700 uid-0 dir, with `SO_PEERCRED` uid==0 | ADR-00, ADR-07 | `test_operator_sock_rejects_agent` |
| K1 | Non-blocking sockets, 64 KiB outbound cap → EOF; bounded reader | ADR-00 | T4 non-reader |
| K2 | Kill by uid at teardown; refuse to start if any exist; RLIMIT_NPROC | ADR-00 | `test_fork_survivor_killed` |
| K3 | oom_score_adj −1000 TCB / +1000 agents; rogue slot nice 19, SCHED_IDLE, RLIMIT_CPU | ADR-00 | T4 spin/bomb: 0 honest misses |
| K4 | EOF after 3 consecutive misses (not a suspend). Demo `--tick-deadline-ms 250` | ADR-00 | T4 wall-time bound |
| L1 | `ks run --pause-at TICK,… / --step` pauses between ticks; beats 1–3 run live | ADR-07 | `test_pause_identical_record` |
| L2 | `ks inject --with-baselines` → `RUN/baselines/<name>/`, embedded by the console | ADR-07 | console golden |
| L3 | Audit proof = live `ks verify RUN --head` (TAMPER, first bad **seq**). The page is stale until rebuilt. `--dry-run` prints the apply command. `blame` is an alias | ADR-07, TERMS | `test_dryrun_prints_apply` |
| M1 | RNG `sha256(canonical([seed, name, tick]))` everywhere | ADR-00/06 | T1 |
| M2 | The view is snapshotted after the control phase; execution is sequential, so a version is visible iff seq > s | ADR-00/05/06 | `test_same_tick_visibility` |

## N. Red-team spec (kabir)

| id | Resolution |
|---|---|
| N1 | RT11a (ADR-04 path, rogue `--slot crm`, false_accusations=0) / RT11b (operator suspends payments, fresh-epoch release, tainted items stay held) |
| N2 | SEC-03 §4 and ADR-03/06 renames throughout |
| N3 | RT6 projects over conn ≠ rogue. RT4 uses a presigned unsent envelope. RT3 spliced args → bad_sig. RT2 runs fresh |
| N4 | RT12 drops reconnect and delegation; it keeps the retry probe plus a synthetic revoked-ancestor act_chain |
| N5 | RT7 redaction boundary; RT8(g,h); new RT3c |

## CON-02 checklist: contracts v1.1.0 (maya)

- [ ] C1: `MAX_EXPIRY_TICKS=8`, `MAX_DEPTH=32`, every decode exception → `CanonicalError`
- [ ] Transport: `TickFrame.epoch`, `TickFrame.view`/`ViewEntry`, `MAX_VIEW_ENTRIES`, `MAX_SIGN_PER_TICK`, signer doc
- [ ] C2: `WitnessCheckpoint.count`; `LATE_FRAME`, `STALE_PLAN`; K4 + F3 + N1 validators; `determinism_view()`
- [ ] C3: `field_obj_id`; M11 docs; aggregates enumerate rows
- [ ] C4: tamper/stall hard=False, dropped from HARD_ALLOWED; empty-evidence cases (M3, K6); docs M9, M10, K15, monotonic release
- [ ] C5: `t0_seq_est`; M14; approval binding; **M13 dropped**
- [ ] C6: `fault_tick`, `key_mode`, `decision_latency_ticks`, `tcb_view()`; `RunAnchor`; `anchored` + reasons (K16); Keyring K5; RunDir K7 + `BASELINES_DIR`; new DETERMINISTIC_FILES; `Exit.DIVERGED`; M12
- [ ] ids: `ks.operator`, `SYSTEM_CONN="c-0"`; README K12/K13; SEC-03 probes → regression tests; regenerate `schema/`

## ADR revision assignments (21 Nov)

| Owner | Items |
|---|---|
| maya (ADR-00, CON-02) | A1, A3, C1–C5, C7, D3, E4, F6, I1, J1, K1–K4, M1, M2 |
| arjun (ADR-01/02) | C3, D1, D2, D5, E1, E3–E5, F1–F7 |
| nisha (ADR-03/04) | B1 adapters, D4, D5, E1, G1–G7, H1–H5 |
| vikram (ADR-05) | A2, A8, B1, B2, B5, B6, G6, H1, I1; review items 5–9 |
| tara (ADR-06) | A1–A7, B2, B5, G1, H5, I1, M1, M2 |
| ishaan (ADR-07) | B3, C6, E2, F1, J1, L1–L3 |
| kabir (SEC-02, THREAT-MODEL) | D4, F7, H5, N1–N5 |
| zoya (TERMS, script) | A6 keys, B3, B4 ⚑, D4, E2, L3 |

## Deferred to post-finale

| Item | Reason |
|---|---|
| Keyed commitments (SEC-03 §5) | A 2.0 hash change. Covered now by "pseudonymised" wording and no OTel export of sensitive hashes |
| Genesis bound to config+keyring | Already covered by the anchor's hashes |
| Absence and coarse reads | Enumerated rows suffice |
| RT12 delegation | No delegation path in the world |
| Per-conn flood budget (F8b) | One frame per tick already bounds records |
| LLM agent (D9) | Stretch goal, only if green by 30 Nov |
| Field objects for non-sensitive fields | F2+x deliberately keeps an honest row conflict |

## Amendments

| id | Amends | Change | Source | Test |
|---|---|---|---|---|
| G1-a | G1 | System tools gain `ks.seed` (signer `ks.gateway`). It is valid only as record seq 1, tick 0, on `c-0`, with an empty read_set, and its write_set must equal `seed_state`. Any other admitted `ks.seed` fails verify as `seed_invalid` (TAMPER). The seed record stops using `ks.dispatch`, so G4 stays pure. Contracts 1.3.0, additive. G1 is otherwise unchanged | ⚑ D-15, decided by Aarav on 19 Nov (B3-43, maya) | `tests/contracts/test_contracts_13.py` |
| A8-a | A8, B2 | `t0_seq_est`'s backward walk follows the suspect's reads of its own earlier versions **only through tool reads**. Each read-set entry now carries `source` = `view` or `tool`, set by the gateway. The literal walk (every self-read, view ones too) is still computed and goes in the plan as `t0_seq_est_literal`, so the dry-run reports the delta. A self-chain (bad W1, the suspect's tool reads W1, writes W2, alert on W2) seeds W1. The B2 hero seed stays {`S-17.iban` v2, `S-22` v2}, because crm sees its honest tick-3 `S-31` edit only in its view. Residual: a self-read that reached the suspect only through its view is not followed, and shows up as a non-zero delta. When the view and the tool read one object at different versions, both entries are kept (Panel, B3-41 review). Also in contracts 1.4.0: `RestoreStep.to = None` restores a culprit-created object to absent. A8 and B2 are otherwise unchanged | ⚑ B3-45 option C, decided by Aarav on 19 Nov (B3-46, maya) | `tests/taint/test_taint.py` (self-chain), `tests/taint/test_world_f2plus.py`, `tests/contracts/test_contracts_14.py`, `tests/gateway/test_b346.py` |
