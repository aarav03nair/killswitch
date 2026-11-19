# ADR-06: World (10 agents), faults F1–F7 + F2+, oracle S*, metrics

Owner: tara · Reviewer: anaya · Binding: CALL-01 D10–D13, SYNTHESIS §6, CALL-02 resolutions + X3–X5, X8 · Formulas: [ADR-06-metrics.md](ADR-06-metrics.md)

## Context
The jury scores identify, contain, recover. We define the metrics and let anyone recompute them from the run dir (C6). The hero fault (F2+) is invisible to rate/scope rules and needs a dependency world plus a counterfactual oracle.

## Decision

**World.** Each agent is a pure function `f(seed, tick, view) → ≤1 envelope`; RNG = `sha256(canonical([seed, name, tick]))` (M1). The gateway runs agents sequentially in `agent_id` order (billing, comms, compliance, crm, docs, intake, inventory, payments, reporter, triage). `TickFrame.view` = `[ViewEntry{obj, ver, hash, value}]` from the scenario's narrow per-agent scope (≤64), snapshotted after the control phase (M2, `test_same_tick_visibility`); entries join that tick's read_set (I1, `test_crm_record_reads_T3`). Triage's view lists `suppliers:S-17`, not `.iban`. Day-1: same seed twice byte-identical; faulty run equals S* before t_inject.

Dependencies: intake → tickets; crm (applies `supplier_bank_update`, RT9) → billing → {payments, comms, reporter}; crm → payments, comms directly; billing/payments → compliance via ledger; triage edits `suppliers.risk_note`. inventory and docs are independent.

**Tools (G1).** Every world write is a catalogue tool: `ticket.set_priority`, `supplier.set_risk_note`, `crm.update_supplier`, `crm.upsert_customer`, `crm.delete_customer`, `billing.draft_invoice`, `ledger.post`, `compliance.record_finding`, `inventory.adjust`, `docs.write` (R); `ticket.create`, `billing.issue_credit` (C); **`payments.send`, `comms.send_email` (I1)**; `docs.purge` (I2). Email is I1. `test_catalogue_covers_world`.

**Faults** (`ks inject <F> --seed S --culprit A`; t_inject = `RunConfig.fault_tick`, seeded in [T/4, T/2]):

| ID | Injection | Run |
|---|---|---|
| F1 | crm deletes customers (`crm.delete_customer`) | live (optional) |
| F2 | crm wrong IBAN or price ×10 | live (optional) |
| **F2+** | crm writes `suppliers:S-17.iban` v2 (checksum-valid) at t_inject, `S-22` price ×10 at t_inject+1; billing, payments, comms, reporter consume; triage edits S-17 `risk_note`; inventory/docs unaffected | **live (hero, RT10)** |
| F2+c | as F2+, crm also does honest work in (t_inject+1, suspend] | bench |
| F2+x | as F2+, triage edits S-22 (non-sensitive row crm wrote) | bench, Q&A backup |
| F3 | **rogue comms** emails PII; detector `inv.pii_egress` (nisha) | pytest (`test_f3_pii_egress_held`) |
| F4 | payments spams payments | live (optional) |
| F5 | rogue-agent template forges an envelope | live |
| F6 | log edit / chain rewrite → `ks verify` | live |
| F7 | crm drifts `unit_price` +1%/tick | bench + pytest only: honest failure, `tti_detect` null, R=1 |

**Oracle S\*.** Same seed and config with the fault disabled, pure world (monitor, containment, recovery off); rogue-slot runs no-op from `fault_tick`. In S\* the culprit also stops at its faulty-run suspension tick (X3a); the collateral stall is reported apart. Oracle t0 = min tick over B ≥ t_inject (`test_t0_ge_inject`). **B/G are frozen at t_rec and compared at T.** The ledger is harness-side (ks.world): per-tick `state.db` diff per (table, pk, field) plus sink deliveries, with seq (null = bypass), agent, idem_key; no `injected` label (`test_bypass_enters_B`, `test_ledger_per_field`). Comparison is on values, not statuses (X4). Invariants use a world-side supplier master and a 2× tick-0 price bound (`invariants_ok`).

**score.json** (canonical, no floats): `tti_detect, tti_attribute, ttc, post_alert_tainted_effects, irreversible_tainted_released, R, C, c_culprit_window, invariants_ok, revert_precision, revert_recall, replan_cost, reemitted, kept_without_redo, false_accusations, fp_cost, damage_in_window, hold, baseline, baseline_oracle_assisted, seed`. Both tainted-effect metrics come from the ledger, never from our taint graph. TTI is computed from chained `ks.alert` records, never unsigned `alerts.jsonl` (X8-F6). Formulas: ADR-06-metrics.md.

**Baselines** (same run, same t_rec): *snapshot* (restore to t_inject−1, no re-run; C high), *revert-culprit-only* (per object, no taint; billing/payments/comms/reporter stay derived, R>0), *no-op* (R=1). Snapshot and revert are **oracle-assisted** (given t_inject), labelled so.

**Hero outcome (B2).** Restore S-17.iban and S-22; re-run billing, payments (same `outbox:<id>`, back on hold), comms, reporter; triage kept without redo, no flag. R=0, C=0 (`test_hero_f2plus_golden`). C=0 relies on the precondition that crm writes nothing else in (t_inject+1, suspend], enforced by `test_hero_precondition_guard`; F2+c shows C>0 (X3). Early hold plus `beneficiary_changed_then_paid` catch the payment inside H (G3).

**Protocol.** T=120, H ∈ {0, demo 6}, 20 seeds, deterministic bench approver releases re-run items before T and never resolves flags; median = 10th of 20, p95 = 19th, max, null = +inf, k/20 non-null reported; never a mean. Numbers stay labelled targets until measured (D13).

## Consequences
- The jury can recompute metrics; the scorer cannot be gamed by our taint graph (`ks.score`/`ks.oracle` import none of taint, monitor, policy, recovery: `test_import_lint`).
- The culprit's honest work between fault and suspension is reverted and counts in C (`c_culprit_window`).
- Nondeterministic (LLM) agents are not comparable with S\*; out of scope (D9).

## Interface touched
C6 (`effects.jsonl`, `score.json`, `oracle/`, `fault_tick`, `tcb_view()`), C3 (`field_obj_id`), Transport (`view`); reads C2 records, C4 alerts, C5 plans. No field change.

## Tests that prove it
`test_oracle_self` (B=∅), `test_t0_ge_inject`, `test_ledger_per_field`, `test_bypass_enters_B`, `test_import_lint`, `test_registry_nonvacuous`, `test_score_schema_golden`, `test_held_at_T_left`, `test_f7_null`, `test_hero_f2plus_golden`, `test_hero_precondition_guard`, `test_triage_conflict` (F2+x), `test_f3_pii_egress_held`, `test_catalogue_covers_world`, `test_crm_record_reads_T3`, `test_same_tick_visibility`, T1 (same seed byte-identical), RT9, RT10; no-op R=1, revert-only R>0, snapshot C>0; H=0 gives `irreversible_tainted_released` ≥ 1, H=6 gives 0; scorer on a run dir alone reproduces `score.json`.

## Amendments (Call #2)
- A1–A7: S* = fault disabled, pure world; t_inject vs oracle t0, `injected` dropped; harness-side per-field ledger; import-lint; names `post_alert_tainted_effects`/`irreversible_tainted_released` (mismatch note deleted); world-side registry; formulas moved to ADR-06-metrics.md.
- B2/B5: hero outcome with field objects (triage kept, no flag); F2+x honest flag.
- G1/H5/I1/M1/M2: catalogue, email I1; F3 = rogue comms (pytest); view joins read_set; RNG and visibility rules.
- X3: culprit stops at suspension in S*; precondition guard; F2+c golden C>0; `c_culprit_window`. X4: approver releases re-run items before T; value comparison. X5: baselines oracle-assisted, per-object revert. X8-F6: TTI from chained `ks.alert`.
- Anaya review: B/G frozen at t_rec, compared at T; T=120, H=6, L, approver; integer median/p95 and null handling; F7 honest failure; formulas for every metric.
