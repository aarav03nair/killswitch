# ADR-06: World (10 agents), faults F1–F7 + F2+, oracle S*, metrics

Owner: tara · Reviewer: anaya · Binding: CALL-01 D10–D13, SYNTHESIS §6

## Context
The jury scores identify, contain, recover. RES-08 found no standard definition, so we define them and let anyone recompute them from the run dir (C6). The Panel showed the hero fault (F2+) is invisible to rate/scope rules and needs a dependency world plus a counterfactual oracle.

## Decision

**World.** Each agent is a pure function `f(seed, tick, view) → ≤1 envelope`, RNG derived as `sha256(seed|agent|tick)`. The gateway tick barrier runs agents in `agent_id` order (billing, comms, compliance, crm, docs, intake, inventory, payments, reporter, triage), so a reader sees writes from earlier ticks. Day-1 test: same seed twice is byte-identical (`DETERMINISTIC_FILES`), and the faulty run equals S* before t0.

| Agent | Reads | Writes (per tick) |
|---|---|---|
| intake | seeded inbound feed | `tickets` (incl. `supplier_bank_update`) |
| triage | `tickets` | `tickets.priority`; edits `suppliers.risk_note` (crm rows; later write-write conflict) |
| crm | `tickets` | `customers`, `suppliers(iban, unit_price)`; **applies `supplier_bank_update` tickets** (RT9) |
| billing | `suppliers`, `customers`, `tickets` | `invoices` (amount = qty × unit_price), `ledger` |
| payments | `invoices`, `suppliers.iban` | `outbox` payment (I1), `ledger` |
| comms | `invoices`, `customers` | `outbox` email (I2) |
| reporter | `invoices`, `ledger`, `inventory` | `docs/kpi.md` |
| compliance | `ledger` sample | `findings` |
| inventory | `inventory` | `inventory`, reorder tickets |
| docs | `docs/wiki` | `docs/wiki` |

Dependency graph: crm → billing → {payments, comms, reporter}; crm → payments, comms (direct IBAN/contact reads); billing/payments → compliance via ledger. inventory and docs are independent; triage consumes tickets, not crm output.

**Fault catalogue** (`ks inject <F> --seed S --tick T0 --culprit A` swaps the culprit's step for a faulty one, still signed with its own key; t0 is random per seed in [T/4, T/2]).

| ID | Injection point | Run |
|---|---|---|
| F1 | crm deletes customer rows | live |
| F2 | crm writes wrong IBAN or price ×10 | live |
| **F2+** | crm swaps a supplier IBAN (checksum-valid) at t0, price ×10 on another at t0+1; billing, payments, comms, reporter consume; triage edits a crm row later; inventory/docs unaffected | **live (hero, RT10)** |
| F3 | crm exfiltrates customers via email outbox | pytest |
| F4 | payments spams payments | live |
| F5 | rogue-agent template forges another's envelope | live |
| F6 | log-line edit / full chain rewrite → `ks verify` | live |
| F7 | crm drifts `unit_price` +1%/tick | live (honest failure case) |

**Oracle S\*.** Rerun the same seed with the culprit slot emitting no-ops (`oracle/`). Every world effect is one line in `effects.jsonl`: `{eff, tick, agent, kind, key, value_hash, class, state, injected}`, state ∈ present/held/cancelled/released. Compare on semantic `(kind,key,value_hash)`, never on bytes, tick or our taint graph. t0 = tick of the first `injected` effect. **B** = final-run effects absent or different in S*; **G** = honest effects equal to S*. Invariants checked on both: ledger balances, payment beneficiary = registry IBAN, unit_price ≤ 2× history, no payment to an unlisted IBAN. The scorer reads only the run dir (`config.json`, `record.jsonl`, `alerts.jsonl`, `plans/`, `effects.jsonl`, `oracle/`).

**score.json** (canonical, no floats; ratios are `{"n","d"}`; ticks are integers, `null` = never):
`tti_detect` (t0 → first alert), `tti_attribute` (alert → correct agent_id and first bad action_id), `ttc` (alert → first denied culprit envelope), `post_alert_tainted` (effects committed after the alert, by anyone, whose recorded read set touches B; target 0), `irreversible_released` (tainted I1/I2 items released; target 0), `R` (|B left|/|B|, irreversible counted), `C` (|G lost|/|G|), `revert_precision`, `revert_recall`, `replan_cost` `{rerun, replan, approvals, g}`, `reemitted` (duplicate external effects; target 0), `kept_without_redo`, `false_accusations`; also `fp_cost`, `damage_in_window`, `hold`, `baseline`, `seed`. Clean = R=0 and C=0; no composite score.

**Baselines** scored on the same faulty run: *snapshot* (restore to pre-t0 state: C high), *revert-culprit-only* (restore crm writes with no taint: clobbers triage, leaves billing/reporter derived, R>0, C>0), *no-op* (R=1).

**Hold.** `hold_window_ticks` 0 vs >0 (D10). At 0 the payment is dispatched and scored as `irreversible_released=1` and residual R; at >0 the early hold on `sensitive` `suppliers.iban` plus lineage hold yields 0.

**Protocol.** `ks.bench` runs ≥20 seeds (1..20) per fault × hold × {system, 3 baselines}; reports median, p95 (nearest rank) and max, never a mean. A probe keeps submitting culprit envelopes after containment. Abstract numbers stay labelled targets until measured (D13).

## Consequences
- Metrics are recomputable by the jury; the scorer cannot be gamed by our taint graph.
- Removing a culprit can change honest agents that read it; S* handles this by construction, but nondeterministic (LLM) agents would not be comparable. Out of scope (D9).
- Name mismatch to resolve: SPEC Q6 and TERMS use `post_alert_tainted_effects` / `irreversible_tainted_released`; this ADR uses the issue's names.

## Interface touched
C6 (`effects.jsonl`, `score.json`, `oracle/`, `RunConfig.fault/culprit`); reads C2 records, C4 alerts, C5 plans. No contract field change.

## Tests that prove it
1. Same seed twice → byte-identical `DETERMINISTIC_FILES`; clean run equals S* ledger.
2. Faulty run before t0 equals S* effects.
3. F2+ dependency: B contains billing/payments/comms/reporter effects; G contains inventory, docs, triage.
4. No-op baseline R=1, C=0; snapshot R=0 (hold>0), C>0; revert-only R>0.
5. Hold 0 gives `irreversible_released=1`; hold>0 gives 0.
6. Scorer run on a run dir alone (workspace deleted) reproduces `score.json`.
7. RT9: ticket-laundered IBAN is applied by crm.
