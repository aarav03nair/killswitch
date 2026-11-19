# ADR-03: Gateway, action classes R/C/I1/I2/U, policy and epoch fencing

Owner: nisha · Binding: CALL-01, THREAT-MODEL v3, CALL-02 resolutions (freeze), contracts 1.1.0

## Context
Agents reach shared state only through the gateway (B2 TCB). Recovery needs a class, a read/write set and a recorded decision before each action runs. Two races matter: a suspend landing mid-write (RT5) and an irreversible effect leaving after its lineage turned bad (RT10). A rogue may also skip the gateway (RT1).

## Decision

**1. Pipeline (fixed order, first failure stops, every stop is recorded).** One frame per connection per tick, FIFO; a wrong tick gives `deny/late_frame` in that agent's slot.
1. decode: unparseable, oversize or deeper than `MAX_DEPTH` gives `deny/schema`, `envelope=None`, and the connection closes
2. schema: unknown keys give `deny/schema`
3. signature against the claimed principal: `deny/bad_sig` (connection only). A system agent_id on `c-1..` gives `bad_sig` without verification; `c-0` carries in-gateway system envelopes only
4. expiry (`MAX_EXPIRY_TICKS=8`), then nonce (window = 8). The nonce is consumed only after sig and expiry pass. A reused `(agent_id, action_id)` gives `nonce_reused`
5. epoch and **deny-list**: agent, any `act_chain` ancestor, and the **connection** (`conn:<id>`). Reasons `stale_epoch`, `suspended`, `revoked`, `revoked_ancestor`. Connections are 1:1 and never reconnect
6. classify per action instance. An agent-signed envelope with a `ks.*` tool gives `deny/out_of_scope`
7. policy (below)
8. one **`BEGIN IMMEDIATE`** transaction. It first takes `seq` (execute order, ADR-00 T5), then re-reads epoch and the full deny-list (step 5 is a fast path only), then executes
9. after commit: append the sealed record (`seq` already fixed; gateway sets `ts`, `record_id`), then enqueue outbox items. The exec record's `write_set` covers the outbox object versions created by the enqueue, so reconciliation stays clean. A crash between commit and append aborts the run and verify reports RECONCILE; never silent.

The step-8 re-check closes RT5. The suspend commits as a Control in the same store, so a write either commits before it (`seq < q`) or sees it and gets `deny/suspended` or `stale_epoch`. The real window is between steps 5 and 8 (hook `GatewayHooks.between_check_and_txn`). Presigned envelopes die at 5 or 8.

**2. Classification.** Class is a function of `(tool, args, state)`, not the tool name. Adapters declare it and emit read and write sets; the agent reports nothing. Any tool outside the catalogue, an adapter without a classifier result, or a classifier exception gives **U, `deny/class_u`**, never executable. An R tool becomes U if its pre-image is unreadable. Declared class is ignored.

**3. Field objects (B1, X1, X2).** Each `RunConfig.sensitive_fields` entry is its own versioned object `table:pk.field` (C3 `field_obj_id`); the rest of the row is `table:pk`. Pks contain no `.`. Adapter rules:
- A write emits only the objects that changed. A field-only edit does not bump the row.
- A whole-row read (row read, aggregate, row in the TickFrame view) reads that row's field objects too. A read that omits the field reads only the row. Any read returning a sensitive value lists its field object.
- Triage's view scope lists `suppliers:S-17`, never `.iban`, so its read set omits the IBAN and its edit is kept, not flagged.

Sensitivity comes only from config.

**4. Catalogue (covers ADR-06's world; `test_catalogue_covers_world`).**

| Tool | Class | Writes / note |
|---|---|---|
| `<table>.read` (registered) | R | read set recorded; unregistered is U |
| `ticket.set_priority` | R | `tickets.priority` |
| `supplier.set_risk_note` | R | `suppliers:<pk>` `risk_note` only |
| `crm.update_supplier` | R | changed supplier objects, incl. field objects |
| `crm.upsert_customer`, `crm.delete_customer` | R | `customers:<pk>` (delete = tombstone) |
| `billing.draft_invoice`, `inventory.adjust`, `docs.write` | R | versioned rows |
| `ledger.post` | R | `ledger` rows (billing, payments) |
| `compliance.record_finding` | R | `findings` rows |
| `ticket.create` | C | compensator `ticket.close` |
| `billing.issue_credit` | C | compensator `billing.reverse_credit` |
| `payments.send` | **I1** | outbox, sink `payments` |
| `comms.send_email` | **I1** | outbox, sink `email` (ADR-06 changes to I1) |
| `docs.purge` | I2 | `hold/needs_approval` |
| `ks.control`, `ks.dispatch`, `ks.alert`, `ks.approve`, `ks.recover.<op>` | system | signed by the issuing system principal (gateway, monitor, `ks.operator`, recovery); agents cannot submit |
| anything else, raw SQL, shell, network | U | deny |

**5. Role to tool and field scope (`test_scope_table`).** Scope is per tool; adapters fix writable fields.

| Role | Tools | Fields |
|---|---|---|
| intake | `ticket.create` | tickets |
| triage | `ticket.set_priority`, `supplier.set_risk_note` | `tickets.priority`, `suppliers.risk_note` (never `.iban`) |
| crm | `crm.*` | suppliers, customers |
| billing | `billing.*`, `ledger.post` | invoices, credits, ledger |
| payments | `payments.send`, `ledger.post` | outbox (payments), ledger |
| comms | `comms.send_email` | outbox (email) |
| reporter, docs | `docs.write`; docs also `docs.purge` | docs |
| compliance | `compliance.record_finding` | findings |
| inventory | `inventory.adjust`, `ticket.create` | stock, tickets |

A sig_ok `deny/out_of_scope` record (`policy_rule p.scope`) is the evidence for ADR-04's hard `scope` detector.

**6. Policy**:
- `p.scope`: tool outside the role gives `deny/out_of_scope`.
- `p.i1_outbox`: I1 never executes inline. The gateway writes an `OutboxItem` (`queued`, `release_tick = tick + hold_window_ticks`, `lineage` = recorded read set). The agent gets `exec/ok` for the enqueue only.
- `p.i2_approval`: I2 gives `hold/needs_approval`; `unhold` by `ks.operator` re-executes the envelope through steps 5-8, without nonce or expiry, as a new record citing the hold record.
- `p.lineage_hold`: an R/C write or I-class item whose recorded read set touches a tainted version gives `hold/lineage_hold` (D8). Agent-declared lineage is ignored.
- `p.sensitive_early_hold` (generic, **by lineage**, G3): at creation, if the item's lineage contains a sensitive-field version written at tick `v`, `release_tick = max(tick + H, v + 2H)`. Detectors get a full window after the bad write; a post-creation trigger alone would miss F2+, where the swap precedes the payment. After creation, if a lineage sensitive field changes, the dispatcher holds the item with `Control{hold, outbox:<id>, issued_by ks.gateway, auto, reason=sensitive_field}` (an exec record cannot carry that reason). At `H=0` the rule is off. The hero is caught by `beneficiary_changed_then_paid` plus lineage hold; dispatched items stay residual damage (D10).

**7. Dispatcher.** Each tick, for each `queued` item with `release_tick <= tick`, the dispatcher emits `ks.dispatch` on `c-0` and, in its transaction, re-checks author epoch and deny-list, no hold, lineage untainted, sensitive fields unchanged. Only then does the item go `dispatched`. The record's read set is lineage plus `outbox:<id>@ver`; its write set is the status change. Holds and unholds are Controls, so fold(record) equals state on clean runs (`test_clean_run_reconciles`). An unheld item returns to `queued`, re-checked. Idempotency key is gateway-derived.

**8. Release (D4).** Release makes the agent active at a **fresh, strictly monotonic epoch**, never the old one. It lifts only suspension holds; lineage and sensitive holds survive and are re-checked at dispatch.

**9. Recovery.** Every `ks.recover.<op>` is bound to a `ks.approve{plan_id, plan_hash, steps}` record (`test_recover_bound_to_approval`).

**10. Denials and bypass.** Every deny and hold is a sealed record with `decision`, `Reason`, `policy_rule` and no effects. Attribution uses `attributed_agent` only. `workspace/` is 0700 and `state.db` 0600, gateway uid. If perms are relaxed, reconcile flags an off-log version as class U: hard alert, `root_candidates` empty, `evidence_seqs=(alert.seq,)`; nobody is suspended (RT1b).

## Consequences
- Fail-closed: a new tool is dead until classified and scoped.
- Early hold over-holds; false-positive cost is scored.
- F3 (in-scope PII email) is stopped by ADR-04's `inv.pii_egress` on the queued item.
- U on bypass is detection only when perms are relaxed.

## Interface touched
C1 (expiry 8, nonce, epoch), C2 (`Decision`, `Reason`, `late_frame`, `policy_rule`), C3 (`field_obj_id`, read/write sets, `OutboxItem`), C4 (Control, deny-list incl. `conn:`), C5 (taint input, `ks.approve`), C6 (`hold_window_ticks`, `sensitive_fields`). CON-02 asks: `field_obj_id`, system tool ids, `SYSTEM_CONN`.

## Tests that prove it
- **RT1** a strict / b relaxed: reconcile hard alert within 1 tick, no honest suspension.
- **RT3** 0 exec from the suspended connection; **RT3c** forged Control: 0 applied.
- **RT5** (`between_check_and_txn`): 0 exec with `seq > q`; `test_crash_commit_append`; `test_depth_6kb_denied`.
- `test_catalogue_covers_world`, `test_scope_table`, `test_sensitive_field_object`, `test_action_id_reuse`.
- `test_early_hold_non_iban` (non-IBAN config), **RT10** hold 0 vs >0, **RT11b** fresh-epoch release keeps tainted items held, `test_recover_bound_to_approval`.

## Amendments (Call #2)
- G1/G2: full catalogue, email = I1, `ks.*` rows, role scope table (Kabir M1).
- G3: early hold at creation by lineage, off at H=0, hold is a Control (M2).
- G4, D5, D4: `ks.dispatch` records; connection deny-list; release = fresh epoch, suspension holds only (M3-M5).
- G5, G7, E1, D2, C2: seq at txn start, `between_check_and_txn`, system-id rules, expiry before nonce, `late_frame` (M6-M8).
- B1/X1/X2: field objects and read rules. G6: approval binding. IBAN marking dropped from `crm.update_supplier`.
- Integration pass: outbox enqueue (step 9) is covered by the exec record's `write_set` (outbox object versions).
