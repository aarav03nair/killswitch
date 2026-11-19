# ADR-03: Gateway, action classes R/C/I1/I2/U, policy and epoch fencing

Owner: nisha · Binding: CALL-01, THREAT-MODEL v3, contracts 1.0.0

## Context
Agents reach shared state only through the gateway (B1 untrusted, B2 TCB). Recovery needs a class, a read/write set and a recorded decision before each action runs (RES-02). Two races matter: a suspend landing while a write is in flight (RT5), and an irreversible effect leaving after its lineage turned bad (RT10). A rogue agent may also skip the gateway (RT1).

## Decision

**1. Pipeline (fixed order, first failure stops, every stop is recorded).**
1. frame decode: unparseable gives `deny/schema`, `envelope=None`
2. schema: unknown keys give `deny/schema`
3. signature against the claimed principal: `deny/bad_sig` (connection only)
4. nonce and expiry: `nonce_reused`, `expired`
5. epoch and deny-list (revoked/suspended agent or any `act_chain` ancestor): `stale_epoch`, `suspended`, `revoked`, `revoked_ancestor`
6. **classify per action instance**
7. policy (below)
8. execute in **one SQLite transaction** that begins by re-reading epoch and deny-list (step 5 is only a fast path)
9. seal record (gateway assigns `seq`, `ts`, `record_id`), then 10. enqueue outbox items.

The step-8 re-check is what closes RT5: the suspend commits as a Control write in the same store, so a write either commits before it (`seq < q`) or sees it and gets `deny/suspended` or `stale_epoch`. Presigned envelopes carry the old epoch and die at step 5 or 8. Per-tick quota gives `over_quota`.

**2. Classification.** Class is a function of `(tool, args, state)`, not of the tool name. Adapters declare it and emit the read and write sets; the agent reports nothing. The gateway derives the class before execution and records it. Any tool not in the catalogue, any adapter without a classifier result, or any classifier exception gives **U, `deny/class_u`**. U is never executable (rule 6). An agent's declared class is ignored.

**3. Demo-world catalogue.**

| Tool | Class | Note |
|---|---|---|
| `*.read`, `*.list`, `*.search` | R | reads only; read set recorded |
| `crm.update_supplier` | R | pre-image held; marks `suppliers.iban` sensitive |
| `triage.update_row`, `inventory.adjust`, `docs.write`, `billing.draft_invoice` | R | versioned rows |
| `ticket.create` | C | compensator `ticket.close` |
| `billing.issue_credit` | C | compensator `billing.reverse_credit` |
| `payments.send` | I1 | outbox, sink `payments` |
| `comms.send_email` | I1 | outbox, sink `email` |
| `docs.purge` (destroys only copy) | I2 | `hold/needs_approval`, runs only after an approved Control |
| `ks.control` | gateway-signed | rule 10; agents cannot submit it |
| anything else, raw SQL, shell, network | U | deny |

An R tool becomes U if its pre-image cannot be read.

**4. Policy** (rule ids are mine, `p.*`):
- `p.scope`: tool outside the agent's role gives `deny/out_of_scope`.
- `p.i1_outbox`: I1 never executes inline. The gateway writes an `OutboxItem` (`queued`, `release_tick = tick + hold_window_ticks`) whose `lineage` is the recorded read set. The agent gets `exec/ok` for the enqueue only.
- `p.i2_approval`: I2 gives `hold/needs_approval`.
- `p.lineage_hold`: an R/C write or I-class item whose recorded read set touches a tainted version gives `hold/lineage_hold` (D8). Agent-declared lineage is ignored.
- `p.sensitive_early_hold`: **generic**. If an action's *read set* includes an object whose `RunConfig.sensitive_fields` entry (`table.field`) changed after the item's creation, or the action writes one, every dependent outbox item goes `held/sensitive_field`. No IBAN or payments code exists in the rule; the IBAN appears only in config. Already dispatched items stay residual damage (D10).

**5. Dispatcher.** Each tick, for each `queued` item with `release_tick <= tick`, the dispatcher opens a transaction and re-checks: author epoch and deny-list, no `held` status, lineage still untainted, sensitive fields unchanged since creation. Only then `released` then `dispatched` (setting `dispatched_seq`). Failure leaves it `held` and records the reason. Holds are never cancelled here; `release` un-holds and restores the epoch, and only an approved `cancel_outbox` step cancels (C6). Idempotency key is gateway-derived.

**6. Denials.** Every deny and hold is a sealed record with `decision`, `Reason`, `policy_rule` and no effects (rule 11, enforced by `Record`). Attribution goes through `attributed_agent` only.

**7. DB bypass.** Gateway-owned `state.db` (0700, separate uid) blocks it. If perms are relaxed, reconciliation (state = fold(record)) flags an off-log version as class U, hard alert, `Alert.suspect` null; no honest agent is suspended (RT1b).

## Consequences
- Fail-closed: a new tool is dead until classified.
- The in-transaction re-check serialises writers; cheap on SQLite.
- Early hold over-holds (conservative, consistent with over-taint); false-positive cost is scored (RT11).
- Dispatched items are out of reach.
- U on bypass is detection, not prevention, where perms are relaxed (C2 wording).

## Interface touched
C1 (epoch, expiry, nonce consumed), C2 (`Decision`, `Reason`, `ActionClass`, `policy_rule`), C3 (read/write sets, `OutboxItem`, `idempotency_key`), C4 (Control epoch fencing, reconcile alert), C6 (`hold_window_ticks`, `sensitive_fields`). C5 is read-only here (taint set input). No contract field changes are needed.

## Tests that prove it
- **RT1** (a strict: `bypass_fail`; b relaxed): reconcile hard alert within 1 tick, `Exit.RECONCILE`, no honest agent suspended.
- **RT5** (`GatewayHooks.pause_in_txn`): 0 `exec` records for the culprit with `seq > q`; 0 outbox dispatches after `q`; at most 1 exec per tick.
- Unit: unknown tool, classifier exception and unreadable pre-image give `deny/class_u`; every denial reason yields a record.
- Unit: sensitive-field change holds dependent items with a config that names a non-IBAN field (proves genericity).
- Unit: dispatcher refuses a `queued` item after a taint or suspend arrives between enqueue and release (rule 5); RT10 hold 0 vs >0.
