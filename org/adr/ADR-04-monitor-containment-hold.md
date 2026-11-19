# ADR-04: Monitor detectors, graded containment and lineage hold

**Owner:** nisha · **Reviewer:** maya · **Status:** in review · **Inputs:** CALL-01, THREAT-MODEL v3, CALL-02 resolutions (freeze), contracts 1.1.0

## Context
Signatures and policy cannot see a valid-looking action that carries bad data. A rogue writes a poisoned value through its own scope, honest agents consume it, and the effect leaves. The monitor must (1) detect from data invariants, not from "who looks odd", (2) attribute separately and with humility, (3) contain in graded steps, and (4) stop tainted irreversible effects per action, not per agent. Anti-framing is a hard constraint (D7): an attacker must not be able to make us suspend an honest agent. Targets: 0 post-alert tainted effects and 0 irreversible tainted effects released.

## Decision
**1. Detector catalogue** (`ks.monitor`, pure functions over records and side-store values, no LLM). Each emits an `Alert` with `detector`, `evidence_seqs`, `evidence_versions` (taint seeds). `test_hard_table` pins this table to the C4 validator.

| Detector | Kind | Grade |
|---|---|---|
| `inv.beneficiary_changed_then_paid` (payee field changed, then paid, within a window) | INVARIANT | hard |
| `inv.ledger_balance` (debits = credits) | INVARIANT | hard |
| `inv.iban_checksum` (mod-97) | INVARIANT | hard; justified because it guards a sensitive field that feeds I1 `payments.send` |
| `inv.pii_egress` (F3: a queued `comms.send_email` body carries PII) | INVARIANT | hard (I1) |
| `scope` (a sig_ok `deny/out_of_scope` record, ADR-03 `p.scope`) | SCOPE | hard |
| `reconcile` (fold(record) differs from state) | RECONCILE | hard; names nobody, so suspends nobody |
| `sig` | SIGNATURE | hard, **connection only** |
| `inv.price_vs_history` (vs frozen baseline), `rate`, `barrier.deadline` | ANOMALY, RATE | soft |
| `tamper`, `witness_stall` | TAMPER, WITNESS_STALL | **never hard** (dropped from `HARD_ALLOWED`) |

A checksum-valid EVIL IBAN passes `iban_checksum`; `beneficiary_changed_then_paid` plus the lineage hold catches it. Owner of `inv.pii_egress` is nisha; the cleartext pytest stays kabir's.

**2. Detect, then attribute.** Detectors never name anyone. `attribute()` takes the agent id only from `rec.attributed_agent`.
- **`root_candidates[0]` is the attributed writer of `evidence_versions`** (write_set lookup). The bounded backward taint walk then ranks the rest: agents reached only through read sets come after it.
- Two or more distinct writers, or none: no suspend. The monitor holds by lineage and escalates to the incident console.
- The suspect is `root_candidates[0]`, derived and never stored.
- Evidence conventions: `beneficiary_changed_then_paid` puts the **payee field object only** (for the hero, `suppliers:S-17.iban`, writer crm) in `evidence_versions`; the payment goes in `evidence_seqs`, so the payer is never a writer of evidence. `inv.pii_egress` seeds the queued `outbox:<id>` version, written by the emailing agent. `reconcile` has empty `root_candidates` and `evidence_seqs=(alert.seq,)`. The `scope` detector cites the denied record.
- The walk's seed is the earliest `t0_seq_est`; RunConfig is never read.

**3. Hard versus soft, and who gets suspended** (D7). Auto-action needs `hard` and a kind in `HARD_ALLOWED`.
- SCOPE and I-class INVARIANT (including `iban_checksum`, `pii_egress`): auto-suspend `root_candidates[0]`.
- RECONCILE: hard alert, suspends nobody.
- SIGNATURE: suspends the **connection** only (`conn:<id>`), never the claimed agent.
- TAMPER and WITNESS_STALL (`hard=False`): recovery **freezes automatically by kind**, from chained `ks.alert` records, for the rest of the run. Nobody is suspended or named.
- ANOMALY, RATE and `barrier.deadline`: alert only, one click to act.
- **Read-reached agents are never auto-suspended.** A laundered honest writer is suspended and counted in `false_accusations`. In RT9, crm (the writer) is `[0]` and intake is in the top 3.

**4. Suspend bumps the epoch.** `Control{op=suspend}` is a signed, recorded envelope issued by the monitor. Epochs start at 0 and are strictly monotonic per principal: suspend, revoke and release each set a new maximum, and verify folds them. Stale-epoch envelopes are denied, which fences in-flight work. The connection joins the deny-list (ADR-03 step 5 and the step-8 txn). A suspended agent's `act_chain` descendants are denied as revoked ancestors.

**5. Per-action lineage hold and unhold.** On an alert the gateway marks the seed versions tainted.
- A new action whose recorded read set touches a tainted version is held at policy time: that **is** the `hold/lineage_hold` record (ADR-03 `p.lineage_hold`).
- `Control{op=hold, target=action:<rid>|outbox:<id>}` is only for items already queued when the alert lands.
- `unhold action:<rid>` re-executes the same envelope through epoch, deny-list, class, policy and taint, **without** nonce or expiry, and writes a new record linked by `envelope_hash`. An unheld outbox item returns to `queued` for the dispatcher re-check.
- Agent-declared lineage and `act_chain` are never used for taint (D8). Untainted work from the same agent proceeds.

**6. Release and revoke.** **Release** makes the agent active again at a **fresh, strictly higher epoch** (never the pre-suspend one, so presigned envelopes stay dead). Agents learn it through `TickFrame.epoch`, which is None while suspended or revoked. Release lifts **suspension holds only**; lineage and sensitive-field holds survive and are re-checked at dispatch, so the RT11 victim's tainted payment stays held. Items whose taint a human cleared leave the hold. **Revoke** is never automatic; only `ks.operator` issues it (D7). "Incident console" names only the read-only page.

**7. Hold window (D10).** `RunConfig.hold_window_ticks` H is the only knob. Outbox items wait that long, and a lineage sensitive version delays release to `v+2H` (ADR-03). At H=0 there is no hold and an escaped payment is scored as residual damage. The demo uses H=6, asserted at least the maximum detection latency.

## Consequences
- An attacker cannot frame an honest agent by forged signatures, tampering, or by making an honest agent pay a poisoned payee: suspension follows the writer of the evidence, never the payer or a reader.
- Attribution is a heuristic. A laundered honest writer is a counted false accusation; ties and no-writer cases go to a human.
- Checksum-valid poisoned data passes until the beneficiary or ledger detectors fire; the hold window is the backstop.

## Interface touched
**C4** (Alert, Control; `hard=False` for tamper and stall; validator; docs for root_candidates[0], monotonic release, empty-evidence cases), **C2** (`attributed_agent`, `read_set`, `write_set`, `sig_ok`), **C3** (`OutboxItem.lineage`, field objects, side-store values), **C5** (taint seeds, `t0_seq_est`), **C6** (`hold_window_ticks`). Transport: `TickFrame.epoch`. No new contract fields; `suspect` stays derived.

## Tests that prove it
- **RT9**: crm `[0]`, intake in the top 3, with EVIL IBAN caught by the beneficiary detector.
- **RT10** (F2+ hero): at H>0, `irreversible_tainted_released == 0` and lineage holds exist only on items whose read set touches tainted versions; at H=0 it scores residual.
- **RT11a** (ADR-04 path, rogue `--slot crm`): `false_accusations == 0`. **RT11b** (operator suspends payments): fresh-epoch release, tainted items stay held. Bad-sig floods suspend only the connection.
- **RT12**: after suspend then revoke, descendants and queued items stay denied or held; stale epoch rejected.
- `test_hard_table`, `test_epoch_monotonic`, `test_f3_pii_egress_held`, and units: ANOMALY cannot be hard; tamper freezes with zero suspensions; two writers or none gives no suspend.

## Amendments (Call #2)
- H1: `root_candidates[0]` = writer of `evidence_versions`; bounded walk; two or more or none means no suspend (Maya 1).
- H2: read-reached agents never auto-suspended; laundered writer counted (Maya 1).
- H3: hard/soft table tied to D7; `iban_checksum` justified; tamper and stall never hard, freeze by kind to run end (Maya 5, 6).
- H4: beneficiary evidence is the payee field object only (Maya 2).
- H5: new `inv.pii_egress` for F3, owner nisha.
- D4, D1: release = fresh strictly monotonic epoch, suspension holds only (Maya 3, Kabir).
- Unhold semantics and policy-time hold = the `hold/lineage_hold` record (Maya 4). D5 connection deny-list; E1 system-id rules; E2 signer `ks.operator`.
- X1/X2: field objects are the evidence granularity. Same-name metric: `irreversible_tainted_released` (Maya 9).
