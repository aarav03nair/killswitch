# ADR-04: Monitor detectors, graded containment and lineage hold

**Owner:** nisha · **Reviewer:** maya · **Status:** in review · **Inputs:** CALL-01, PANEL-ENG-00, THREAT-MODEL v3, CON-01

## Context
Signatures and policy cannot see a valid-looking action that carries bad data. A rogue agent writes a poisoned value through its own scope, honest agents consume it, and the effect leaves. The monitor must therefore (1) detect from data invariants rather than from "who looks odd", (2) attribute separately and with humility, (3) contain in graded steps, and (4) stop tainted irreversible effects per action, not per agent. Anti-framing is a hard constraint (D7): an attacker must not be able to make us suspend an honest agent. TTC is redefined (PANEL 1.2): the targets are 0 post-alert tainted effects and 0 irreversible tainted effects released.

## Decision
**1. Detector catalogue** (`ks.monitor`, pure functions over records and side-store values, no LLM). Each emits an `Alert` with a `detector` id, `evidence_seqs` and `evidence_versions` (the taint seeds).

| Detector | Kind | Hard |
|---|---|---|
| `inv.iban_checksum` (format and mod-97) | INVARIANT | yes |
| `inv.beneficiary_changed_then_paid` (payee field changed, then a payment to it, within a window) | INVARIANT | yes |
| `inv.price_vs_history` (delta against the frozen baseline) | ANOMALY | no |
| `inv.ledger_balance` (debits equal credits) | INVARIANT | yes |
| `scope` (write outside the agent's scope) | SCOPE | yes |
| `reconcile` (fold(record) differs from live state: unmediated write, class U) | RECONCILE | yes |
| `sig`, `verify`, `witness_stall` | SIGNATURE, TAMPER, WITNESS_STALL | yes |

A checksum-valid EVIL IBAN passes `iban_checksum`; the beneficiary-changed-then-paid detector is what catches it (RT9, RT11).

**2. Detect, then attribute.** Detectors never name anyone. After an alert fires, `attribute()` walks backward taint from `evidence_versions` over recorded `write_set` and `read_set` entries to the writers of those versions. It ranks `root_candidates` by earliest causal write, then by the number of tainted descendants, with the agent id taken only from `rec.attributed_agent`. The "suspect" is `root_candidates[0]`, derived and never stored as a verdict. In RT11 payments is the victim, because the paying action is the *evidence* and not the *origin*. Backward taint ranks R first, and an auto-suspend acts only on the origin of a hard alert, never on an agent merely named as evidence.

**3. Hard versus soft.** Auto-action requires `hard` and a kind in `HARD_ALLOWED` (D7).
- SCOPE, I-class INVARIANT and RECONCILE (class U): auto-suspend `root_candidates[0]`.
- SIGNATURE: suspend the **connection** only (`conn:<id>`), never the claimed agent.
- TAMPER: freeze recovery (`ks recover --dry-run` returns `Exit.FROZEN` until the alert is resolved). It suspends nobody and names nobody.
- WITNESS_STALL: same as tamper.
- ANOMALY and RATE: alert only, one click to act.
- If attribution is empty or tied for first, the monitor holds by lineage but does not suspend. It escalates to the console.

**4. Suspend bumps the epoch.** `Control{op=suspend}` is a signed, recorded envelope that raises the target's epoch. Stale-epoch envelopes are denied, which also fences in-flight work. A suspended agent's `act_chain` descendants are denied as revoked ancestors (RT12).

**5. Per-action lineage hold.** On an alert the gateway marks the seed versions tainted. Any later action, or any pending outbox item, whose **recorded** `read_set` (`OutboxItem.lineage`) touches a tainted version is held with `Control{op=hold, target=action:<record_id>|outbox:<id>}`. Agent-declared lineage and `act_chain` are never used for taint (D8). Untainted work from the same agent proceeds.

**6. Release and revoke.** `release` is `unhold` plus restoring the pre-suspend epoch, after the human decision. Items whose taint was cleared leave the hold. `revoke` is never automatic; only `ks.console` can issue it (D7), and a revoked agent's `act_chain` descendants stay denied.

**7. Hold window (D10).** `RunConfig.hold_window_ticks` is the only knob. Outbox items wait that many ticks before dispatch, which gives detectors time to land. At 0 there is no hold and an escaped payment is scored as residual damage.

## Consequences
- An attacker cannot frame an honest agent by forging signatures, by tampering, or by making an honest agent pay a poisoned payee, since suspension follows the origin and not the evidence.
- Attribution is a heuristic; ties go to a human, and false positives are scored (`fp_cost`).
- Checksum-valid poisoned data still gets through until the beneficiary or ledger detectors fire, and the hold window is the backstop.

## Interface touched
**C4** (Alert, Control: produced here), **C2** (reads `attributed_agent`, `read_set`, `write_set`, `sig_ok`), **C3** (`OutboxItem.lineage`, side-store values), **C5** (taint seeds feed `TaintSet`), **C6** (`hold_window_ticks`). C1 only for `epoch` and `act_chain`. No contract field changes proposed. The task description names a `suspect` field; the contract has none, so it is derived from `root_candidates[0]`.

## Tests that prove it
- **RT9** (laundering via ticket): checksum-valid EVIL IBAN is caught by the beneficiary detector, and rogue A is in the top 3 of `root_candidates`.
- **RT10** (F2+ hero): at hold>0, `irreversible_tainted_released == 0` and lineage holds exist only on items whose recorded read set touches tainted versions; at hold=0 the damage is scored as residual.
- **RT11** (framing DoS): payments (victim) is not suspended; the rogue ranks first. Bad-sig floods suspend only the connection and `false_accusations == 0`.
- **RT12** (persistence): after suspend then revoke, docs' `act_chain` descendants and queued items are denied or held for P ticks, and the stale epoch is rejected.
- Unit: an ANOMALY alert cannot set `hard`; a tamper alert freezes recovery with zero suspensions; release restores the epoch.
