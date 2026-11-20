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
- The bounded backward walk seeds from the alert's `evidence_versions` (ADR-05 §4, CALL-02 X3); `t0_seq_est` is its output, not its seed. An agent's recorded read set includes that tick's `TickFrame.view` entries (ADR-05 §3, resolution I1). RunConfig is never read.

**3. Hard versus soft, and who gets suspended** (D7). Auto-action needs `hard` and a kind in `HARD_ALLOWED`.
- SCOPE and I-class INVARIANT (including `iban_checksum`, `pii_egress`): auto-suspend `root_candidates[0]`.
- RECONCILE: hard alert, suspends nobody.
- SIGNATURE: suspends the **connection** only (`conn:<id>`), never the claimed agent.
- TAMPER and WITNESS_STALL (`hard=False`): recovery **freezes automatically by kind**, from chained `ks.alert` records, for the rest of the run. Nobody is suspended or named.
- ANOMALY, RATE and `barrier.deadline`: alert only, one click to act.
- **Read-reached agents are never auto-suspended.** A laundered honest writer is suspended and counted in `false_accusations`. In RT9, crm (the writer) is `[0]` and intake is in the top 3.

**4. Suspend bumps the epoch.** `Control{op=suspend}` is a signed, recorded envelope issued by the monitor. Epochs start at 0 and are strictly monotonic per principal: suspend, revoke and release each set a new maximum, and verify folds them. Stale-epoch envelopes are denied, which fences in-flight work. The connection joins the deny-list (ADR-03 step 7 (conn deny-list) and the step-13 txn). A suspended agent's `act_chain` descendants are denied as revoked ancestors.

**5. Per-action lineage hold and unhold.** On an alert the gateway marks the seed versions tainted.
- A new action whose recorded read set touches a tainted version is held at policy time: that **is** the `hold/lineage_hold` record (ADR-03 `p.lineage_hold`).
- `Control{op=hold, target=action:<rid>|outbox:<id>}` is only for items already queued when the alert lands.
- `unhold action:<rid>` re-executes the same envelope through epoch, deny-list, class, policy and taint, **without** nonce or expiry, and writes a new record linked by `envelope_hash`. An unheld outbox item returns to `queued` for the dispatcher re-check.
- Agent-declared lineage and `act_chain` are never used for taint (D8). Untainted work from the same agent proceeds.

**6. Release and revoke.** **Release** makes the agent active again at a **fresh, strictly higher epoch** (never the pre-suspend one, so presigned envelopes stay dead). Agents learn it through `TickFrame.epoch`, which is None while suspended or revoked. Release lifts **suspension holds only**; lineage and sensitive-field holds survive and are re-checked at dispatch, so the RT11 victim's tainted payment stays held. Items whose taint a human cleared leave the hold. **Revoke** is never automatic; only `ks.operator` issues it (D7). "Incident console" names only the read-only page.

**7. Hold window (D10).** *(Amended 20 Nov, B3-51; see Amendments (B3-51) below. Original text struck: "H is the only knob ... At H=0 there is no hold and an escaped payment is scored as residual damage.")* `RunConfig.hold_window_ticks` H sets the **time window** only: outbox items wait H ticks, and a lineage sensitive version delays release to `v+2H` (ADR-03) or, if it changes after creation, triggers the `sensitive_field` early hold. H=0 drops the window and the early hold. It does **not** drop the lineage hold (§5): that is alert-driven containment, independent of H, and it applies to any item whose lineage is tainted when it is released. Residual damage at H=0 therefore means effects dispatched **before** the alert. The demo uses H=6, asserted at least the maximum detection latency. The D10 "no hold at all" contrast is a separate, recorded switch: `RunConfig.lineage_hold = false` (contracts 1.6.0), set only by `ks run --hold 0 --no-lineage-hold` and allowed only with H=0. It is covered by `config_hash`; verify reads it, does not count the taint flag against a dispatch in that run (all other F4 checks still apply), and verify, console and score print the "NO-LINEAGE-HOLD contrast run" banner.

## Consequences
- An attacker cannot frame an honest agent by forged signatures, tampering, or by making an honest agent pay a poisoned payee: suspension follows the writer of the evidence, never the payer or a reader.
- Attribution is a heuristic. A laundered honest writer is a counted false accusation; ties and no-writer cases go to a human.
- Checksum-valid poisoned data passes until the beneficiary or ledger detectors fire; the hold window is the backstop.

## Interface touched
**C4** (Alert, Control; `hard=False` for tamper and stall; validator; docs for root_candidates[0], monotonic release, empty-evidence cases), **C2** (`attributed_agent`, `read_set`, `write_set`, `sig_ok`), **C3** (`OutboxItem.lineage`, field objects, side-store values), **C5** (taint seeds, `t0_seq_est`), **C6** (`hold_window_ticks`; v1.6 `lineage_hold`, B3-51). Transport: `TickFrame.epoch`. No new contract fields; `suspect` stays derived.

## Tests that prove it
- **RT9**: crm `[0]`, intake in the top 3, with EVIL IBAN caught by the beneficiary detector.
- **RT10** (F2+ hero): at H>0, `irreversible_tainted_released == 0` and lineage holds exist only on items whose read set touches tainted versions. *(Amended B3-51.)* At H=0 the lineage hold still applies, so residual is only what left before the alert. The D10 contrast run (`--hold 0 --no-lineage-hold`, `lineage_hold = false` in config.json) scores `irreversible_tainted_released >= 1` and `R.n > 0`, verifies exit 0 anchored with the banner, and the same records under `lineage_hold = true` fail verify with `window_violation` (anchored relabel: `config_mismatch`).
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
- Integration pass: walk seeds from `evidence_versions`, `t0_seq_est` is the output; read set includes `TickFrame.view` entries.

## Amendments (B3-51, 20 Nov; maya + kabir, done openly)
- **§7 was wrong, the code was right.** Nisha's B3-51 run showed that at H=0 the F2+ payment is still lineage-held: the alert lands in the same tick as the enqueue, before the next release phase. Kabir's B3-51 review ruled: "The lineage hold (s5) is containment driven by the alert and does not depend on H; H only sets the window and the sensitive-field early hold." §7 and the RT10 line are amended to match; "H is the only knob" is withdrawn.
- **The contrast is recorded, not hidden.** A run without the lineage hold is a configuration, so it lives in `RunConfig` (contracts 1.6.0, additive `lineage_hold: bool = True`, validator: `false` needs H=0), not in an in-process flag. Agents cannot reach it (only the CLI in the parent sets it).
- **Verify does not call the contrast run tampering.** In a `lineage_hold = false` run, `window_pass` skips only the taint flag; unrecorded items, double dispatch, release tick, recorded holds and author suspensions stay `window_violation`. `VerifyReport.lineage_hold` echoes the config; verify, console and `ks score` (`lineage_hold`, `contrast` keys) show `NO_LINEAGE_HOLD_BANNER`.
- Alternative kabir named (a CALL decision to drop D10) not taken: the contrast is kept, labelled.
