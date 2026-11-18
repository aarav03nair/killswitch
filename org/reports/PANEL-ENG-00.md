# PANEL review of ENG-00 (STRAWMAN.md)

Reviewer: panel · 19 Nov · Verdict: **changes**. RES-08 not yet present; not used.

## 1. Against the three metrics

1.1 **TTI is weakest on the hero fault.** Rules on deny bursts, scope and rate cannot see F2: a wrong IBAN from crm is an in-scope, normal-rate write. "Attribution comes free" only after a bad effect is detected. Fix: split TTI into detect (data invariants: IBAN checksum, price delta vs history, ledger balance, "beneficiary changed then paid") and attribute (write_set lookup, O(1)). Report both.

1.2 **TTC is defined wrongly.** "Alert → culprit's last effective action" ends when the culprit stops, while honest agents keep spreading its data. Redefine: alert → first denied culprit envelope, plus **post-alert tainted effects** (by anyone) and **irreversible tainted effects released**. Target 0 for both.

1.3 **Recovery has two holes.** (a) Write-write conflict: if an honest agent later edited a row the culprit wrote, restoring the before-value clobbers it (RES-06 F5 shows Git conflicting on exactly this). Rule: restore only if current version == culprit's after-version, else re-run or flag. (b) Re-run can re-fire external effects (RES-02 §4, opt. 3): route re-runs through the outbox, deduped by idempotency key. Recovery appends compensating records, never edits history (RES-02 F7).

## 2. Eight ways the jury breaks it

| # | Attack | Handled? | Minimal change |
|---|---|---|---|
| 1 | **Gateway bypass / key theft.** Single process: a scripted rogue agent imports `sqlite3` or reads another agent's private key | No. "Only path" is convention | One subprocess per agent; workspace and keys readable only by gateway process. Add **reconciliation**: rebuild state from the log, diff against live state, alert on unmediated writes (class U) |
| 2 | **Log truncation / rewrite.** Recorder key and file sit in the attacker's process; tail since last signed head can be cut | Partly | Checkpoint head every tick to a separate witness process (RES-04 §4); `verify` prints first bad index |
| 3 | **Honest consumer → irreversible action.** billing reads bad IBAN, payments pays it | No. Only culprit's outbox is held | **Lineage hold**: on quarantine, freeze every outbox item whose payload lineage touches a tainted version (RES-02 §5, Cordon). Before quarantine: hold I1 items whose lineage has a beneficiary change younger than N ticks |
| 4 | **Laundering / collusion.** Culprit plants a ticket; a second agent makes the write | Partly (taint yes, attribution no) | Tickets/messages are objects in read sets; alert runs backward taint (Taser, RES-01 §2.4) and names root candidates, not just the writer |
| 5 | **Unrecorded or coarse reads.** `SELECT *`, KPI aggregates, LLM memory | Over-taint at best | Row-level read sets in adapters; aggregates over-taint and re-run (accepted, Taser conservative policy). State granularity in the ADR |
| 6 | **Slow drift (F7)** poisons the rolling baseline | Admitted failure | Freeze baselines from a trusted window; invariants catch drift at any rate. Demo point: late detection still yields clean recovery |
| 7 | **False positive quarantines a good agent** | No undo-of-containment | *Suspend* (writes held, reversible) before *revoke*. Auto only on hard evidence (bad signature, scope breach, tamper); anomaly = one click. `release` re-queues cancelled work. Score FP cost |
| 8 | **Race and clock games.** Policy passes, quarantine lands, action executes (TOCTOU); agent-chosen timestamps; replayed envelopes | No | Credential epoch (fencing token) checked inside the execution transaction. Gateway assigns time and `seq`. Nonce + expiry. Show: zero culprit writes after the quarantine `seq` |

## 3. Scope for 8 days + 5 minutes

3.1 **Cut:** LLM mode at finale; Dolt (RES-06 never ran it; SQLite + gateway row versions suffice); Merkle proofs; SPIFFE/token exchange (one mapping slide); OTel beyond one OTLP-JSON exporter. F3/F5/F6 become pytest cases.

3.2 **Keep:** gateway in subprocess isolation, recorder + witness + `verify`, invariant detectors, graded containment with lineage hold, taint planner with dry-run diff, scorer that recomputes metrics from ground truth, two baselines, `ks inject` CLI plus a rogue-agent template the jury can script.

3.3 **Hero scenario (F2+):** crm changes a supplier IBAN and one price ×10; billing, comms, payments and reporter consume it; inventory/docs are independent; triage later edits a crm-written row (conflict case). IBAN/beneficiary invariant fires → crm suspended → payment and email held by lineage → recovery reverts crm, re-runs billing/reporter, cancels the payment, keeps inventory/docs/triage. Scorecard vs both baselines; then the jury edits a log line and `verify` catches it.

3.4 Open Q5: the hold window is fair if shown both ways. With hold = 0 the payment escapes and is scored as residual irreversible damage; this pre-empts the "cheat" call.

## 4. Where research refines the strawman

4.1 RES-01 §4–5: replay does not transfer to LLM agents. Label step (2) deterministic-only; LLM mode becomes a re-plan-with-approval queue.

4.2 RES-02 §2.12–13, §3: classify per action instance, not per tool. Adopt R/C/I1/I2/U with U denied (fail-closed). Split compensable into safe and unsafe under concurrent readers.

4.3 RES-03 §4: verify and record the **whole** `act` chain; sign at agent and gateway. §2.10: where upstream uses one service credential, attribution lives only in our log. Say so.

4.4 RES-04 §1, §4: a bare chain does not resist whole-file rewrite; external anchor required. §5: store hashes in the log and values in a redactable side store. Otherwise before/after IBANs make the audit log a PII store, and F3 (exfiltration) leaks into the evidence.

4.5 RES-05 §1, §5: agentgateway already does identity-aware tool authz; novelty is quarantine linked to provenance and rollback.

4.6 RES-06 F4–F5: revert-one-keep-later exists in Dolt/Git; the gap is read dependencies. This confirms 1.3(a) as a must-fix.

4.7 RES-07 §1, §2.4: every real incident was single-agent; none had B building on A. "Which of ten" and dependent undo are evidenced by literature only. Incidents strongly support gating, scoped credentials and recording independent of self-report. Who&When (53.5% agent / 14.2% step, abstract) is a cited baseline, not run (offline rule).

## 5. Framing

5.1 "Attribution + containment" alone is safe but crowded (RES-05). "Selective undo" alone rests on A1 and on literature rather than incidents (RES-07).

5.2 Recommend a **provenance-first** frame. Every write has an author and every read has a source. Identify, contain and recover are then three queries on one graph: blame lookup, lineage hold, taint undo. Selective undo is the payoff shown in the demo, with honest limits (irreversible → report; LLM → re-plan).

5.3 It mirrors the brief ("what changed, who changed it, how fast can it be undone") and survives a partial A1 failure. Reconciliation (state = fold(log)) turns "audited, not demoed" into something the jury can run.

## 6. Must-fix in ADRs

Write-write conflict rule (1.3a); outbox-deduped re-run (1.3b); TTC redefinition (1.2); process isolation + reconciliation (2.1); witness checkpoints (2.2); lineage hold (2.3); graded containment + release (2.7); epoch fencing (2.8); invariant detectors (1.1).
