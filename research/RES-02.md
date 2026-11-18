# RES-02: Compensation, sagas and irreversible actions: a reversibility taxonomy for agent effects

Owner: meera. Reviewer: anaya. Read 19 Nov 2026. Method note: sources were read via the WebFetch tool, which returns model-summarised page content; quotes below are the ones the tool returned, and numbers should be re-checked in the PDFs before Aarav quotes them.

## 1. TL;DR

- **Every "undo" mechanism in the literature classifies the effect before it runs, not after.** Sagas split steps into compensable / pivot / retryable [3]; GoEx ties undo to what access the runtime has [2]; Atomix and Cordon stage or gate effects by class [8][9]. Our recorder must capture the class and the compensator at action time, or recovery is guesswork.
- **Compensation is semantic, not a snapshot restore.** Sagas' C_i "semantically undoes" T_i without restoring the old state, because other transactions may have changed it [1][4]. Same-shaped warning for us: restoring a snapshot overwrites other agents' work [4][7].
- **The saga literature admits the exact gap we are in:** when a compensation runs, the system makes no effort to notify or abort transactions that already read the partial result [1]. "Agent B consumed agent A's bad write" is that case. Nobody hands us a fix; the dependency record is what we have to build.
- **Irreversible effects are only safe if held back until validated** (Cordon outbox, Atomix commit gate) or confined by capability (GoEx blast radius) [2][8][9]. Pre-execution gating belongs in Containment.
- Recent agent-transaction work (Feb to Oct 2026) is a preprint wave, not settled practice; useful as design vocabulary, not as proof.

## 2. Findings

1. **[Fact]** A saga is a long-lived transaction split into smaller transactions, each with a compensating transaction C_i that "semantically undoes" T_i's effects, not necessarily restoring the earlier state; the airline example cancels a reservation rather than resetting the seat count [1] (Garcia-Molina and Salem, Princeton, ACM copyright 1987; the page did not name the venue).
2. **[Fact]** The Sagas paper says compensation is hard in general (its example: a fired missile cannot be reversed) and suggests follow-up actions (a second letter, a stop-payment message), or avoiding aborts so forward recovery suffices [1].
3. **[Fact]** Sagas give no isolation: other transactions can see a partial saga's effects, and on compensation "no effort" is made to notify or abort transactions that already read them [1]. Microsoft's pattern page lists the same anomalies: lost updates, dirty reads, fuzzy reads, with countermeasures (semantic lock, commutative updates, pessimistic view, reread values, version files) [3].
4. **[Fact]** Microsoft's saga page defines compensable transactions, a **pivot** transaction (point of no return; "after a pivot transaction succeeds, compensable transactions are no longer relevant"), and retryable transactions (idempotent, after the pivot) [3].
5. **[Fact]** Compensating Transaction pattern: record each step's state and its compensating action as it runs; compensation steps may fail so must be idempotent; undo order need not be exact reverse; "Some actions have external side effects or legal consequences that can't be reversed"; run irreversible steps only after critical validations pass; restoring a snapshot can overwrite concurrent changes; sometimes only manual intervention works and the system should alert with detail [4].
6. **[Fact]** Temporal's saga write-up: compensations must cope with "the possibility that what you want to compensate for may or may not have executed"; "undoing the state changes is different from rolling the database back to a previous snapshotted state"; compensations may not run if a Workflow times out [7].
7. **[Fact]** Event sourcing: the append-only store is the system of record; "The only way to update an entity or undo a change is to add a compensating event"; the original event stays in the stream; fixing application code does not fix historical bad events; handlers must be idempotent or side effects such as payments fire twice [5].
8. **[Fact]** GoEx (Patil et al., arXiv 2404.06921, 10 Apr 2024) proposes post-facto validation via **undo** and **damage confinement** [2]. Per the Berkeley blog, undo feasibility depends on privilege: file systems and databases with root access can undo; Gmail-like services "may be limited or require alternative approaches"; email cannot be unsent after a while, so confinement (e.g. read but not send) is used; blast radius is "a quantification of the user's risk appetite" [6]. The blog gives no method to measure blast radius or decide reversibility generally [6].
9. **[Fact]** Atomix (arXiv 2602.14849v2, 29 May 2026) logs reads and effects, seals a transaction when its footprint is complete, and commits only when per-resource frontiers show no earlier conflicting work can still arrive. At commit, bufferable effects are released, reversible external effects accepted, irreversible ones allowed out; on abort, unreleased effects are suppressed and externalised reversible ones compensated where possible [8]. Results reported only qualitatively in the fetched abstract (clean recovery under injected faults; irreversible actions "correctly classified" do not leak) [8].
10. **[Fact]** Cordon (arXiv 2606.17573v1, 16 Jun 2026, EuroSys '27 format) splits effects into **local mutations** (shadow state, promoted on commit) and **external effects** (outbox, released after validation). Outbox entries record sink, payload lineage, authority state, idempotency key, release status. "Committed external effects cannot later be treated as ordinary recoverable state"; they are recorded for audit or compensation [9]. Reported: plain execution committed policy-violating effects in 45/45 risk-bearing workflows; existing-defence adapters intercepted 14/45 before commit; Cordon 45/45; median rollback 4.17 ms with 0 residual deltas vs git restore/reset leaving a median of 73 residual deltas (deterministic trajectories) [9]. Authors' own benchmark, preprint, not independently verified.
11. **[Fact]** "Tracking State Footprints" (arXiv 2610.03140v1, 2 Oct 2026) argues agents need database-like guarantees, frames each agent by its read/write "state footprint", and notes agents cannot be deterministically replayed [10]. The fetched abstract does not describe how undo works [10].
12. **[Our view]** Classification is per action instance, not per tool. `delete_file` is reversible if the file is in a versioned store, irreversible if not; `send_email` is irreversible, but "send to internal sandbox address" is not. GoEx's point that reversibility depends on access [6] supports this.
13. **[Our view]** "Compensable" must be split in two for rollback to work with other agents' dependent work: compensation that is **safe under concurrent readers** (commutative, e.g. cancel) vs not (overwrite). The sources do not spell this split out; this is our inference from [1][3][4].

## 3. Taxonomy table

| Class | Example agent actions | Recovery strategy | Must be logged BEFORE the action runs |
|---|---|---|---|
| **R: Reversible** (we hold a pre-image) | Write/delete a file in a versioned repo; DB row update in a store with history; config change in IaC | **Restore** the pre-image, then check for later writers (see worked example) | Agent ID, resource ID, pre-image or version pointer, read set of the action, timestamp, parent action |
| **C: Compensable** (a semantic inverse exists, state not restored) | Reserve/cancel booking; create/delete ticket; issue refund; revoke a granted permission; post-then-retract message in a system that supports retraction | **Compensate** with a registered idempotent inverse C_i [1][4]; or **re-execute** if the action is idempotent and deterministic | Action args, the compensator (name + args), idempotency key, who may invoke it, expiry window of compensability |
| **I1: Irreversible but containable** (effect left our boundary, can be quarantined or followed up) | Email/Slack to external party; payment; webhook; public API write | **Quarantine** consumers of the effect; follow-up action (correction notice, stop-payment) [1]; manual escalation [4]. Better: hold in outbox until validated [9] | Destination sink, payload hash, authority used, idempotency key, release status, approver, blast-radius estimate |
| **I2: Irreversible and uncontainable** | Destroying the only copy of data; actions with legal effect | **None** after the fact. Only gating: deny, or require human approval, before it runs [2][4] | Same as I1 plus explicit "no undo" flag and the approval record |
| **U: Unclassified/unmediated** | Tool we cannot wrap; shell with raw network | Treat as I2 by default; reject or log a boundary violation (Cordon's treatment) [9] | The fact it was unmediated |

[Our view] The class column is ours (the saga literature has compensable/pivot/retryable [3]; GoEx has undo/confinement [2]; Cordon has local/external [9]). The mapping to the five recovery strategies named in the issue (restore / compensate / re-execute / quarantine / none) is our synthesis.

## 4. Worked example: agent A's bad write consumed by agent B

Setup (illustrative, ours): agent A writes `risk_limit = 5,000,000` (should be 500,000) to a shared config store (class R, pre-image logged). Agent B reads it at t+2 min, computes exposure for 40 accounts, writes a report, and sends a summary email to a manager (class I1). Agent C, unrelated, writes to the same store at t+3 min on a different key.

Detection at t+10 min. Options for B's dependent work, with trade-offs:

| Option | What happens | Gain | Cost / risk |
|---|---|---|---|
| 1. Snapshot restore to before A's write | Whole store goes back to t | Simple, fast | Discards C's valid write and anything else after t: collateral loss. Overwrites concurrent work [4][7] |
| 2. Revert A's write only, leave B alone | Pre-image restored for A's key | Keeps C | B's report and email still embed the bad value: residual damage. Sagas make no effort to notify earlier readers [1] |
| 3. Revert A, mark B's outputs tainted, **re-execute B** | Needs B's read set recorded; B re-runs on corrected input | Clean results if B's step is idempotent and its inputs are recorded | LLM agents are not deterministically replayable [10]; B may produce different output and different side effects. Re-running must not re-fire the email [5] |
| 4. Revert A, **compensate** B's effects | B's report deleted or superseded; correction message sent about the email | Works for class R and C outputs; honest audit trail (compensating event, original stays) [5] | Correction does not unsend the email (I1). Requires registered compensators |
| 5. Revert A, **quarantine** B's outputs for human review | B's report and downstream readers frozen | Safe when B's class is uncertain | Slow; human in loop. Matches manual-intervention guidance [4] |
| 6. Prevent: gate B's email until A's write is validated | B's email sits in outbox | Zero residual damage for I1 | Latency; needs the gate to know the write is unvalidated [8][9] |

[Our view] Best default: 2 + taint-propagation + 4 for R/C effects, 5 for I1 effects already out, and 6 going forward. This only works if the Recorder has B's read set (that B read A's key at t+2). Without it you can only do 1.

## 5. Implications for our design

**Recorder (feeds Recovery).**
- **Build:** at action time, log agent ID, resource, class (R/C/I1/I2/U), pre-image pointer or compensator, idempotency key, **read set and write set** (the Atomix/State Footprints idea [8][10]). The tool wrapper writes this, not the agent.
- **Reuse:** append-only compensating-event discipline from event sourcing: never edit history, add a compensating record [5].

**Recovery.**
- **Build:** a recovery planner that, given "undo agent A's action X," walks the dependency graph to B and C and outputs per-dependent plans from the options above, with an estimate of residual damage vs collateral loss. This is the piece the saga literature explicitly lacks [1].
- **Build:** compensators that are idempotent and logged as they run, resumable after failure [4].
- **Avoid:** whole-store snapshot restore as the primary path [4][7]; assuming deterministic re-execution of LLM agents [10].

**Containment: pre-execution gating.**
- **Build:** a chokepoint that refuses to run an unclassified tool call (class U treated as I2) [9], holds I1 effects in an outbox until a validator or timer passes, and requires human approval for I2 [4][9].
- **Build:** "pivot" markers: once an irreversible step is done, the recovery plan for that task changes from compensate to forward-recover or escalate [3].
- **Reuse:** GoEx's confinement idea (capability scoping, e.g. read mail but not send) as the revocation action when an agent is quarantined [2][6].
- Quarantine of agent A should also freeze **outbox entries derived from A's outputs** (taint through lineage; Cordon keeps payload lineage per entry [9]).

**Evaluation harness.** Score each rollback by residual damage and collateral loss (defined in the plan, Q8); the worked example above is a ready test scenario.

## 6. Implications for framing (bullets only)

- Fact for the hook: Sagas (1987) already say that when you compensate, nobody tells the transactions that read the partial result [1]. Agents recreate this at machine speed.
- Contrast: single-agent frameworks undo "a transaction"; the jury's scenario needs "undo one agent among ten." Cordon and Atomix are per-task transactions [8][9]; we found no source among these that does per-agent attribution plus cross-agent dependency (not exhaustive).
- Cordon's reported 45/45 vs 14/45 interception is a vivid number, but it is the authors' own benchmark [9]; say so if used.

## 7. Open questions

- Are Atomix and Cordon open source and runnable offline? Not checked (RES-05 / RES-06).
- Real incidents: were any recoveries compensation-based vs backup-based? (RES-07)
- Retro/Warp re-execution mechanics for the "re-execute B" option (RES-01).
- Atomix exact numbers (abstract gives only qualitative claims) and the full Cordon/State Footprints text: read the PDFs before quoting.
- The Sagas paper venue was not named in the fetched copy; confirm citation before use.

## 8. Sources

1. Garcia-Molina, Salem. "Sagas", Princeton, ACM (c) 1987. https://www.cs.cornell.edu/andru/cs711/2002fa/reading/sagas.pdf (primary).
2. Patil et al. "GoEX: Perspectives and Designs Towards a Runtime for Autonomous LLM Applications", arXiv 2404.06921v1, 10 Apr 2024. https://arxiv.org/abs/2404.06921 (primary; only abstract read).
3. Microsoft Learn, "Saga design pattern", Azure Architecture Center. https://learn.microsoft.com/en-us/azure/architecture/patterns/saga (primary vendor docs; undated).
4. Microsoft Learn, "Compensating Transaction pattern". https://learn.microsoft.com/en-us/azure/architecture/patterns/compensating-transaction (primary vendor docs; undated).
5. Microsoft Learn, "Event Sourcing pattern". https://learn.microsoft.com/en-us/azure/architecture/patterns/event-sourcing (primary vendor docs; undated).
6. Berkeley Gorilla blog, "GoEX". https://gorilla.cs.berkeley.edu/blogs/10_gorilla_exec_engine.html (secondary to [2], first-party by the authors' group).
7. Temporal blog, "Compensating Actions, Part of a Complete Breakfast with Sagas". https://temporal.io/blog/compensating-actions-part-of-a-complete-breakfast-with-sagas (vendor blog, secondary).
8. Mohammadi et al. "Atomix: Timely, Transactional Tool Use for Reliable Agentic Workflows", arXiv 2602.14849v2, 29 May 2026. https://arxiv.org/abs/2602.14849 (primary, preprint; abstract-level read).
9. Chen et al. "Cordon: Semantic Transactions for Tool-Using LLM Agents", arXiv 2606.17573v1, 16 Jun 2026, via https://www.alphaxiv.org/abs/2606.17573.md (primary, preprint; read via alphaxiv mirror).
10. Mraz et al. "Tracking State Footprints: How Agents Can Transact", arXiv 2610.03140v1, 2 Oct 2026. https://arxiv.org/abs/2610.03140 (primary, preprint; abstract-level read).
