# TERMS: one name per concept (ABS-04; updated for the design freeze in ABS-08)

Owner: zoya · Reviewer: maya · 19 Nov 2026 · v2 · Inputs: CALL-01.md, contracts 1.1.0 (`src/ks/contracts`), ABS-04 review (maya), CALL-02.md + CALL-02/resolutions.md (v1.1.0 changes), CALL-02/anaya.md §2–4, SYNTHESIS §4/§6, PANEL-ENG-00, RES-02.

**Rule.** The abstract, diagram, demo narration, incident-console labels and code use the left-hand term and nothing else. If a banned synonym appears in a draft, reviewers flag it. Glosses are written for a banking reader and are at most 15 words. They are glosses, not abstract sentences: Aarav writes his own (CHARTER). Code names come from the frozen contracts 1.1.0 (`src/ks/contracts`), with CALL-02/resolutions.md ids for the v1.1 changes (marked **v1.1** with the resolution id). `⚠` marks a gap still open (see §7).

## 1. Actors and the mediated path

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **agent** | One automated worker (e.g. crm, billing), running in its own sealed process. | `agent_id` (C1); one subprocess per agent (`ks.runtime` spawns them) | bot, worker, assistant, AI |
| **culprit** | The agent whose faulty actions caused the damage, buggy or rogue. | `RunConfig.culprit` (C6, scorer-only, blanked in `tcb_view()`, A3); `RecoveryPlan.culprit` (C5, chosen by a person) | bad agent, attacker (unless the rogue scenario), offender, suspect (in the abstract) |
| **suspect** (incident console / internal only) | The top-ranked root candidate on an alert; an accusation, not a finding. | derived as `Alert.root_candidates[0]`; never stored (PMO accepted) | the whole term is banned in the abstract: use root candidates |
| **honest agent** | Any agent that is not the culprit, even if it read bad data. | none (scorer ground truth, C6) | innocent, good agent, victim |
| **gateway** | The single checkpoint every agent action must pass through before it touches anything. | `ks.gateway`; also runs the tick barrier (ADR-00) | proxy, middleware, broker, firewall, control plane |
| **trust boundary** | Line past which nothing an agent sends is trusted until the gateway checks it. | THREAT-MODEL §2, B1 (agent → gateway IPC) | perimeter, firewall, sandbox wall |
| **connection** | One agent process's line to the gateway; a bad signature suspends this, not the agent. | C2 `conn_id`; Control target `conn:<id>`; conns are 1:1, no reconnect (D5); `SYSTEM_CONN = "c-0"` for in-gateway system envelopes only (**v1.1**, E1) | session, socket (in prose), channel |
| **operator** | The person who approves plans, releases and revokes; each decision is a signed Control. | signer `ks.operator` (**v1.1**, E2; replaces `ks.console`, no alias, X7); `operator.sock` (J1). "Incident console" = the read-only page | admin, supervisor, `ks.console`, console (as the signer) |
| **action envelope** ("envelope" after first use) | A signed request from an agent: who, what, on whose behalf, valid when. | C1 `Envelope` {agent_id, action_id, parent_action_id, act_chain, tool, args, nonce, expiry_tick, epoch, claimed_ts_us, claimed_seq, sig}; recorded form `EnvelopeHeader` (args → args_hash) | request, message, call, payload, ticket |
| **act chain** | The chain of who asked whom, carried on every envelope. | C1 `act_chain: [ActLink{principal, action_id}]`, `parent_action_id` | delegation path, call stack, lineage (reserved, see §3) |
| **tick** | One scheduling round: each agent submits at most one envelope, run in fixed order. | C2 `tick`; barrier runs in the gateway (ADR-00), transport `TickFrame{tick, epoch, view}`; one frame per connection per tick (C2) | step, turn, cycle, round |
| **sequence number (seq)** | The gateway's own position number for each record; agents cannot choose it. | C2 `seq` (agent-sent `claimed_seq` is never used for ordering) | timestamp, index, offset, id |

## 2. The record and its audit

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **record** | The gateway-signed entry written for every action, including denials. | C2 `Record`; `ks.recorder`; `record.jsonl` | log, log line, audit log, journal, trace, event |
| **recorder** | The gateway component that writes records; agents never write their own. | `ks.recorder` | logger, tracer, auditor |
| **read set** | Exactly which data versions an action looked at, captured by the gateway. | C2 `read_set: [ReadEntry(obj, ver, hash)]`; a whole-row read also lists that row's field objects (**v1.1**, X2) | inputs, dependencies, sources, footprint |
| **write set** | Exactly which data an action changed, with before and after versions. | C2 `write_set: [WriteEntry]` (before/after ver + hash); actions write only changed objects (B1) | outputs, changes, diff, mutations |
| **provenance graph** | The map linking every change to its author and every read to its source. | none; derived from C2 read/write sets in `ks.taint` (confirmed: no graph type) | DAG, lineage graph, dependency graph, knowledge graph |
| **witness** | A separate process that countersigns the record's latest fingerprint every tick. | `ks.witness`; C2 `WitnessCheckpoint(seq, tick, head` [+ count, **v1.1**]`)`; `witness.jsonl` | notary, anchor, timestamp server, blockchain |
| **verify** | The audit check anyone can run to detect edited, missing or forged records. | `ks.verify`; CLI `ks verify RUN --head` (L3); `VerifyReport`, `RunAnchor` (**v1.1**, F1) | validate, audit (as a verb), check, prove |
| **tamper-evident** | Any edit up to the last witnessed point is detected; not prevented. | `ks.verify.Exit` (TAMPER) + `VerifyReport.first_bad` (a **seq**, not an index) + `last_witnessed_seq` | tamper-proof, immutable, unforgeable, secure log |
| **reconciliation** | Rebuild state from the record and compare to live data, catching bypass writes. | `AlertKind.RECONCILE`, detector `reconcile`, `Exit.RECONCILE`, C3 `state_digest`; class U; names nobody, so suspends nobody (H3) | replay, consistency check, diffing |
| **side store** | Separate store for sensitive values (e.g. IBANs); the record keeps only fingerprints. | C3 `SideStore` / `SideEntry`; run dir `sidestore/` | vault, PII store, cache |
| **workspace** | The shared data all agents work on, owned and changed only by the gateway. | `workspace/state.db` (C6 `STATE_DB`), `ks.state` (row-versioned SQLite, D5) | database (in prose), shared memory, environment |

## 3. Classes, holds and containment

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **action class** | Label fixed before an action runs, saying how it could ever be undone. | C2 `action_class: ActionClass`; assigned in `ks.gateway` / `ks.policy` | effect type, risk level, category |
| **class R (reversible)** | We hold the earlier version and can restore it exactly. | `ActionClass.R` | undoable, rollback-able |
| **class C (compensable)** | Cannot restore, but a registered opposite action exists (cancel, refund). | `ActionClass.C` | reversible (wrong), soft |
| **class I1 (irreversible, containable)** | Leaves our boundary (payment, email); can only be held or followed up. | `ActionClass.I1` → outbox | external, side effect |
| **class I2 (irreversible, uncontainable)** | No follow-up possible; runs only with prior human approval. | `ActionClass.I2` | destructive, critical |
| **class U (unclassified)** | Anything we cannot classify or that bypassed the gateway; denied by default. | `ActionClass.U`; `Reason.CLASS_U`; reconciliation mismatch | unknown, unsafe, shadow |
| **outbox** | Waiting area where irreversible actions sit until released; nothing leaves without it. | C3 `OutboxItem` (status queued / held / released / dispatched / cancelled); C2 `outbox_ids`; C5 `cancel_outbox` | queue, staging, buffer, sandbox |
| **idempotency key** | Tag on each outbox item so a re-run never sends the same effect twice. | C3 `OutboxItem.idempotency_key` + helper `idempotency_key()` | nonce (different purpose), dedupe id |
| **lineage hold** | Freeze any action or outbox item whose read set touches tainted data. | C4 Control `hold` / `unhold` (target = action or outbox id); `Decision.HOLD` / `Reason.LINEAGE_HOLD`; `OutboxStatus.HELD` | quarantine, block, freeze (as noun), gate, pause |
| **hold window** | How long new irreversible actions wait in the outbox. Demo shows 0 vs >0. | `RunConfig.hold_window_ticks` (demo H = 6, A6) | delay, cooling-off, grace period |
| **sensitive field** | A data field tagged so changes to it trigger an early hold (IBAN is one). | `RunConfig.sensitive_fields` (`'table.field'`); rule `p.sensitive_early_hold`; `Reason.SENSITIVE_FIELD`; each entry is a field object (**v1.1**, B1) | PII field, critical field, watched field |
| **field object** | A sensitive field versioned on its own, apart from the rest of its row. | object id `table:pk.field` (rest of row stays `table:pk`); C3 `field_obj_id` / `row_obj_id`; `split_obj_id` → (table, pk, field\|None); validator rejects `.` in a pk (**v1.1**, X1, B1). Whole-row reads include it; field-only edits do not bump the row (X2) | column object, cell, sub-row |
| **graded containment** | Stepwise response: suspend first, revoke only after a person confirms. | `ks.containment` | kill, shutdown, isolation, quarantine |
| **suspend** | Stop one agent (or connection) acting immediately; reversible by release. | C4 Control `suspend` (target agent_id or `conn:<id>`) | quarantine, kill, pause, freeze, disable, block |
| **revoke** | Permanently cancel an agent's authority, after human confirmation. | C4 Control `revoke` | kill, ban, terminate, delete |
| **release** | Lift a suspension; restores the agent's permissions (fresh epoch). Lineage holds stay. | C4 Control `release` (new epoch maximum; lifts suspension holds only, lineage / sensitive holds survive, D4); `unhold` for holds | resume, unblock, restore, un-quarantine, "restore / rewind the epoch" |
| **epoch** | A permission counter; each suspend, revoke or release sets a new value, voiding in-flight requests. | C1 `epoch`; C4 Control `epoch`; strictly monotonic per principal (D1); `TickFrame.epoch` None while suspended or revoked (**v1.1**, D3) | fencing token (internal ADR only), version, generation, session |
| **alert** | A detector's finding with evidence; "hard" alerts trigger automatic suspend. | C4 `Alert` {alert_id, tick, seq, detector, kind, hard, evidence_seqs, evidence_versions, root_candidates, conn_id}. Alerts are not signed (Controls are); scoring reads chained `ks.alert` records, never `alerts.jsonl` (X8) | alarm, incident, warning, flag (reserved, see §4), signed alert |
| **invariant detector** | A rule on the data itself (e.g. supplier IBAN changed without approval) that raises alerts. | `AlertKind.INVARIANT`; ids `inv.*` (ADR-04); `ks.monitor` | anomaly detector, AI monitor, classifier |
| **root candidates** | The short list of agents that may have started the fault, ranked. Not a verdict. | C4 `Alert.root_candidates` | culprit (as a finding), guilty party, root cause, blame result |

Note: "kill switch" is the **project name only**. Never use it for an operation; the operations are suspend, revoke, lineage hold.

## 4. Recovery

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **taint** | Mark on every data version that was written by, or derived from, the culprit. | C5 `TaintSet` (`RecoveryPlan.taint_set`); `ks.taint`. Seed = every culprit write in [t0_seq_est, suspend] (A8) | contamination, infection, poison, blast radius |
| **recovery plan** | The proposed fix, step by step, shown as a dry-run diff before anything changes. | C5 `RecoveryPlan` {culprit, t0_seq_est, taint_set, steps, diff}; `ks.recovery`; bound to approval by `plan_hash` (G6) | rollback plan, remediation, playbook |
| **dry-run diff** | Preview of exactly what the recovery plan would change, approved before it runs. | `RecoveryPlan.diff` (`DiffEntry`); CLI `ks recover --dry-run`. Demo lanes: restore · re-run · kept · independent (B3) | preview, simulation, what-if |
| **taint-scoped revert** | Undo only the culprit's tainted changes; everyone else's work stays. | C5 step `restore` (confirmed: a taint-scoped revert = the set of `restore` steps); `RestoreStep.expect` = the culprit's after-version (B6) | rollback, undo (except in headline prose), restore, reset, roll back |
| **kept** | Honest work recovery leaves untouched, with no redo. | dry-run diff lane `kept` (B3); score key `kept_without_redo` | preserved, spared, saved, whitelisted |
| **write-write conflict** | An honest agent later changed the same field object or row; a person decides. | C5 step `flag`, reason `write_write_conflict`. Granularity: field object for `sensitive_fields`, row for everything else. Hero F2+: none (triage kept). Bench F2+x: one, unresolved, counts in residual damage R (B5) | merge conflict, collision, clash |
| **re-run** | Repeat a deterministic honest step on corrected data; effects deduplicated, never sent twice. | C5 step `rerun`; a re-run payment reuses the same `outbox:<id>` (v+1, back on hold, B2) | replay, re-execute, retry, redo |
| **re-plan** | An LLM step that must be thought through again; queued for human approval. | C5 step `replan` | regenerate, re-prompt, re-reason, retry |
| **compensate** | Run the registered opposite action (cancel, refund, correction notice) for a class C effect. | C5 step `compensate` | reverse, refund (generic), undo, rollback |
| **cancel (outbox item)** | Discard a held outbox item so it never leaves. | C5 step `cancel_outbox` | delete, drop, block, recall |
| **flag** | Hand an item to a person because we cannot prove a safe fix. | C5 step `flag`; an unresolved flag counts as left in residual damage R; the bench approver never resolves flags (A6) | escalate, manual review, ticket |

## 5. Scoring and metrics

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **oracle (S\*)** | Same seed, fault off; the culprit also stops from its suspension tick. | `ks.oracle`; run dir `oracle/`; A1 + CALL-02 X3a (A1′). Pure world: monitor, containment, recovery off; outbox dispatches at `release_tick`. Non-culprit suspensions are not mirrored | ground truth (in abstract), baseline, golden run, reference, "the run without the culprit", "culprit removed" |
| **t0** | Moment the first bad effect lands, as judged by the oracle. | scorer: min tick over B ≥ `RunConfig.fault_tick` (scorer-only, A2). Planner estimate: `RecoveryPlan.t0_seq_est` (bounded backward walk over alert evidence; never reads RunConfig) | start of incident, fault time |
| **bad effects (B)** | Effects missing or different in S\*, fixed when recovery starts. | `ks.score`; frozen at t_rec (same tick for us and every baseline); keyed per (table, pk, field) in the harness ledger (A4) | damage set, harmful actions |
| **good effects (G)** | Effects that match S\*, including the culprit's honest ones; fixed when recovery starts. | `ks.score`; frozen at t_rec | legitimate work, honest work set |
| **residual damage (R)** | Share of bad effects still wrong at run end, held or flagged included. Hero F2+ measured value: ALLOWED-NUMBERS N4, only with D-17's release clause. | `ks.score` key `R` = {n,d}: \|{k ∈ keys(B): final(k) ≠ S\*(k)}\| / \|keys(B)\|, scored at T; compares values only (X4) | leftover damage, error rate, miss rate |
| **collateral loss (C)** | Share of good effects lost by recovery, including the culprit's own reverted work. Hero F2+ measured value: ALLOWED-NUMBERS N5 (hero only). | `ks.score` key `C` = {n,d}; split-out key `c_culprit_window` (X3d) | collateral damage, false positives, overkill |
| **culprit-window loss** | The part of collateral loss that is the culprit's own reverted honest work. | `ks.score` key `c_culprit_window` (X3d), from the ledger | acceptable loss, expected loss |
| **collateral stall** | Delay that holds and recovery impose on honest work, reported apart from collateral loss. | `ks.score`, measured against the unmirrored S\* (A1′); score.json key `collateral_stall` `{n,d}`, apart from `fp_cost.stall_ticks` (§7 item 10). **Real runs:** `{n,d,basis: s_star}` is a proxy (divergence from S\*, not S0; ADR-06 A3): always say "proxy" | slowdown, overhead, latency cost |
| **clean recovery** | Residual damage R = 0 and collateral loss C = 0 together, all invariants holding. Any R = 0 claim also states the operator releases: N held items released, of which M honest (D-17, CALL-02 B2-b). | `ks.score`; also requires `invariants_ok` at T; no composite score | perfect recovery, full undo, 100% |
| **TTI-detect** | Time from t0 to the first alert (for a bad action that was denied or held and never landed: from that action to the first alert naming the culprit, ADR-06-metrics A5). | `ks.score` key `tti_detect`, from chained `ks.alert` records (X8) | detection time, MTTD, time to alert |
| **TTI-attribute** | Time from alert to naming the right agent and its first bad action. | `ks.score` key `tti_attribute` (`root_candidates[0]` == culprit) | blame time, attribution latency, MTTI |
| **TTC** | Time from alert to the first denied culprit envelope. | `ks.score` key `ttc` | time to kill, time to stop, MTTC, containment time |
| **post-alert tainted effects** | Bad effects by any agent after the alert, counted from the ledger. Hero F2+ measured value: ALLOWED-NUMBERS N6. | `ks.score` key `post_alert_tainted_effects` (A6); from the ledger, never from our taint or read sets (A5) | leakage, spread, blast radius |
| **irreversible tainted effects released** | Bad payments or emails that actually left despite holds. Hero F2+ measured value: ALLOWED-NUMBERS N7, N16. | `ks.score` key `irreversible_tainted_released` (A6); dispatched payment / email sink effects in B, never the gateway's class | escaped payments, leaks |
| **seeded run** | One reproducible scenario run; same seed gives the same records, signatures aside. | C6 run dir; `ks.bench`; `ks repro A B` diffs `determinism_view()`, exit `Exit.DIVERGED` if they differ (C4–C6) | trial, episode, simulation |
| **run dir** | The folder of outputs the scorer reads; nothing else counts. | C6 | results folder, artefacts |

Note: "R" and "C" are overloaded (class R / class C vs residual damage R / collateral loss C). **Rule:** in the abstract and demo, always write the metric as "residual damage R" / "collateral loss C" on first use in each section, and the class as "class R" / "class C". Never bare "R" in a sentence that also mentions classes.

## 6. Scenarios and demo

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **hero scenario (F2+)** | crm swaps a supplier IBAN; billing, payments, comms consume it; triage's later edit is kept. | fault `F2+` in `ks.world` / `ks.inject`; golden B2 as amended by B2-a (D-16): restore iban + S-22, re-run billing / payments (same `outbox:<id>`, v+1, re-held, then operator unhold; no cancel) / comms; reporter independent, not re-run; triage kept, no flag; per-seed precondition: crm writes nothing else in (t_inject+1, suspend], guard test (X3b) | demo case, use case, story, F2 (without +) |
| **conflict variant (F2+x)** | Bench variant: triage edits the price row crm wrote, so a person must decide. | fault `F2+x`; `test_triage_conflict`; `flag(write_write_conflict)`, unresolved, R > 0 (B5). Measured before resolver (D-18): R 1/5, C 21/254, 29 honest items held (BENCH-S3 medians; ALLOWED-NUMBERS N15). Jury Q&A backup, not the demo | failure case (F7 is the honest failure), edge case |
| **culprit-work variant (F2+c)** | Bench variant: crm also does honest work before suspension, so collateral loss C > 0. | fault `F2+c`; `test_culprit_honest_write_in_C`; golden C = {n,d} > 0, reported (X3c). ⚑ Pending S4-24: BENCH-S3 F2+c shows C 0 [0..0]; gloss not changed until anaya decides | edge case, corner case |
| **independent agents** | Agents that never read tainted data (inventory, docs) and keep running throughout. | none (scorer ground truth) | unaffected, bystanders |
| **inject** | Jury tool to introduce a fault or run arbitrary code inside the rogue agent. | `ks.inject`; CLI `ks inject` | attack script, fuzz, chaos |
| **rogue agent** | An agent template running jury-supplied arbitrary Python, used for the break test. | rogue-agent template in `ks.inject` | malicious agent, hacker, adversary agent |
| **oracle-assisted** | Label for a baseline handed t0 from the oracle, which a real system lacks. | score.json `baseline`; X5 | ideal, upper bound, cheating |
| **snapshot baseline** | Comparison: return the whole workspace to just before the fault; given t0 (oracle-assisted). | `ks.bench` baseline; to t_inject−1, cancels held items, no re-execution (best case) | checkpoint restore, full rollback |
| **revert-culprit-only baseline** | Comparison: put back each object the culprit wrote, no reader repair; given t0 (oracle-assisted). | `ks.bench` baseline; per object (X5), no conflict check, outbox untouched | naive revert, simple undo |

## 7. Contract check (Maya's ABS-04 answers + CALL-02)

All ⚠ from v1 are closed.

1. **Revert vs `restore`**: confirmed. `restore` stays the per-object step; a taint-scoped revert = the set of `restore` steps (C5 docstring). "Restore" stays banned in prose.
2. **Culprit vs suspect**: there is no `Alert.suspect`. Culprit = `RunConfig.culprit` (scorer) / `RecoveryPlan.culprit` (person). Suspect = `root_candidates[0]`, console only (row added).
3. **Provenance graph**: confirmed, no graph type.
4. **Witness checkpoint, side store**: resolved, C2 `WitnessCheckpoint`, C3 `SideStore`.
5. **Hold window, sensitive tag**: resolved, `RunConfig.hold_window_ticks`, `RunConfig.sensitive_fields`.
6. **Metric names**: fixed by CALL-02 A6: `post_alert_tainted_effects`, `irreversible_tainted_released`. TERMS copies score.json keys exactly. ADR-06 now uses the PMO metric names; TERMS and ADR-06 agree.
7. **Idempotency key**: resolved, it exists as C3 `OutboxItem.idempotency_key`.
8. **Connection suspend**: resolved, Control target `conn:<id>` (row added).
9. **Reconciliation**: confirmed, detector `reconcile`, class U.
10. **Collateral stall** (ABS-08): resolved, score.json key `collateral_stall` `{n,d}` like R and C (ADR-06-metrics §3): the system run's `final_T` against the unmirrored fault-off run S0 over non-culprit keys; separate from `fp_cost.stall_ticks`. B3-27 (20 Nov): real runs have no S0, so they report the proxy `{n,d,basis: s_star}` (ADR-06 A3); never call it the S0 measure.
11. **`ks.console`**: removed from ids.py with no alias (E2, X7; grep test). Nowhere in the kit except as a banned synonym.

## Changes v2 (ABS-04 review fixes + CALL-02 freeze, ABS-08, 19 Nov)

- Code names now come from contracts 1.1.0 + CALL-02 resolutions, not maya.md §3 (Maya's ABS-04 review, applied row by row): culprit, new suspect row, alert fields (not signed), envelope (`expiry_tick`, `claimed_*`, `EnvelopeHeader`), act chain (`ActLink`), tick (gateway barrier, `TickFrame`), read set (`ReadEntry`), all five class rows (`ActionClass`), witness, verify / tamper-evident (`first_bad` is a seq), reconciliation, side store, outbox, lineage hold, hold window, sensitive field, invariant detector, taint, recovery plan, dry-run diff, write-write conflict, release, t0, metrics.
- Accepted additions (workspace, trust boundary, idempotency key) moved into §1–§3 with Maya's code names. New rows: connection, operator (`ks.operator` replaces `ks.console`), field object, kept.
- CALL-02: oracle S\* gloss = same seed, fault off, culprit stops from its suspension tick (X3a); B / G frozen at recovery start; G includes the culprit's honest work; R counts held-at-T and flagged items; C row mentions culprit's reverted work; new rows culprit-window loss (`c_culprit_window`), collateral stall, oracle-assisted.
- Hero row: triage's edit is **kept** (no conflict). Write-write conflict is field-or-row; the honest conflict lives in F2+x. New rows F2+x and F2+c.
- Release = fresh epoch, lifts suspension only (D4). Epoch gloss: every suspend / revoke / release sets a new value (D1).
- §7 rewritten as closed items; one open (collateral stall key, tara). Baseline glosses no longer use the banned word "restore".

## Changes v3 (S4-18, zoya, 21 Nov)

- Hero row: golden B2 now as amended by B2-a (D-16): reporter independent; payments re-run under the same `outbox:<id>`, re-held, operator unhold; no cancel.
- F2+x row: measured values, labelled "before resolver" (D-18). F2+c row: ⚑ pending S4-24 (BENCH-S3 shows C = 0).
