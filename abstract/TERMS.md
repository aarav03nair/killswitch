# TERMS: one name per concept (ABS-04)

Owner: zoya · Reviewer: maya · 19 Nov 2026 · Inputs: CALL-01.md, CALL-01/maya.md §3 (C1–C6, modules), CALL-01/kabir.md, SYNTHESIS §4/§6, PANEL-ENG-00, RES-02.

**Rule.** The abstract, diagram, demo narration, console labels and code use the left-hand term and nothing else. If a banned synonym appears in a draft, reviewers flag it. Glosses are written for a banking reader and are at most 15 words. Code names are taken from maya.md §3 (C1–C6, module list). `⚠` marks a gap or mismatch that Maya must confirm or fix (see §7).

## 1. Actors and the mediated path

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **agent** | One automated worker (e.g. crm, billing), running in its own sealed process. | `agent_id` (C1); one subprocess per agent | bot, worker, assistant, AI |
| **culprit** | The agent whose faulty actions caused the damage, buggy or rogue. | Alert `suspect` (C4) ⚠ | bad agent, attacker (unless the rogue scenario), offender |
| **honest agent** | Any agent that is not the culprit, even if it read bad data. | none (scorer ground truth, C6) | innocent, good agent, victim |
| **gateway** | The single checkpoint every agent action must pass through before it touches anything. | `ks.gateway` | proxy, middleware, broker, firewall, control plane |
| **action envelope** ("envelope" after first use) | A signed request from an agent: who, what, on whose behalf, valid when. | C1 `Envelope` {agent_id, action_id, parent_action_id, act_chain, tool, args, nonce, expiry, epoch, sig} | request, message, call, payload, ticket |
| **act chain** | The chain of who asked whom, carried on every envelope. | C1 `act_chain`, `parent_action_id` | delegation path, call stack, lineage (reserved, see §3) |
| **tick** | One scheduling round: each agent submits at most one envelope, run in fixed order. | C2 `tick`; barrier in `ks.runtime` | step, turn, cycle, round |
| **sequence number (seq)** | The gateway's own position number for each record; agents cannot choose it. | C2 `seq` | timestamp, index, offset, id |

## 2. The record and its audit

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **record** | The gateway-signed entry written for every action, including denials. | C2 `Record`; `ks.recorder` | log, log line, audit log, journal, trace, event |
| **recorder** | The gateway component that writes records; agents never write their own. | `ks.recorder` | logger, tracer, auditor |
| **read set** | Exactly which data versions an action looked at, captured by the gateway. | C2 `read_set[(obj, ver)]` | inputs, dependencies, sources, footprint |
| **write set** | Exactly which data an action changed, with before and after versions. | C2 `write_set[(obj, before/after ver+hash)]` | outputs, changes, diff, mutations |
| **provenance graph** | The map linking every change to its author and every read to its source. | none; derived from C2 read/write sets in `ks.taint` ⚠ | DAG, lineage graph, dependency graph, knowledge graph |
| **witness** | A separate process that countersigns the record's latest fingerprint every tick. | `ks.witness`; signed `(seq, head, tick)` ⚠ | notary, anchor, timestamp server, blockchain |
| **verify** | The audit check anyone can run to detect edited, missing or forged records. | `ks.verify`; CLI `ks verify` | validate, audit (as a verb), check, prove |
| **tamper-evident** | Any edit up to the last witnessed point is detected; not prevented. | `verify` exit code + first bad index | tamper-proof, immutable, unforgeable, secure log |
| **reconciliation** | Rebuild state from the record and compare to live data, catching bypass writes. | part of `ks.verify` and per-tick check; raises class U alert ⚠ | replay, consistency check, diffing |
| **side store** | Separate store for sensitive values (e.g. IBANs); the record keeps only fingerprints. | none in C1–C6 ⚠ | vault, PII store, cache |

## 3. Classes, holds and containment

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **action class** | Label fixed before an action runs, saying how it could ever be undone. | C2 `class`; assigned in `ks.gateway` / `ks.policy` | effect type, risk level, category |
| **class R (reversible)** | We hold the earlier version and can restore it exactly. | `class = "R"` | undoable, rollback-able |
| **class C (compensable)** | Cannot restore, but a registered opposite action exists (cancel, refund). | `class = "C"` | reversible (wrong), soft |
| **class I1 (irreversible, containable)** | Leaves our boundary (payment, email); can only be held or followed up. | `class = "I1"` → outbox | external, side effect |
| **class I2 (irreversible, uncontainable)** | No follow-up possible; runs only with prior human approval. | `class = "I2"` | destructive, critical |
| **class U (unclassified)** | Anything we cannot classify or that bypassed the gateway; denied by default. | `class = "U"`; reconciliation mismatch | unknown, unsafe, shadow |
| **outbox** | Waiting area where irreversible actions sit until released; nothing leaves without it. | C2 `outbox_ids`; C5 `cancel_outbox` | queue, staging, buffer, sandbox |
| **lineage hold** | Freeze any action or outbox item whose read set touches tainted data. | C4 Control `hold` / `unhold`, target = action or outbox id | quarantine, block, freeze (as noun), gate, pause |
| **hold window** | How long new irreversible actions wait in the outbox. Demo shows 0 vs >0. | config value ⚠ | delay, cooling-off, grace period |
| **sensitive field** | A data field tagged so changes to it trigger an early hold (IBAN is one). | `sensitive` tag in policy (`ks.policy`) ⚠ | PII field, critical field, watched field |
| **graded containment** | Stepwise response: suspend first, revoke only after a person confirms. | `ks.containment` | kill, shutdown, isolation, quarantine |
| **suspend** | Stop one agent (or connection) acting immediately; reversible by release. | C4 Control `suspend` | quarantine, kill, pause, freeze, disable, block |
| **revoke** | Permanently cancel an agent's authority, after human confirmation. | C4 Control `revoke` | kill, ban, terminate, delete |
| **release** | Lift a suspension or hold and restore the agent's epoch; held work proceeds. | C4 Control `release` (and `unhold` for holds) | resume, unblock, restore, un-quarantine |
| **epoch** | A permission counter; bumping it instantly invalidates the agent's in-flight requests. | C1 `epoch`; C4 Control `epoch` | fencing token (internal ADR only), version, generation, session |
| **alert** | A detector's signed finding with evidence; "hard" alerts trigger automatic suspend. | C4 `Alert` {detector, evidence_seqs, suspect, root_candidates, hard} | alarm, incident, warning, flag (reserved, see §4) |
| **invariant detector** | A rule on the data itself (e.g. supplier IBAN changed without approval) that raises alerts. | C4 `detector`; `ks.monitor` | anomaly detector, AI monitor, classifier |
| **root candidates** | The short list of agents that may have started the fault, ranked. Not a verdict. | C4 `Alert.root_candidates` | culprit (as a finding), guilty party, root cause, blame result |

Note: "kill switch" is the **project name only**. Never use it for an operation; the operations are suspend, revoke, lineage hold.

## 4. Recovery

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **taint** | Mark on every data version that was written by, or derived from, the culprit. | C5 `taint_set`; `ks.taint` | contamination, infection, poison, blast radius |
| **recovery plan** | The proposed fix, step by step, shown as a dry-run diff before anything changes. | C5 `RecoveryPlan` {taint_set, steps, dry-run diff}; `ks.recovery` | rollback plan, remediation, playbook |
| **dry-run diff** | Preview of exactly what the recovery plan would change, approved before it runs. | C5 dry-run diff | preview, simulation, what-if |
| **taint-scoped revert** | Undo only the culprit's tainted changes; everyone else's work stays. | C5 step `restore` ⚠ | rollback, undo (except in headline prose), restore, reset, roll back |
| **write-write conflict** | An honest agent later edited the same row, so we flag instead of overwriting. | C5 step `flag` | merge conflict, collision, clash |
| **re-run** | Repeat a deterministic honest step on corrected data; effects deduplicated, never sent twice. | C5 step `rerun` | replay, re-execute, retry, redo |
| **re-plan** | An LLM step that must be thought through again; queued for human approval. | C5 step `replan` | regenerate, re-prompt, re-reason, retry |
| **compensate** | Run the registered opposite action (cancel, refund, correction notice) for a class C effect. | C5 step `compensate` | reverse, refund (generic), undo, rollback |
| **cancel (outbox item)** | Discard a held outbox item so it never leaves. | C5 step `cancel_outbox` | delete, drop, block, recall |
| **flag** | Hand an item to a person because we cannot prove a safe fix. | C5 step `flag` | escalate, manual review, ticket |

## 5. Scoring and metrics

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **oracle (S\*)** | The same run replayed with the culprit removed: the "should have been" outcome. | `ks.oracle`; S\* | ground truth (in abstract), baseline, golden run, reference |
| **t0** | Moment the first bad effect lands, as judged by the oracle. | `ks.oracle` / `ks.score` | start of incident, fault time |
| **bad effects (B)** | Effects in the faulty run that are missing or different in S\*. | `ks.score` | damage set, harmful actions |
| **good effects (G)** | Honest effects that match S\*. | `ks.score` | legitimate work, honest work set |
| **residual damage (R)** | Share of bad effects still present after recovery. Target 0. | `ks.score` metric `R` = \|B left\| / \|B\| | leftover damage, error rate, miss rate |
| **collateral loss (C)** | Share of good work lost by recovery. Target 0. | `ks.score` metric `C` = \|G lost\| / \|G\| | collateral damage, false positives, overkill |
| **clean recovery** | R = 0 and C = 0 in the same run. | `ks.score` | perfect recovery, full undo, 100% |
| **TTI-detect** | Time from t0 to the first alert. | `ks.score` `tti_detect` ⚠ | detection time, MTTD, time to alert |
| **TTI-attribute** | Time from alert to naming the right agent and its first bad action. | `ks.score` `tti_attribute` ⚠ | blame time, attribution latency, MTTI |
| **TTC** | Time from alert to the first denied culprit envelope. | `ks.score` `ttc` ⚠ | time to kill, time to stop, MTTC, containment time |
| **post-alert tainted effects** | Tainted effects by any agent after the alert. Target 0. | `ks.score` ⚠ | leakage, spread, blast radius |
| **irreversible tainted effects released** | Tainted payments or emails that left despite holds. Target 0. | `ks.score` ⚠ | escaped payments, leaks |
| **seeded run** | One reproducible scenario run; same seed gives byte-identical records. | C6 run dir; `ks.bench` | trial, episode, simulation |
| **run dir** | The folder of outputs the scorer reads; nothing else counts. | C6 | results folder, artefacts |

Note: "R" and "C" are overloaded (class R / class C vs residual damage R / collateral loss C). **Rule:** in the abstract and demo, always write the metric as "residual damage R" / "collateral loss C" on first use in each section, and the class as "class R" / "class C". Never bare "R" in a sentence that also mentions classes.

## 6. Scenarios and demo

| Term (locked) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **hero scenario (F2+)** | crm swaps a supplier IBAN; billing, payments and comms consume it; triage later edits crm. | fault id `F2+` in `ks.world` / `ks.inject` | demo case, use case, story, F2 (without +) |
| **independent agents** | Agents that never read tainted data (inventory, docs) and keep running throughout. | none (scorer ground truth) | unaffected, bystanders |
| **inject** | Jury tool to introduce a fault or run arbitrary code inside the rogue agent. | `ks.inject`; CLI `ks inject` | attack script, fuzz, chaos |
| **rogue agent** | An agent template running jury-supplied arbitrary Python, used for the break test. | rogue-agent template in `ks.inject` | malicious agent, hacker, adversary agent |
| **snapshot baseline** | Comparison: restore the whole workspace from a checkpoint. | `ks.bench` baseline | checkpoint restore, full rollback |
| **revert-culprit-only baseline** | Comparison: undo the culprit's writes but do not repair readers. | `ks.bench` baseline | naive revert, simple undo |

## 7. Mismatches and gaps for Maya (C1–C6 check)

1. **Revert vs `restore`.** Public term is "taint-scoped revert"; C5 step is `restore`. Proposal: keep `restore` as the per-object step name and say in the ADR that a taint-scoped revert = the set of `restore` steps. Banning "restore" in prose avoids confusion with "restore epoch" (release). Maya to confirm or rename the step.
2. **Culprit vs `suspect`.** C4 `Alert.suspect` is an accusation; "culprit" is ground truth (scorer only). Keep both; prose uses "suspect" only when talking about the alert field.
3. **Provenance graph** has no contract. It is derived from C2 read/write sets in `ks.taint`. Fine if nobody adds a separate `graph` type; confirm.
4. **Witness checkpoint** `(seq, head, tick)` and **side store** are not in C1–C6. Suggest a witness entry type under C2 or C6 and a side-store note in C3 (ADR-02, arjun).
5. **Hold window** and **`sensitive` tag**: config/policy, no contract. Suggest they live in the C6 run-dir config so the scorer can see which hold value was used.
6. **Metric field names** (`tti_detect`, `tti_attribute`, `ttc`, `post_alert_tainted`, `irreversible_tainted_released`, `R`, `C`) are proposed; C6 only says "scorer reads run dir". Tara (ADR-06) to fix names.
7. **Idempotency key** (re-runs dedupe through the outbox) is not a C1/C2 field; `nonce` is for replay protection, not dedupe. Suggest an explicit `idempotency_key` on outbox items.
8. **Connection vs agent suspend** (anti-framing, D7): C4 `Control.target` must allow a connection id, not only an agent_id.
9. **Reconciliation** alert: confirm its `Alert.detector` name (proposed `reconcile`) and that it raises class U.

**Proposed additions (vikram, ABS-03 review; existing rows unchanged, owner to accept or reject):**

| Term (proposed) | Plain-English meaning (≤15 words) | Code name | Banned synonyms |
|---|---|---|---|
| **workspace** | The shared data all agents work on, owned and changed only by the gateway. | `state.db` (row-versioned SQLite, D5) | database (in prose), shared memory, environment |
| **trust boundary** | Line past which nothing an agent sends is trusted until the gateway checks it. | THREAT-MODEL §2, B1 (agent → gateway IPC) | perimeter, firewall, sandbox wall |
| **idempotency key** | Tag on each outbox item so a re-run never sends the same effect twice. | proposed outbox field `idempotency_key` (see item 7) | nonce (different purpose), dedupe id |
