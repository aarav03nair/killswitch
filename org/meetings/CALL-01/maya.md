# CALL-01 position: maya (Eng Lead / Architect)

## 1. Panel review

**Accepted as written:**
- write-write rule
- outbox-deduped re-run
- TTC redefinition
- witness checkpoints
- graded containment
- epoch fencing inside the execution txn
- invariant detectors
- PII side store

**Pushback:**
- **2.1 isolation.** Subprocess per agent: yes. "Keys readable only by gateway" can't be enforced with one uid in one container. Agents get their own key (fd) and a socket, never a DB path. We claim *enforced in prod (uid/container), detected here (reconciliation over per-row version hashes each tick)*.
- **2.7 release.** We hold, never cancel, so `release` = un-hold plus restore epoch.
- **3.1 "F5/F6 as pytest".** This contradicts decision 11. F5 and F6 must work live. F3 stays a pytest case.
- **2.3 pre-quarantine hold.** A policy rule on `sensitive` fields, not IBAN code.

## 2. Votes (§7)

1. Agree
2. Agree
3. Agree
4. **Amend.** Re-execute deterministic steps. LLM re-plan = a `replan` step queued for console approval. We build no re-planner.
5. **Amend.** SQLite: yes, but ADR due **23 Nov** so build starts day 1.
6. Agree. The witness is a separate process.
7. **Amend.** Also auto-suspend on a reconciliation mismatch (class U).
8. **Amend.** Hold per action, not per agent. The gateway holds writes and outbox items whose read set touches tainted versions.
9. Agree. Stretch only if the hero path is green by 30 Nov.
10. Agree. One config value.
11. **Amend.** Add a bypass: the rogue opens `state.db` directly and reconciliation catches it.
12. Agree, including the triage conflict row.
13. Agree. ≥20 seeded runs, freeze 1 Dec.

## 3. Breakdown

**Contracts.** Freeze by 22 Nov in `src/ks/contracts/` (maya):

- **C1 Envelope:** agent_id, action_id, parent_action_id, act_chain, tool, args, nonce, expiry, epoch, sig
- **C2 Record:** seq, tick, envelope_hash, decision, class, read_set[(obj, ver)], write_set[(obj, before/after ver+hash)], outbox_ids, prev_hash, hash, gw_sig
- **C3 State:** obj=`table:pk`; `get→(value, ver, author)`; `history(obj)`
- **C4 Alert/Control:** Alert{detector, evidence_seqs, suspect, root_candidates, hard}; Control{suspend|revoke|release|hold|unhold, target, epoch}
- **C5 RecoveryPlan:** taint_set, steps[restore|rerun|replan|cancel_outbox|compensate|flag], dry-run diff
- **C6 Run dir:** the scorer reads only this.
- **Transport:** JSON-lines over Unix sockets

**Sprint 2 ADRs (by 24 Nov):**

| ADR | Owner | Scope |
|---|---|---|
| 00 | maya | Topology, tick barrier |
| 01 | arjun | Identity, envelope |
| 02 | arjun | Recorder, witness, verify, side store |
| 03 | nisha | Gateway, action classes, policy, fencing |
| 04 | nisha + tara | Monitor, containment, lineage hold |
| 05 | vikram | Versioned state, taint, conflict rule, dedupe |
| 06 | tara | World, faults, oracle, metrics |
| 07 | ishaan | CLI and timeline |

**Sprint 3 build (25 Nov to 2 Dec):**

| Owner | Modules |
|---|---|
| arjun | `ks.identity`, `ks.recorder`, `ks.witness`, `ks.verify` |
| nisha | `ks.gateway`, `ks.policy`, `ks.monitor`, `ks.containment` |
| vikram | `ks.state`, `ks.taint`, `ks.recovery` |
| tara | `ks.world`, `ks.inject`, `ks.oracle`, `ks.score`, `ks.bench` |
| ishaan | `ks.cli`, `console/` |
| maya | `ks.runtime`, integration |

**Before 25 Nov:** a walking skeleton (agent → gateway stub → recorder → verify).

**Schedule:**
- D1–2: modules against fixtures
- D3: hero path end to end
- D4–5: containment and recovery
- D6: bench
- D7: hardening and freeze
- D8: buffer

## 4. Biggest risk

**Subprocess isolation breaks the determinism the oracle needs.** If scheduling noise makes S\* diverge, R/C are garbage, and jury re-runs won't reproduce them.

**Mitigation:** the gateway is the scheduler. Each tick, a barrier collects one envelope (or no-op) per agent, run in agent_id order.

**Day-1 test:**
- The same seed twice gives byte-identical records.
- The faulty run equals S\* before t0.
