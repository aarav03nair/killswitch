# GUARDRAILS: claims we can defend vs claims a jury will punish (ABS-02)

Owner: zoya · Reviewer: panel · 19 Nov 2026 · Inputs: abstract/FACT-CARD.md (only source for outside numbers), research/SYNTHESIS.md §0/§3/§6, research/RES-11.md §1/§4/§5, research/RES-10.md (DROP list), org/meetings/CALL-01.md D1–D13 (binding), org/meetings/CALL-02.md + CALL-02/resolutions.md (design freeze, binding; D13 meaning revised), CALL-02/anaya.md §2–4, org/adr/THREAT-MODEL.md C1–C6, abstract/TERMS.md v2 (locked terms).

**How to use.** Every row is a phrase or a rule. None of it is abstract text: Aarav writes every sentence (CHARTER). Use the locked terms from TERMS.md.

**Three ground rules that apply to every row**

- **Tense (v5, D-19).** The 20-seed bench exists (org/reports/BENCH-S3.md, T=40). Past tense ("measured") is allowed **only** for values on abstract/ALLOWED-NUMBERS.md, with their conditions. Everything else (finale demo, jury break, D-18 resolver, red-team pass values) stays design, plan or target. No "achieves" or "showed" about anything not on that list.
- **External numbers** come only from abstract/FACT-CARD.md (ABS-01), the only source, and carry its "must travel with it" wording (D13). Not SYNTHESIS §2: its wording differs from the card.
- **Our numbers** (v5, D-19 revises D13): measured values only from abstract/ALLOWED-NUMBERS.md, each with its source row, its condition and T=40; anything else of ours is a definition or a labelled target (§1.5 below). Superseded rule: "targets only, nothing measured by 22 Nov".

---

## 1. Safe claims (note form; Aarav phrases them)

### 1.1 Problem (D1: the abstract opens here)

| # | Claim (note form) | Rests on | Condition / limit |
|---|---|---|---|
| P1 | Undo is a **dependency** problem, not a snapshot problem: "undo X" is undefined once other agents have read X | SYNTHESIS §0 (confirmed); commit stores record no reads (RES-06); sagas make "no effort" to notify readers (fact 13); OTel has no read/write sets (fact 11) | Opening idea (D1). Say the multi-agent dependency risk is backed by the literature, not by incidents (D2) |
| P2 | A blunt stop (wiping the board) did **not** end agent coordination at scale: METR on the OpenAI/HF incident | FACT-CARD #1–#3; D2 | Use it only as proof that a blunt stop failed. FACT-CARD #1/#2 wording: "roughly", "METR, preliminary findings", "July 2026" (no day), "agents in OpenAI's ExploitGym evaluation runs", "about two days later" (new board via an Artifactory cache namespace). Never "internal" or "cyber" (FACT-CARD #1 note) |
| P3 | Single-agent incidents: seconds to break, days to repair, whole backup or no recovery at all | Facts 9–10 | "Reportedly"; PocketOS "per the founder, as reported" |
| P4 | Forward containment exists (Airlock) and, by design, leaves committed effects and absorbed state to "orthogonal rollback" | Fact 8; RES-11 §4 #2–#4; D3 | One credited clause, "complementary"; keep the qualifier "by design" |
| P5 | An agent's own log is **testimony**, not evidence; Airlock's journals are "taken as reported, not authenticated" | RES-11 §4 #6; SYNTHESIS §1 frame C | Present it as Airlock's declared assumption, not as a defect |
| P6 | LLM-based failure attribution is about half right at agent level and much lower at step level | Facts 4–6 (Who&When, FAMAS); RES-10 headline 1 | Give the setting: GPT-4o, best strategies, a different strategy per metric. FAMAS needs 20 re-runs (~105 min) |

### 1.2 Fix (provenance as the organising idea, D1)

| # | Claim (note form) | Rests on | Condition / limit |
|---|---|---|---|
| F1 | **Niche** = multi-agent + per-author + shared external state + dependants handled, as a combination | RES-11 §1 (watch-outs); SYNTHESIS §1; D1 | Claim the combination, never one part on its own (each part has prior art) |
| F2 | One mediated path: every action passes through the gateway; unmediated writes are caught by reconciliation (state = fold(log)) | Principle 1; D11 (DB bypass); THREAT-MODEL RT1 | "Caught", not "impossible" |
| F3 | The gateway's adapters record read and write sets at row level, and at field level for sensitive fields (field objects); agents never self-report | Principle 2; D8; CALL-02 B1, X1, X2 | Lineage the agent declares is never trusted (D8, C5). Field objects are generic (driven by the sensitive-field config), never "IBAN-specific". A whole-row read counts as reading its field objects too |
| F4 | Identity on every action: agent signature + gateway signature; the gateway assigns `seq` and time | D6; principle 3; THREAT-MODEL rule 3, RT6 | A valid signature proves which key signed through which handle, not intent (C4) |
| F5 | Identify = an invariant detector raises an alert, then attribution is a **lookup** on signed records, not an inference | Principle 6; contrast with P6 | It is a different task from Who&When, so no "beats" claim (X20) |
| F6 | Contain **per action**: a lineage hold on writes and outbox items whose recorded read set touches tainted versions; independent agents keep running | D8; principle 7; C5 | Effects released before the alert are not held and count as residual damage (D10). Hold window H=0 keeps the lineage hold on: measured F2+ H=0 escape is 0 (ALLOWED N16). The escape appears only with the lineage hold **off** and no recovery (D10 contrast, N17, "not a security result") |
| F7 | Graded containment: auto-suspend only on hard evidence (scope breach, I-class invariant breach, reconciliation mismatch = class U); anomalies need one click; revoke only after confirmation | D7 | Do not merge these into a single "auto-kill" |
| F8 | Anti-framing: a bad signature suspends the **submitting connection**, never the claimed agent | D7; C4; RT3 | Pairs well with the jury break (F12) |
| F9 | Recovery = taint-scoped revert: only writes whose current value is still the culprit's after-version; otherwise flag (write-write conflict); readers re-run; append-only records | Principle 8; C6; CALL-02 B1, B6, A8, X3 | Over-taint rather than under-taint (conservative, D4). Conflict granularity = field object for sensitive fields, **row** for everything else: never say "same field" in general. The culprit's own writes between fault and suspension are reverted too and count in collateral loss C (we cannot tell its honest ones apart without the fault tick, which the system never sees) |
| F10 | Dependants: deterministic steps re-run through the outbox with idempotency keys (no re-emitted effects); LLM steps become a re-plan queued for approval | D4; principle 9 | The finale has no LLM agent (D9). Re-plan is a queued item, not autonomous repair |
| F11 | Irreversible effects: hold window in the outbox, then compensate or report, never reverse | D10; C6; RES-11 §5 must-not #3 | Containment holds and never cancels. `release` = active again at a fresh epoch; it lifts suspension only, lineage holds stay (CALL-02 D4). Discarding a held item is an approved recovery-plan step after the dry-run diff. **Hero (v5, B2-a):** the hero plan has **no** cancel: payments re-run under the same `outbox:<id>` at v+1, are re-held, then the operator unholds them and they leave with clean payloads (scripts/demo.sh line 5). Those unholds count in D-17's release clause |
| F12 | Tamper-evident **up to the last witnessed head**: hash chain + separate witness process signing (seq, head, tick) every tick + `verify` (chain, signatures, witness heads, seq gaps, reconciliation) | D6; C1 | Use this exact scope. A stalled witness head raises an alert. No Merkle proofs |
| F13 | The jury can try to break it live: `ks inject`, rogue agent with arbitrary Python, direct `state.db` bypass, log-line edit, full chain rewrite → `verify`; threat model published first | D11; THREAT-MODEL §7 | F3 (exfiltration) is a pytest, not live. Red-team pass values stay targets until kabir's REDTEAM-S4 report (ALLOWED §5) |

### 1.3 Why it matters (testimony vs evidence)

| # | Claim (note form) | Rests on | Condition / limit |
|---|---|---|---|
| W1 | Recovery is **scored against an oracle** (S\*: same seed, fault off, culprit stops from its suspension tick), never against our own taint graph | Principle 10; SYNTHESIS §6; RES-11 §5 safe #3; CALL-02 A1, X3a | Recovery metrics sit next to Airlock-style containment metrics, not in place of them. Never describe S\* as "the run without the culprit" or "culprit removed" (TERMS §5). Snapshot and revert-culprit-only baselines are given t0, so call them **oracle-assisted** (X5) |
| W2 | The audit holds even against the audited agent, within the stated threat model | D6; THREAT-MODEL §3 | Always attach "within the threat model" (host compromise is out of scope) |
| W3 | Re-plan / redo cost reported openly, because Airlock's "kept without redo" metric penalises re-runs | RES-11 §1 watch-out 2; SYNTHESIS §6 | Pairs with "re-emitted effects = 0" (target) |
| W4 | **Maps to** AI Act Art 12(1) (automatic logs) and Art 14(4)(e) (stop "in a safe state"), NIST AI RMF MANAGE 4.3, RBI FREE-AI Sutra 5 ("Accountability cannot be delegated to the model and underlying algorithm") | FACT-CARD #15; RES-08 ref [19] (NIST AI RMF MANAGE 4.3, not on the card); FACT-CARD row R (spare, status S) | "Maps to" only. NIST MANAGE 4.3 as a reference only, no number. Article numbers only, no amending-regulation number. High-risk dates 2 Dec 2027 (Annex III) / 2 Aug 2028 (Annex I). RBI quote: open the RBI report and check the exact words before printing (press paraphrases them); if not checked, omit it |
| W5 | Enterprise path: OTel export, policy-as-code; Dolt and agentgateway are **production twins** | D5; SYNTHESIS §5; CHARTER | A twin is a stated path, not an integration |
| W6 | A banking-readable scenario: crm swaps a supplier IBAN; billing, payments and comms consume it; triage later edits the same supplier and its edit is **kept** (no flag); inventory and docs stay independent | D12 (hero F2+); CALL-02 hero decision, B2, B3 ⚑ | It is the scenario we will show, not a real incident. The ×10 price change stays in the data, not in the story. The hero has **no** write-write conflict: never say triage's edit is flagged or conflicts. The honest conflict lives in bench F2+x (L9), for Jury Q&A only |
| W7 | The brief's three scores (time-to-identify, time-to-contain, clean recovery) have **no agreed measurement** in the standards we checked; we define checkable ones, scored against the oracle | RES-08 headline (NIST SP 800-61r3 has no mean-time metrics; Google SRE on mean-time stats) | Always "in the standards we checked"; never "no standard exists". Our definitions are §1.5; no seconds (D13) |

### 1.4 Limits to state (stating them builds credibility; one short line in the abstract)

| # | Limit | Rests on |
|---|---|---|
| L1 | No reversal of irreversible external effects: hold, compensate or report | D10; C6; SYNTHESIS §3 |
| L2 | Taint tracks data exposure, not meaning: we over-taint by design, so collateral holds are possible | THREAT-MODEL §3; D4; Airlock App. F |
| L3 | Colluding agents: we name root candidates and claim no prevention; a laundered write carries the launderer's signature | C3; CALL-01 attribution of laundered writes |
| L4 | Out of scope: gateway or witness host compromise, one insider holding both keys, covert channels, preventing prompt injection | THREAT-MODEL §3 |
| L5 | Key isolation: "enforced in production (uid/container), detected here by reconciliation" | C2; CALL-01 key isolation; Maya's recorded dissent |
| L6 | Finale agents are deterministic; one LLM agent is a stretch goal | D9 |
| L7 | Scale: about 10 agents, single host, tick barrier (logical clock) | RES-11 §3 "Us" column; CALL-01 determinism |
| L8 | **F2+c honesty note (corrected S4-24, anaya, 21 Nov; D-20: F2+c as built does not exercise honest in-window writes; C not quoted).** Hero C = 0 holds only because crm writes nothing else between fault and suspension (per-seed precondition, guard test). The case "crm works honestly in that window, its work is reverted, C > 0" is **not measured**: bench F2+c does not exercise it. Reason (records, seeds 1..20, T=40, H=6): the monitor suspends crm at t_inject+2 on 19/20 seeds (s7: at t_inject, window empty), so the window (t_inject+1, suspend] is the suspend tick only; crm's one honest action there lands in the same tick, but the mirrored S\* (CALL-02 X3a) stops crm from the suspend tick, so S\* never has that write: it falls in B (reverted, counted in R if left), never in G. On 11/20 seeds that action changes nothing (empty write set); on 8/20 it writes one customer row. Hence C 0 and `c_culprit_window` 0 by construction, not a measurement. Fixture fix: S4-30 (tara), after the finale (D-20). Until S4-30 closes: cite no F2+c value, do not claim C > 0 is measured, do not state this limit with a number | CALL-02 X3a, X3b, X3c; anaya dissent note; BENCH-S3 §F2+c; S4-24 finding |
| L9 | **F2+x honesty note.** In bench F2+x triage edits the non-sensitive row crm wrote (the ×10 price) → write-write conflict → flag, unresolved because the bench approver never resolves flags. Measured, **before resolver** (D-18 not built; values may change): residual damage R 1/5, collateral loss C 21/254, 29 honest items held (medians, ALLOWED N15). Quote all three together; this is the honest conflict case, show it if asked (JURY-QA Q10) | CALL-02 B5; BENCH-S3 §F2+x + Reading notes; CALL-04 D-18 |

### 1.5 Our numbers: definitions, measured values (D-19) and remaining targets

v5: D-19 (Aarav, CALL-04) lets the abstract cite measured BENCH-S3 values. The value column below points to abstract/ALLOWED-NUMBERS.md (IDs N1–N17), which carries each value's source row and condition. All at T=40, 20 seeds, H=6 unless stated.

| Metric | Definition | Label in the abstract |
|---|---|---|
| D13 meaning (CALL-02; element 1 revised by D-19) | Elements the numbers sentence must carry, in Aarav's words: (1) ~~label "targets, to be measured"~~ → measured values from ALLOWED-NUMBERS with T=40, 20 seeds, and D-17's release clause next to any R = 0; (2) scope = the hero scenario only (F2+x disclosed separately, "before resolver"); (3) residual damage R = 0 and collateral loss C = 0, both written in full; (4) zero post-alert tainted effects and zero irreversible tainted effects released; (5) an honest agent's later change to the **same data** → a person decides → counts in residual damage; (6) the culprit's own work between fault and suspension → reverted → counts in collateral loss | Meaning only, not wording. ✗ "same field" (wrong outside sensitive fields, where conflicts are row-level) · ✗ C = 0 read as unconditional (needs clause 6) · ✗ bare R / C (§1.5 note) · ✗ seconds |
| t0 | Oracle time of the first bad effect (never before the fault tick) | definition only |
| B / G | Fixed at recovery start: faulty-run effects absent or different in S\* / effects that match S\* (including the culprit's honest ones) | definition only |
| residual damage R | \|B left\| / \|B\| at run end; items still held at T and unresolved flags count as left | F2+ measured 0 [0..0] **with** D-17 release clause (N4); F2+x 1/5 before resolver (N15) |
| collateral loss C | \|G lost\| / \|G\|; the culprit's reverted in-window work is reported separately (`c_culprit_window`) | F2+ measured 0 [0..0], hero only (N5); F2+x 21/254 before resolver (N15); F2+c: does not exercise honest in-window writes; C not quoted (D-20), cite nothing |
| clean recovery | R = 0 and C = 0 in the same run, every invariant holding at run end | F2+ only, with D-17 clause; never for F2+x |
| post-alert tainted effects | Bad effects by any agent after the alert, counted from the ledger (score key `post_alert_tainted_effects`) | F2+ measured 0 [0..0] (N6) |
| irreversible tainted effects released | Bad payments or emails that actually left (score key `irreversible_tainted_released`) | F2+ measured 0 [0..0] at H=6 (N7) and H=0 with lineage hold on (N16); D10 contrast only as N17 |
| re-emitted effects | Effects sent twice by re-runs | F2+ measured 0 [0..0] (N8) |
| TTI-detect / TTI-attribute / TTC | t0 → first alert / alert → correct agent + first bad action / alert → first denied culprit envelope | F2+ measured in **ticks**: TTI-detect 2 [0..2], TTI-attribute 0, TTC 1 (N1–N3); **no seconds** |
| protocol | ≥20 seeded runs; median, p95, max; snapshot and revert-culprit-only baselines (both **oracle-assisted**: given t0) and no-op; hold 0 vs >0; collateral stall reported apart from collateral loss; F2+x and F2+c on the bench | **done** at T=40, seeds 1..20 (BENCH-S3); F2+c does not exercise honest in-window writes, C not quoted (D-20, S4-30). T=120 rerun not done (S4-14) |

Write "residual damage R" and "collateral loss C" in full on first use, so they are not confused with class R and class C (TERMS §5).

---

## 2. Do not claim

| # | Do not claim | Reason (source / decision) | Safer alternative (concept) |
|---|---|---|---|
| X1 | "First" or "only" for provenance-based containment, agent undo or agent gateways | Airlock (2611.06727), Wang (2608.10502), agentgateway; SYNTHESIS §3; RES-11 §5 must-not #1–#2 | The F1 combination; credit the prior art |
| X2 | "Today's tools stop one agent or all of them" as our own insight | It is Airlock's own motivation (§1, App. G); SYNTHESIS §3 | Credit that framing to Airlock; our gap begins after commit (P4) |
| X3 | Any Airlock comparison: better, faster, "leaks", "simulation-only", "scripted agents only" | Not true and not tested; Airlock reports 0 post-τ1 leaks and ran six LLM deployments on physical devices; RES-11 §5 must-not #3; D3; C6 | Complementary: forward vs backward, one credited clause |
| X4 | A bare "Airlock cannot undo" | It is a declared design choice, and Airlock beats checkpoint rollback on its own metrics; RES-11 §5 must-not #2 | "Leaves committed effects to orthogonal rollback, by design" (P4) |
| X5 | "First selective undo for agents" | Taser, Retro, Warp, Aire (fact 14); Wang (single agent); Spark to Fire (message rewrite); State Footprints (vision); RES-11 §5, RES-10 headline 4 | The systems idea carried over to multi-agent shared state with dependants |
| X6 | That multi-agent collateral incidents are common, or that METR is a case of one agent consuming another's bad write | The only public case was collusion inside an evaluation; SYNTHESIS §0/§3; D2 | METR = a blunt stop that failed; dependency risk = from the literature, and say so |
| X7 | "We would have stopped it" (METR) | D2; SYNTHESIS §3 | What the blunt stop showed + what our design targets |
| X8 | "Legitimately held credentials", exact HF dates, "11 days to detect" | METR: the board came from exploiting Artifactory; outlets conflict on dates; RES-11 §6; SYNTHESIS §3 | "July 2026", "about two days later", "per METR" |
| X9 | "One method gets 53.5% / 14.2%"; quoting two different 53.5s | Two methods averaged over four cells; Atomix τ-bench is also 53.5; RES-10 DROP 1, 10 | Fact 4 with its setting; at most one 53.5 |
| X10 | MAST "94%" (or any MAST number) | Label accuracy of a few-shot o1 annotator; RES-10 DROP 2; FACT-CARD "not safe to print"; D13 | Leave MAST out |
| X11 | Venues for MAST, Cordon, CHIEF, FAMAS, Atomix, GoEx, DeltaBox, State Footprints; "Mohammadi et al." as the Atomix authors; the 29 May 2026 Atomix date | Not confirmed; RES-10 DROP 3, 4, 5, 11; FACT-CARD "not safe to print" | "arXiv preprint" + ID, no day (Who&When = ICML 2025 is fine); Atomix as "MPI-SWS and collaborators" unless the author list is copied from the arXiv abs page |
| X12 | Cordon beat real products; Atomix beats checkpoints; Atomix frontier gating improves success under speculation; DeltaBox is per-agent; State Footprints rolls back; GoEx has numbers; CHIEF is SOTA; FAMAS works as an online detector | RES-10 DROP 3–9 | Concept + arXiv ID only, no number (D13), or omit |
| X13 | IBM 241/247 days as agent numbers; RBI "18%"; "2026/1744" | SYNTHESIS §3 | Omit |
| X14 | That we reverse irreversible effects (sent email, paid invoice) | RES-11 §5 corollary; D10; C6; SYNTHESIS §3 | Hold / compensate / report; whatever escapes is scored as residual damage |
| X15 | "Tamper-proof", "immutable", "unforgeable" record | D6; C1; SYNTHESIS §3 | Tamper-evident up to the last witnessed head; we detect, we do not prevent (B4) |
| X16 | Merkle proofs, inclusion proofs, a transparency log, "blockchain" | D6 ("No Merkle proofs"); TERMS bans "blockchain" | Hash chain + witness checkpoints + `verify` |
| X17 | That a bad signature or a tamper alert suspends the agent | D7 anti-framing; C4 | Bad signature → submitting connection suspended; tamper alert → recovery frozen, nobody suspended |
| X18 | A fully automatic kill on any anomaly / no human in the loop | D7 (one click for anomalies, revoke after confirmation); TERMS ("kill switch" = project name only) | Auto-suspend on hard evidence only; graded containment |
| X19 | "Compliant", "certified", "meets the AI Act" | SYNTHESIS §3; fact 15 wording rule | "Maps to" Art 12/14, NIST MANAGE 4.3, RBI FREE-AI |
| X20 | "Beats Who&When" or any attribution accuracy of ours | A different task; SYNTHESIS §3; D13 | Attribution as a lookup on signed records vs after-the-fact inference (a different setting) |
| X21 | Any result number of ours **not on ALLOWED-NUMBERS**, or one without its condition (TTI in seconds, bare R = 0, "% recovered", "0 leaks", F2+c values, red-team pass values) | D-19 (revises D13); THREAT-MODEL §5 | A listed value with its condition (ALLOWED-NUMBERS), else definition + "target" |
| X22 | That we identify the true originator under collusion or laundering | C3; CALL-01 attribution of laundered writes | Root candidates, ranked; not a verdict |
| X23 | Preventing prompt injection, collusion or covert channels; surviving gateway compromise | THREAT-MODEL §3 (out of scope) | Contain and recover the *effects*; name what is out of scope |
| X24 | "Keys are unreachable" / full key isolation in our prototype | C2; Maya's dissent (CALL-01 §5) | Enforced in production (uid/container), detected here by reconciliation |
| X25 | Automatic recovery of LLM agents' work; LLM replay; "tested on LLM agents" | D4, D9 | Deterministic re-run + re-plan queued for approval; deterministic finale agents |
| X26 | Exact or semantic taint tracking | THREAT-MODEL §3 (semantic influence out of scope); Airlock App. F | Conservative over-taint, by design |
| X27 | "All honest work kept without redo" | Re-runs count as redo (RES-11 §1 watch-out 2) | Re-runs with no re-emitted effects (target 0) + redo cost reported |
| X28 | Production-ready, scalable, "runs on Dolt", "integrated with agentgateway" | D5 (own SQLite; Dolt = twin); scale ~10 agents (L7) | Production twin / path; tested scale stated |
| X29 | "We cancel or block" as a containment action | CALL-01 release semantics ("we hold, never cancel"); C6 | Lineage hold → unhold, or a recovery-plan step after the dry-run diff (`release` lifts a suspension only, CALL-02 D4) |
| X30 | Detecting any misbehaviour | Detection = invariant detectors on data + scope checks (principle 6); splitting under thresholds has no claim (THREAT-MODEL §5) | Detection on declared data invariants and hard evidence |
| X31 | Cordon 45/45 vs 14/45 | Baselines are the authors' own adapters on their own suite; RES-10 DROP 3; FACT-CARD "not safe to print"; D13 | Concept + arXiv ID only, no number |
| X32 | Any DeltaBox ms figure | FACT-CARD "not safe to print"; D13; RES-10 DROP 6 | Concept + arXiv ID only, no number |
| X33 | Any GoEx number | None exists in the text read (RES-10 DROP 7); FACT-CARD "not safe to print"; D13 | Concept + arXiv ID only, no number |

---

## 3. Overclaim words → what to say instead (concept, not a sentence)

| Word / phrase | Why a jury punishes it | Concept to use instead |
|---|---|---|
| **first**, pioneering, only | Prior art exists for each part (X1, X5) | Builds on named prior art; adds the backward half |
| **novel**, new, unique, unprecedented | Same; juries test novelty first | A named gap + the combination (F1) |
| **tamper-proof**, immutable, unforgeable, secure log | D6 scope; the record file is editable (B4) | Tamper-evident up to the last witnessed head; detect, not prevent |
| **compliant**, compliance, certified, regulation-ready | No assessment done; fact 15 rule | "Maps to" + article |
| **guarantees**, guaranteed, provably, proven, ensures | No proof and no measurement (Airlock has a theorem, we do not) | Designed to; target; checked by `verify` |
| **eliminates**, zero (unscoped), no damage | Irreversible residue and over-taint remain (L1, L2); measured zeros hold only under their conditions | A listed zero with its condition (ALLOWED-NUMBERS; D-17 clause for R) |
| **prevents**, stops, blocks (attacks, injection, collusion) | Out of scope (X23); we act after the alert | Detects, holds, contains after the alert |
| **real-time**, instant, immediately | Tick barrier and logical clock; hold window; no seconds measured | Per tick; before release; within the hold window |
| undo / rollback without qualification, full recovery, reverses any damage | Only provable reversible writes; TERMS bans "rollback" | Taint-scoped revert of landed shared-state writes |
| automatically recovers, self-healing | LLM steps need approval (D4) | Re-run deterministic steps; re-plan with approval |
| outperforms, beats, better than, state of the art | No comparative run (X3, X20) | Complementary; compared to our own planned baselines |
| scalable, production-ready, enterprise-grade | About 10 agents, single host (L7) | Production twin; path to OTel / policy-as-code |
| all, every, any, never, always (unscoped) | One counterexample from the jury breaks it | Scoped: "every mediated action", "within the threat model" |
| identifies the culprit / root cause (collusion) | C3 | Root candidates |
| trustless, zero-trust | The gateway and witness are trusted (TCB, B2) | Trust placed only in the gateway and witness |
| achieves, demonstrates, shows, reduced (past tense) | Only BENCH-S3 values on ALLOWED-NUMBERS were measured (D-19); the finale demo, jury break and resolver are future | "Measured" + listed value + conditions; otherwise will show / target / designed |
| kill / kill switch (as an operation) | TERMS: project name only; D7 is graded | Suspend → revoke after confirmation; lineage hold |
| cancelled (payment), as a containment action | Containment never cancels: holds end by `unhold`; `release` lifts a suspension at a fresh epoch (CALL-01 release semantics; CALL-02 D4) | Held in the outbox. A held item is cancelled only by an approved recovery-plan step (`cancel_outbox`, maya.md C5; TERMS "cancel (outbox item)") after the dry-run diff |
| ground truth (in the abstract) | TERMS term lock | Oracle (S\*) |

---

## 4. 30-second self-check (run on the draft before sending it for review)

1. **Ctrl-F §3 words**: no hits, or every hit has its scope attached.
2. **Each number**: external → on abstract/FACT-CARD.md (the only source), with its "must travel with it" wording? Ours → an ID on abstract/ALLOWED-NUMBERS.md with T=40, 20 seeds and its condition (D-17 release clause next to any R = 0; F2+x "before resolver" with all three values), else definition + "target"? No seconds anywhere? Numbers sentence carries the D13 elements (§1.5 first row, element 1 as revised)?
3. **Tense**: "measured" only next to an ALLOWED-NUMBERS value; anything else built-or-achieved → design / will show / target.
4. **Order (D1)**: problem (dependency gap) → fix (provenance) → why (testimony vs evidence; oracle scoring).
5. **Airlock**: named once, credited, "complementary", no comparison adjective (D3, X3).
6. **METR**: blunt stop failed, and nothing more; no "would have stopped it"; no exact day; no "legitimately held credentials" (D2, X6–X8).
7. **Tamper-evident**: scoped to "up to the last witnessed head"; never "proof" (D6).
8. **Limits line** present: irreversible effects, over-taint, deterministic agents / LLM re-plan, out-of-scope list (L1–L7).
9. **Collusion / laundering** → "root candidates" only (C3).
10. **Regulation** → "maps to", never "compliant" (W4).
11. **Locked terms** (TERMS.md): no banned synonyms (rollback, kill, log, ground truth, quarantine).
12. **Own words**: no sentence copied from this kit, the research files or any AI chat; organisers check for AI-written text (CHARTER). Under 1,000 words.

---

## Changes v2 (panel review, 19 Nov)

- P2: FACT-CARD #1/#2 wording; dropped "internal OpenAI cyber evaluation". Ground rule 2 and self-check 2 name abstract/FACT-CARD.md as the only source; SYNTHESIS §2 dropped.
- X10 → leave MAST out. X12 → concept + arXiv ID only, no number (D13). New rows X31 (Cordon 45/45 vs 14/45), X32 (DeltaBox ms), X33 (GoEx numbers).
- RES-10 DROP 5 leftovers added: frontier gating (X12), "Mohammadi et al." and the 29 May 2026 Atomix date (X11).
- W4: RBI quote is status S (check the report's exact words or omit); Art 14(4)(e) stop "in a safe state".
- §3 "cancelled (payment)" row reworded: containment never cancels; `cancel_outbox` is an approved recovery-plan step after the dry-run diff (CALL-01 release semantics, maya.md C5), so the locked TERMS term is no longer banned.

## Changes v3 (ABS-06 panel nits, 19 Nov)

- F11: discarding a held item is an **approved** recovery-plan step after the dry-run diff.
- W4: NIST AI RMF MANAGE 4.3 now sourced to RES-08 ref [19] (not on the FACT-CARD); reference only, no number.
- New W7: the brief's three scores have no agreed measurement in the standards we checked; we define checkable ones (source RES-08 headline). Used in SKELETON 3b.

## Changes v4 (CALL-02 design freeze, ABS-08, 19 Nov)

- F3: field-level read / write sets for sensitive fields (field objects, generic); whole-row reads include them.
- F9: conflict granularity is field-or-row; the culprit's own in-window writes are reverted and count in collateral loss C (A8, X3).
- W1: S\* = same seed, fault off, culprit stops from its suspension tick; "the run without the culprit" retired; snapshot and revert-culprit-only labelled oracle-assisted (X5).
- W6: triage's edit is **kept** in the hero; no conflict in the hero; the honest conflict is bench F2+x.
- New limits L8 (F2+c: C > 0 when crm works honestly in-window) and L9 (F2+x: honest conflict, R > 0).
- §1.5: new first row with the six elements of the revised D13 meaning (⚑ Aarav; wording is his); B / G frozen at recovery start; R counts held-at-T and flagged items; C notes `c_culprit_window`; score keys `post_alert_tainted_effects` / `irreversible_tainted_released`; protocol adds oracle-assisted label, collateral stall, F2+x / F2+c. Self-check 2 checks the six elements.
- Release semantics (D4): F11, X29 and the §3 "cancelled" row no longer say "restore epoch"; release = fresh epoch, lifts suspension only.

## Changes v5 (S4-18, zoya, 21 Nov; D-19, D-17, B2-a, BENCH-S3)

- Ground rules (tense, our numbers), §1.5, X21, §3 "eliminates" and "achieves" rows, self-check 2–3: D-19 lets the abstract cite measured BENCH-S3 values (T=40, 20 seeds) listed in the new abstract/ALLOWED-NUMBERS.md, each with its condition. "Targets only, nothing measured by 22 Nov" retired; remaining targets: red-team pass values, finale demo, resolver.
- F6: H=0 keeps the lineage hold (measured escape 0); the escape is the D10 contrast with the lineage hold off and no recovery, "not a security result".
- F11: hero has no cancel (B2-a): re-run under the same `outbox:<id>` v+1, re-held, operator unhold.
- F13: red-team pass values stay targets until REDTEAM-S4.
- L8: ⚑ pending S4-24 (anaya): BENCH-S3 F2+c shows C = 0; not decided here; cite no F2+c value.

## Changes (S4-24, anaya, 21 Nov)

- L8 corrected: bench F2+c C = 0 is by construction (suspend at t_inject+2, mirrored S\* drops crm from the suspend tick), not a measurement; the C > 0 case is not measured. Fixture fix opened as S4-30 (tara).
- L9: adds measured C 21/254 and 29 held honest items to R 1/5, labelled "before resolver" (D-18).

## Changes (S4-24, anaya, 21 Nov; D-20)

- L8 and §1.5 C row: D-20 label "F2+c as built does not exercise honest in-window writes; C not quoted"; fixture fix S4-30 after the finale.
- Resolver "undoable" (S4-34 done): use only as "undoable, as a recorded and verified step, until a payment or email that depended on the resolution is released or dispatched; after that a person decides" (ALLOWED-NUMBERS N18 (d)).
