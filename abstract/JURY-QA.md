# JURY-QA: hardest hostile questions, with evidence pointers only (ABS-05)

anaya · 19 Nov 2026 · Reviewer: kabir (security scope) · Inputs: FACT-CARD.md (ABS-01), GUARDRAILS.md (ABS-02), TERMS.md (ABS-04), org/adr/THREAT-MODEL.md (SEC-01), tests/redteam/SPEC.md (SEC-02), research/RES-01, RES-06, RES-07, RES-11, SYNTHESIS.md, CALL-01.md (decisions checked against the source).

**What this is.** For each question: where the evidence lives, the one distinction that matters (note form, ≤12 words), and the trap a hostile juror is fishing for. **No answer prose.** Aarav answers in his own words (CHARTER).

**Tag key.** `#n` = fact-card row · `P/F/W/L/X` = GUARDRAILS row (`§1.5` = own-number table) · `D` = CALL-01 decision · `C1–C6` = THREAT-MODEL §4 claim · `B1–B4` = THREAT-MODEL §2 boundary · `rule n` = THREAT-MODEL §6 · `RT` = red-team test in SPEC §2 · `T§` = TERMS section · `SYN §` = SYNTHESIS · `RES-nn §` = research file.
**TM scope** (only on security questions, for kabir): **in** = in scope for the adopted threat model (CALL-01 "Threat model, adopted"; THREAT-MODEL §3); **out** = declared out of scope, with the production mitigation named there.
**Standing rule for every answer (v5, D-19).** Measured values come only from abstract/ALLOWED-NUMBERS.md (BENCH-S3, T=40, 20 seeds), each with its condition; any R = 0 carries D-17's release clause. Everything else is design or target. Every RT pass value stays a **target** until kabir's REDTEAM-S4 report (THREAT-MODEL §5 last line).

---

## Q1. "Isn't this just Airlock?"

- **Evidence:** #7, #8 · P4, P5, X1–X4 · D3 · C6 (refused: any Airlock comparison) · RES-11 §1 (TL;DR), §3 rows "Backward undo of landed effects" and "Tamper evidence", §4 Airlock #1–#6, §5 safe #1–#3 and must-not #1–#3 · SYN §1 niche bullet, §5 Airlock row.
- **Key distinction:** Airlock stops pre-commit; we revert landed writes and repair readers.
- **Second distinction (only if pushed):** journals "taken as reported, not authenticated" (RES-11 §4 #6) vs signed, witnessed record under a forging-agent threat model (F4, F12, C1).
- **Traps:**
  - Any comparative adjective ("better", "leaks", "sim-only", "scripted only"): Airlock reports 0 post-τ1 leaks and ran six LLM deployments on physical devices (RES-11 §1, §5 must-not #3; X3).
  - Bare "Airlock cannot undo": it is a declared design choice, and Airlock beats checkpoint rollback on its own metrics (X4).
  - "Today's tools kill one agent or all of them" as our insight: Airlock's own framing (X2).
  - "Airlock trusts agents' self-reports": **false**. Its daemon mediates every adapter "without relying on agent self-reporting" (RES-11 §2, §3.1 of Airlock). The gap is authentication of the journal, not mediation.
  - "Airlock has no provenance / reads": false. It has a provenance DAG with data edges and conservative input attribution (RES-11 §2 Taint).
  - Finer containment than Airlock: do not claim. Its min-cut can revoke a single effect class (RES-11 §3).
  - Using Airlock's ~10-agent scale limit against it: we are also ~10 agents, single host (L7).
  - "Guarantees": Airlock has a theorem (Thm 5); we do not (GUARDRAILS §3 "guarantees" row).
  - Pre-empt the metric fight: Airlock's "kept without redo" penalises our re-runs by construction (RES-11 §1 watch-out 2; W3, X27).

## Q2. "Wang et al. already did agent undo. And Retro/Warp did selective undo in 2010."

- **Evidence:** #14 · X1, X5, F1 · SYN §0 ("Killed" bullet), §5 rows Wang, State Footprints, Spark to Fire · RES-11 §1 watch-out, §5 must-not #2, §7 bullet 2 · RES-01 §1, §2.1–2.4, §4 (what breaks with LLM actors), §6.
- **Key distinction:** Wang: one agent's memory. Us: many authors, shared state, dependants.
- **Credit line, not a defence:** the systems idea (record dependencies, revert tainted, keep legitimate work) is Taser/Retro/Warp/Aire's; we carry it to multi-agent shared state (#14, X5). Aire's authorised repair is also prior art for signed recovery actions (RES-01 §2.3 #4; rule 10).
- **Traps:**
  - Saying anything about Wang beyond "single agent, rollback + selective replay": only the **Lacuna summary** was read (RES-11 §1, §7). Wang is not on the fact card: no numbers, no venue.
  - "First selective undo for agents" (X5); "first" anything (X1).
  - Claiming a single component is new; claim only the F1 **combination**.
  - Claiming Retro/Warp-style replay transfers to LLM agents: it does not (RES-01 §4 #1–#3); that is why D4 splits re-run vs re-plan.
  - State Footprints "rolls back" or has a venue: it is a vision paper, venue unconfirmed (X11, X12).
  - "We build and measure it" in past tense (tense rule).

## Q3. "Isn't this just logging? How is it different from OTel tracing?"

- **Evidence:** #11, #12 · P1, P5, F3, F4, F12, W5 · D6, D8 · rules 2, 3, 7, 8, 9, 11 · T§2 (record, recorder, read set, write set) · SYN §1 frame C, §4 principles 2–4 · RES-07 §1 (agents misreported their own actions), §3 Recorder bullet · RES-01 §4 #7 (log trust; Taser's separate backend) · RES-06 §5 (commit stores record no reads).
- **Key distinction:** Gateway records reads and writes; agent testimony never counts as evidence.
- **OTel sub-point:** `gen_ai.*` has no attribute for state read or written, and nothing Stable (#11); OTel is our **export path**, not a competitor (W5).
- **Traps:**
  - Saying "log" ourselves: banned term; use **record** (T§2). The word concedes the question.
  - "No one records reads": false. Airlock (data edges), Retro (SHA-1 of reads), Warp (row versions) all do (RES-11 §2; RES-01 §2.1–2.2). Our claim is the **combination** (F1) plus signed, witnessed records.
  - "Separate tamper-resistant store" as new: Taser's separate audit backend (RES-01 §2.4 #1).
  - "OTel `gen_ai` is all Development": say "not yet stable" (#11 note; SYN §2 row 11 is out of date).
  - "Integrated with OTel": a stated path, not an integration (W5, X28).
  - "Tamper-proof / immutable" (X15).
  - Privacy follow-up ("you log IBANs?"): record holds hashes, values in the side store (rule 9; T§2 side store).

## Q4. "LLMs aren't deterministic. How do you replay anything?"

- **Evidence:** F10, L6 · D4, D9 · CALL-01 §2 "Engineering resolutions: Determinism" (tick barrier; same seed twice gives byte-identical records; faulty run equals S\* before t0) · T§4 (re-run vs re-plan), T§5 (oracle S\*, seeded run) · SYN §4 principle 9 · RES-01 §1 bullets 2–3, §4 #1–#5 · RES-06 F1 (LangGraph replay re-runs nodes with different results) · SPEC §3 "Determinism holds".
- **Key distinction:** Deterministic steps re-run; LLM steps re-planned with human approval.
- **Notes:**
  - The **oracle S\*** itself depends on determinism: that is why finale agents are deterministic (D9), not a convenience.
  - Re-runs go through the outbox with idempotency keys, so no effect is sent twice (F10; target "re-emitted effects = 0", §1.5).
  - Neutral context only: Airlock's controlled comparison grids also use deterministic workers and ground-truth alerts (RES-11 §2, Evaluation).
- **Traps:**
  - "Replay" as our verb: banned synonym of re-run (T§4). We do not replay LLMs.
  - Automatic recovery of LLM work, "tested on LLM agents", "LLM replay" (X25).
  - Claiming our R/C targets carry over to LLM agents: no S\* exists for them in our design.
  - Recording model outputs as a fix: replays only the old, possibly poisoned behaviour (RES-01 §4 #2).
  - Promising the one-LLM-agent stretch goal (D9: only if the hero path is green by 30 Nov).
  - Re-plan as "autonomous repair": it is a queued item awaiting approval (F10).

## Q5. "Can't the agent just bypass your gateway?"

- **TM scope:** **in** (rogue agent, arbitrary Python in its subprocess; D11). **Out:** gateway/witness host compromise; agent and gateway under one OS user (production mitigation: separate uid/container); covert channels (THREAT-MODEL §3).
- **Evidence:** F2, L5, X24 · C2 · D7 (reconciliation mismatch = class U, hard evidence), D11 · rules 1, 2, 6 · B1, B2 · RT1 (variants a strict / b relaxed), RT2 · SPEC §3 "Single-uid limits" · CALL-01 §2 "Key isolation" and §5 Maya's dissent · SYN §4 principle 1 · #12 (MCP no-passthrough, draft spec) · RES-11 §4 Airlock #8 (Airlock makes the same "effects pass through a gateway" assumption).
- **Key distinction:** Bypass is caught by reconciliation; prevention needs per-agent uid.
- **Traps:**
  - "Impossible", "keys unreachable": say "caught", and "enforced in production (uid/container), detected here by reconciliation" (F2; C2 exact wording).
  - Claiming we **attribute** the bypass write: an off-gateway write has no author; root_candidates is empty (names nobody); RT1 only asserts no honest agent is suspended (SPEC RT1 open point).
  - Claiming reconciliation detects a key **read**: it detects unmediated writes only (C2 "refuse" column).
  - Covert channels / reading data around the gateway: out of scope, no claim (THREAT-MODEL §3).
  - "≤1 tick" stated as a result: it is RT1's pass target.
  - Separate uid: the live setup uses one (THREAT-MODEL "Live setup", setuid checked 19 Nov), but the claim stays C2 verbatim. If setuid fails, a key read voids C1/C4 for that run, unseen by reconciliation.
  - A juror acting from a host shell as the gateway's user: host compromise, not a break of C1–C6 (THREAT-MODEL §7 last line).

## Q6. "Can't a rogue agent forge actions or fake its own timestamps?"

- **TM scope:** **in** (rogue: forge, replay, clock games, persistence; THREAT-MODEL §3, §5). Colluding agents **in** only for naming root candidates (C3).
- **Evidence:** F4, F8, X17, X22, L3 · C3, C4 · D6, D7 · rules 2, 3, 4, 10, 11 · B1 · RT3 (= F5, LIVE), RT4, RT6, RT12, RT9 · T§1 (action envelope, act chain, seq) · CALL-01 §2 "Attribution of laundered writes".
- **Key distinction:** Gateway signs and sequences; bad signature suspends connection, not victim.
- **Traps:**
  - "A valid signature proves intent": it proves which key signed through which handle (C4 refuse column).
  - "Unforgeable" (X15).
  - Laundering: a laundered write carries the launderer's signature; we name **root candidates**, ranked, not a verdict (C3; RT9 target: intake in top 3; root candidate ≠ hard evidence, needs a click).
  - Saying a bad signature suspends "the agent" (X17; D7 anti-framing; RT3 pass: billing stays active).
  - Agent-supplied `ts`/`seq` being used for ordering: never; gateway assigns (rule 3; RT6).
  - Key theft as "solved": RT2 target 0 key bytes reachable; production wording C2.

## Q7. "Who watches the witness?"

- **TM scope:** **in** = insider who edits record files, holds **no** gateway or witness key and cannot write the witness head store. **Out** = gateway/witness host or root compromise; one insider holding **both** gateway and witness keys (production mitigation: HSM, split custody, WORM witness log) (THREAT-MODEL §3).
- **Evidence:** F12, X15, X16 · C1 · D6, D7 (tamper alert freezes recovery, suspends nobody) · B3, B4 · rule 8 (stall alert) · RT7 (= F6 line edit, LIVE), RT8 (= F6 full rewrite, LIVE; variants e, f, g; witness-stall test) · THREAT-MODEL §7 · T§2 (witness, verify, tamper-evident).
- **Key distinction:** Tamper-evident up to last witnessed head; detects, never prevents.
- **Notes:**
  - RT8 hands the attacker the **gateway key** (stronger than the threat model) to isolate what the witness adds. Do not generalise that to "survives gateway compromise" (X23).
  - RT8 variant g (rewrite only records after the last witnessed head) **passes when undetected**: it pins the claim boundary. Show it before a juror finds it (SPEC RT8 note).
- **Traps:**
  - "Tamper-proof", "immutable" (X15); Merkle/inclusion proofs, transparency log, "blockchain" (X16; T§2 bans "blockchain").
  - Calling the witness an independent third party: it is a separate process with its own key on the same host; host compromise is out (THREAT-MODEL §3).
  - Claiming protection after the last witnessed head (C1 refuse column).
  - Record **and** heads rewound to an older prefix: caught only against the head printed at run end; no printed head = out of scope (THREAT-MODEL §5 truncation row, "Detect, not exclude").
  - Saying a tamper alert suspends someone (D7; X17; RT7 pass: suspends nobody, recovery frozen).

## Q8. "Couldn't the hold window be cheated: by the agent racing it, or by you tuning it for the demo?"

- **TM scope (agent side):** **in** (rogue: TOCTOU flood, replay into outbox, persistence after suspend; colluding: laundering). **No claim:** splitting under thresholds (THREAT-MODEL §5, "no RT, no claim"); covert channels **out**.
- **Evidence (agent racing it):** F6, C5 · D8 · rules 4, 5 (epoch and deny-list in the write transaction; dispatcher re-checks holds) · RT5, RT4 (outbox variant), RT12, RT10 (dispatch re-check race hook), RT9 (laundered value held) · T§3 (lineage hold, sensitive field: early hold) · CALL-01 §2 "Early hold".
- **Evidence (us tuning it):** D10 (one config value) · BENCH-S3 F2+ H=0 system: R 0, irreversible released 0 (lineage hold stays on at H=0; ALLOWED N16) · D10 contrast, lineage hold off + pause with no recovery: 12 [6..18] payments escaped, >0 on 20/20 seeds (N17, "contrast, not a security result") · §1.5 protocol row · SYN §6 (≥20 seeded runs; median, p95, max; snapshot, revert-culprit-only, no-op baselines; collateral stall and false-positive cost) · T§7 gap 5 (hold value in the run-dir config so the scorer sees it).
- **Key distinction:** Holds follow recorded reads; hold zero shown and scored too.
- **Traps:**
  - Holding effects released **before** the alert: not held; at hold 0 scored as residual damage (C5 refuse column; F6).
  - Agent-declared lineage as the basis of a hold: never trusted; holds come from **recorded** read sets only (D8; C5; RT10 pass line).
  - "The hold is free": it delays honest irreversible effects; collateral stall and FP cost are reported (SYN §6). Measured cost: 3 [0..7] honest items held, median 5 operator releases (N4, N10); no seconds value exists (X21).
  - "We cancel / block" as containment: we hold, never cancel (X29; CALL-01 "Release semantics").
  - "0 escaped" without its condition: say H=6 and H=0 both with the lineage hold on (N7, N16); the 12 escaped is the contrast, never a system result (N17; X21).
  - Claiming H=0 means "no hold": the lineage hold is still on (GUARDRAILS F6 v5).

## Q9. "What about irreversible payments and emails?"

- **Evidence:** L1, F11, X14, X29, W4 · C5, C6 · D10 · T§3 (class C, I1, I2, U; outbox), T§4 (compensate; cancel (outbox item)) · RT10 (hero; H>0 vs H=0) and its F3 variant (PII email, pytest only) · #13 (sagas make "no effort" to notify readers) · RES-01 §1 bullet 4 (Retro/Aire also stop at external effects) · RES-06 §4 (no substrate covers them) · RES-11 §3 "External effects" row, §5 must-not corollary.
- **Key distinction:** Hold before release; afterwards compensate or report, never reverse.
- **Notes:**
  - Class I2 (uncontainable) runs only with prior human approval (T§3).
  - Terminology fork: containment **holds** and never cancels (X29); discarding a held item is a **recovery-plan step** (`cancel_outbox`) after the dry-run diff (F11; T§4). Do not merge the two.
  - Hero (B2-a): no cancel at all. Payments re-run under the same `outbox:<id>` v+1, re-held, then the operator unholds them with clean payloads (scripts/demo.sh line 5; GUARDRAILS F11 v5).
- **Traps:**
  - "Reverse", "undo", "refund" as our undo of a sent effect (X14; T§4 bans "reverse" for compensate).
  - Calling external effects Airlock's weak spot: it is Airlock's strongest part (RES-11 §3).
  - "Meets Art 14(4)(e) safe state": "maps to" only (W4; X19).
  - Hiding the contrast: show it with its label. Escape appears only with the lineage hold off and no recovery (N17); at H=0 with the lineage hold on, 0 escaped (N16). Do not present 12 as a system result.

## Q10. "Why not just use Dolt or git revert?"

- **Evidence:** P1, W5, X28 · D5 · RES-06 §1, F4 (Dolt revert-one-keep-later, verified in Dolt's engine tests), F5 (local git run: dependent edit conflicts), §3 table, §5 · SYN §0 "Confirmed" bullet, §5 Dolt/Git row · T§4 write-write conflict, T§6 snapshot and revert-culprit-only baselines · F9 (revert only provable writes, else re-run or flag).
- **Key distinction:** Dolt reverts commits but records no reads; dependants invisible.
- **Traps:**
  - "Dolt can't revert one commit": it can, and keeps later commits (RES-06 F4).
  - "Runs on Dolt" / "integrated": own row-versioned SQLite; Dolt is the production twin (D5; X28).
  - Quoting RES-06 §4's "Dolt as substrate" recommendation: overridden by D5.
  - Dolt performance numbers: RES-06 never ran Dolt (F4/§4 caveat). The git run is one toy example, not a benchmark (RES-06 §5).
  - Overclaiming conflict handling: a write-write conflict is **flagged**, not merged (T§4; F9).
  - Hero conflict line (CALL-02): triage's edit on the same supplier is **kept**, no flag; the IBAN is its own field object, so they share no datum (W6; CALL-02 B1–B3). Do not call it a conflict.
  - "So you never get a conflict?": an honest one exists in bench **F2+x** (triage edits the price row crm wrote → row-level write-write conflict → flag). Give **both rows** (D-18, CALL-04 decision 2; FACT-CARD O5/O6; ALLOWED N15/N18), medians over 20 seeds, T=40, H=6, container. **Before resolver** (default, resolver off): R 1/5, C 21/254, 29 honest items held; the flag waits for a human because the bench approver never resolves flags. **With resolver ww_rebase/1 (on)**: R 0, C 0, 3 honest items held, after the operator released 5 items (3 honest, 2 tainted-lineage re-run and re-held; D-17); 1 resolution on 19/20 seeds (s7 had no conflict); verify OK on all 40 runs; hero unchanged off/on. Quote all three values per row and both rows together. Show it, do not hide it (L9; CALL-02 B5). Conflicts are field-level only for sensitive fields, row-level elsewhere (F9).
  - "So the resolver auto-merges conflicts?": no. It is opt-in, and it rebases one honest deterministic write on the last clean version as one signed record that `ks verify` checks and `ks recover --unresolve` undoes (ADR-05a §1, §5). It **refuses** the suspect, every alert's `root_candidates[0]`, evidence writers, taint-origin (seed) writers, and LLM, system and suspended agents; anything that fails a check waits for a human (ADR-05a §1, §2a). Nothing is merged by hand, no value invented.
  - "Can a compromised resolver or a colluder slip a bad value through?": known limits, stated as such (THREAT-MODEL Errata, D-18 entry): verify checks the resolution's rule, order, binding and clean inputs, **not the re-computed value** (trusted to `ks.recovery`, TCB); a colluder outside the refused set that copies the culprit's value from its own memory into its args would carry it into the rebased write (C3, no prevention claim). Post-finale: `ks verify --reexec-resolutions` (design, not built).

## Q11. "Any real incident where this happened? Would this have stopped the METR / OpenAI–Hugging Face case?"

- **TM scope (METR part):** the board was coordination over a channel no gateway mediated (Artifactory cache namespace, #2): covert channels are **out**; collusion is **in** only as "root candidates, no prevention" (C3).
- **Evidence:** #1, #2, #3, #9, #10 · P2, P3, X6, X7, X8 · D2 · FACT-CARD "Not safe to print" and "Notes on the A~ rows" · SYN §0 "Partly overturned" · RES-07 §1, §2.1 (7 incidents), §2.4 (would selective rollback have helped?), §4 · RES-11 §6.
- **Key distinction:** Incidents are single-agent; METR shows only a blunt stop failing.
- **Notes:**
  - No public case of agent B consuming agent A's bad write and being repaired (SYN §0; RES-07 §2.4 last para). The dependency risk rests on the literature, and we say so (P1 condition; X6).
  - RES-07 §2.4: selective rollback would **not** have fixed most catalogued incidents (rm -rf, Antigravity, PocketOS); the levers there were gating and credential scope.
  - 3 of 7 incidents are disputed or partly unverified (RES-07 §1): "reportedly" + AIID IDs (#9).
- **Traps:**
  - "We would have stopped it" (X7; D2), or METR as B-on-A (X6). It was collusion inside an evaluation.
  - "Internal" or "cyber" evaluation: METR says neither (#1 note, re-checked today). **GUARDRAILS P2 and SYN §2 row 1 still say "internal OpenAI cyber evaluation"; the fact card wins (D13).**
  - Exact dates/times, "11 days to detect", "legitimately held credentials" (X8; fact card "Not safe to print"). SYN §2 rows 1–2 and RES-11 §6 still carry exact dates: do not lift them.
  - SYN §1 hook bullet "forensics came weeks later" and "METR read ~1,300 transcripts": not on the fact card; do not quote.
  - "Multi-agent incidents are common" (X6); "our tool would have saved PocketOS" (RES-07 §2.4).

## Q12. "What if detection is wrong and you suspend a good agent? Or miss the bad one?"

- **TM scope:** **in** (rogue tricking auto-suspend of an honest agent, RT11; buggy-agent false positive). Semantic influence **out** (we over-taint).
- **Evidence (false positive):** F7, F8, L2, X17, X18 · D7 · C4 · rule 10 (`release` = fresh epoch; lifts suspension holds only, CALL-02 D4) · RT11 (framing DoS: FP cost reported, recomputed, not thresholded; `false_accusations` counted against us), RT1 (unattributable mismatch suspends no honest agent), RT3 (connection, not victim), RT9 (root candidate needs a click) · T§3 (suspend, revoke, release) · §1.5 collateral loss C (target 0) · SYN §6 (false accusations, FP cost).
- **Evidence (miss):** F5, X30 · SYN §4 principle 6 · T§3 invariant detector · §1.5 TTI-detect (definition only) · THREAT-MODEL §5 splitting row · neutral context: Airlock's safety is also relative to the alert's declared source set (RES-11 §4 Airlock #7).
- **Key distinction:** Suspend is reversible; revoke needs a human; false positives scored.
- **Traps:**
  - "Auto-kill", "no human in the loop" (X18); "kill" as an operation (T§3 note).
  - Any FP rate or detection accuracy number (X21; D13). Any "beats Who&When" (X20).
  - "We detect any misbehaviour": only declared data invariants and hard evidence (X30).
  - Over-taint presented as free: collateral holds are possible by design (L2); independents keep running is the RT10 target, not a result.

## Q13. "Is R = 0 just the operator releasing things by hand?"

- **Evidence:** ALLOWED-NUMBERS N4, N10 · BENCH-S3 §F2+ H=6 rows `fp_cost.operator_unholds.total/.honest/.tainted`, `fp_cost.held_honest_actions` · D-17 (CALL-02 resolutions B2-b) · TERMS §5 clean recovery · scripts/demo.sh line 5 (unhold step) · FACT-CARD O1–O2 (demo seed 2: 9 released, 7 honest).
- **Key distinction:** Releases are logged decisions; R still counts anything held at T.
- **Notes:**
  - F2+ medians: 5 released [1..9] = 3 honest [0..7] + 2 tainted-lineage [1..2]. Tainted-lineage = payments recovery re-ran and re-held; they leave with clean payloads.
  - Honest holds are the sensitive-field hold's over-taint cost (L2), not recovery errors.
  - Items still held at run end count as left in R (TERMS §5), so not releasing would raise R, not hide it.
- **Traps:**
  - Bare R = 0 anywhere (D-17).
  - Calling the releases automatic: they are operator `ks contain unhold` steps.
  - Calling released tainted-lineage items "tainted payments sent": the payloads were re-run and clean.
  - [Our view, gap] The console scorecard does not yet show release counts (S4-19); point to score.json until it does.

---

## Also likely (one-line pointers, no full entry)

| Question | Pointers |
|---|---|
| "Is it compliant with the AI Act?" | W4, X19, #15: "maps to" Art 12(1), 14(4)(e); article numbers only, no regulation number |
| "Does it beat Who&When?" | F5, X20, X9, #4–#6: different task (lookup vs inference); quote #4 with its setting, one 53.5 only |
| "Does it scale?" | L7, X28: ~10 agents, single host, tick barrier |
| "Doesn't over-tainting just become kill-everything?" | L2, F6, RT10 (independents' outbox never held, target), Airlock App. F via RES-11 §4 #9 |
| "Can you stop prompt injection / collusion?" | X23, C3, THREAT-MODEL §3: contain and recover effects only |
| "Why not least privilege instead?" | RES-07 §2.4 and §3 (credential scope was the lever in single-agent cases); complementary, not either/or |
| "Why is it called Kill Switch if you never kill?" | T§3 note: project name only; operations are suspend, revoke, lineage hold |

## Inconsistencies found while compiling (for zoya / Aarav; not fixed here)

1. GUARDRAILS P2 condition and SYN §2 row 1 say "internal OpenAI cyber evaluation"; FACT-CARD #1 note (re-checked 19 Nov) says METR does not say "internal" or "cyber". Fact card governs (D13).
2. SYN §2 row 11 says OTel `gen_ai.*` "all Development"; FACT-CARD #11 says "not yet stable", not "all Development".
3. SYN §2 rows 1–2 and RES-11 §6 carry exact HF/METR dates and 23:00 UTC, banned by the fact card.
4. RES-11 §3 "Us" column is STRAWMAN-era (per-agent revoke, "cancel in-flight", "single process", "signed chain head"): superseded by D6–D8 and C6 (per-action lineage hold, separate subprocesses, witness, hold never cancel). Do not cite it as our design.
5. RES-11 §5 safe #3 and RES-01 use "ground truth"; T§5 locks "oracle (S\*)". RES-01 §5 "do not re-run agents" is superseded by D4.
6. RES-06 §1/§4 recommends Dolt as substrate; superseded by D5.

## Changes (ABS-08, zoya, 19 Nov; CALL-02 freeze)

- Q10: hero conflict line updated: triage's edit is **kept**, no flag; the honest conflict lives in bench F2+x (R > 0), with field-or-row granularity. Nothing else edited.
- Resolved by PMO (19 Nov) after CALL-02: Q5 trap cites `Alert.suspect` (no such field; suspect = `root_candidates[0]`, TERMS §1); Q4 note cites "T§7 gap 7: `idempotency_key` not yet a contract field" (resolved: C3 `OutboxItem.idempotency_key`); Q12 cites rule 10 "`release` = un-hold + restore epoch" (CALL-02 D4: fresh epoch, lifts suspension only).

## Changes v5 (S4-18, zoya, 21 Nov; D-19, D-17, B2-a)

- Standing rule: measured values from ALLOWED-NUMBERS only; RT pass values stay targets until REDTEAM-S4.
- Q8: H=0 keeps the lineage hold (0 escaped); D10 contrast (12 escaped) labelled; measured hold cost added.
- Q9: hero has no cancel (B2-a, operator unhold); hold-0 trap rewritten to the labelled contrast.
- Q10: F2+x measured values, "before resolver" (D-18).
- New Q13: operator releases and R = 0 (D-17).

## Changes (S4-11, anaya, 21 Nov; D-18, D-17)

- Q10: F2+x now gives the before-resolver row (N15) and the with-resolver ww_rebase/1 row (N18, BENCH-S3 §S4-13, container), plus two traps: what the resolver will not do, and its known limits (collusion; verify trusts the recorded value).
