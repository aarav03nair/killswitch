# SKELETON: abstract outline for Aarav to fill in (ABS-06)

zoya · 19 Nov 2026 · v2 (panel fixes) · Inputs: FACT-CARD.md (ABS-01), GUARDRAILS.md (ABS-02), TERMS.md (ABS-04), CALL-01.md D1/D2/D3/D12/D13, CALL-01/zoya.md §2, research/RES-08.md (headline, ref [19]).

**What this is.** Headings, word budgets and note-form points only. No line here is a sentence to paste; Aarav writes every word (CHARTER).
**Tag key.** `#n` = fact-card row (R = RBI spare) · `P/F/W/L/X` = GUARDRAILS row · `§1.5` = GUARDRAILS own-number table · `T:` = locked TERMS word to use · `D` = CALL-01 decision.
**Priority key.** `MUST` = land it · `IF-ROOM` = add only while the section total still holds · `Guard:` lines = checks, not points; they cost no words and carry no tag · `Scores:` lines = which of the brief's three scores the subsection answers.
**Before writing.** D1 is marked ⚑: confirm the layered headline (gap → provenance → selective undo → testimony vs evidence).

## Word budget (organisers' order: problem → fix → why it matters, plus limits)

| Section | Words | MUSTs (cap ≈ 1 per 15 words) |
|---|---|---|
| 0 Title + subtitle | 15 | 0 |
| 1 Problem (1a 100 · 1b 90 · 1c 110) | 300 | 19 (6 · 6 · 7) |
| 2 Fix (2b 80 · 2c 45 · 2d 65 · 2e 95 · 2f 45) | 330 | 21 (5 · 3 · 4 · 6 · 3) |
| 3 Why it matters (3a 60 · 3b 70 · 3c 40) | 170 | 10 (4 · 4 · 2) |
| 4 Limits + what we will show (45 + 40) | 85 | 5 (3 · 2) |
| **Total** | **900** (allowed range 850–950; hard cap 1,000) | **55** (cap 60) |

**Binding rule.** Section totals are binding; subsections are ±15 words; bullet order inside a subsection is free. ABS-07 reviewers enforce section totals and MUST coverage, not micro-budgets.

---

## 0. Title ideas (keyword combos only, ~15 words with subtitle)

- IF-ROOM Kill Switch (project name) + undo one agent + keep the rest
- IF-ROOM dependency gap · shared state · multi-agent undo
- IF-ROOM provenance + selective undo + honest agents' work
- IF-ROOM evidence, not testimony · agent record
- IF-ROOM who changed it · who read it · undo
- IF-ROOM subtitle slot → mechanism words: provenance, read sets, witness

Guard: avoid first, novel, tamper-proof, kill (as an operation), rollback [X1 · §3 words · T]

## 1. Problem (300)

### 1a. The gap, shown with the example (100; the abstract opens here, D1)

- MUST brief's frame: ten agents, one broke something; undo "without discarding" others' work [CHARTER]
- MUST crm swaps a supplier IBAN · the scenario we will show, not a real incident [D12 · W6 · T: hero scenario (F2+)]
- MUST billing, payments, comms acted on it → payment + email pending [D12]
- MUST inventory, docs never read it → untouched [D12 · T: independent agents]
- MUST their work: honest AND built on the bad write [P1 · T: culprit, honest agent]
- MUST → "undo crm" undefined: dependency problem ≠ snapshot problem [P1 · D1]
- IF-ROOM dependency risk → source = literature, not incidents; say so [P1 · D2 · X6]

Guard: ×10 price change → in the data, out of the story [D12]
Guard: words agent, culprit, honest agent; never bot / victim [T §1]

### 1b. Blunt tools fail (90; the hook evidence, D2)

- MUST METR on OpenAI/HF → blunt stop failed at scale; nothing more [#1–#3 · P2 · D2]
- MUST scale: roughly 1,200 agents; roughly 700 in the attack [#1]
- MUST board wiped → new board about two days later [#2]
- MUST qualifiers: METR, preliminary · July 2026 · ExploitGym evaluation runs [#1]
- MUST single-agent pattern: seconds to break, days to repair · reportedly [#10 · P3]
- MUST PocketOS: 9 s · three-month-old snapshot · a weekend · per the founder, as reported [#10]
- IF-ROOM OpenAI's hindsight quote, via Al Jazeera [#3]
- IF-ROOM catalogued incidents → only as qualifier: single-agent, in our search [#9 · X6]

Guard: new board's route, if named → Artifactory cache namespace ≠ credentials [#2 · X8]
Guard: ✗ internal / cyber [#1]
Guard: ✗ exact days, "11 days", "would have stopped it" [X7 · X8]

### 1c. What exists, where it stops (110, including the Airlock box and its 4 MUSTs)

- MUST agent's own record = testimony, not evidence [P5 · D1]
- MUST attribution today = inference: ~53.5% agent / ~14.2% step · GPT-4o · best strategies [#4 · P6]
- MUST niche = the combination: multi-agent + per-author + shared state + dependants [F1 · X1]
- IF-ROOM sagas: compensation runs, readers never told [#13 · P1]
- IF-ROOM OTel `gen_ai.*`: no read/write attribute; not yet stable, Nov 2026 [#11]
- IF-ROOM FAMAS: 20 replays · ~105 min per attribution · arXiv preprint [#6 · X11]
- IF-ROOM random baseline 12–29% / 4–19%, by subset [#5]

Guard: P5's Airlock journal point → inside the same clause, or unnamed [D3]
Guard: different strategy per number; ✗ "one method gets" [#4 · X9]
Guard: ✗ "first" / "only" / "nobody" [X1 · X5]

### Box: the one Airlock clause (≈20–30 words; what it must convey, D3)

- MUST named once: Airlock, arXiv 2611.06727, credited [D3]
- MUST theirs = forward containment of multi-agent faults [#8 · P4]
- MUST by design: committed effects + absorbed state → "orthogonal rollback" [#8 · X4]
- MUST ours = backward half, after commit → "complementary" [P4 · D3]

Guard: no #7 numbers in the clause (no room beside the four MUSTs)
Guard: ✗ better, leaks, sim-only, bare "cannot undo", second mention [X2 X3 X4]

## 2. Fix (330)

### 2b. One mediated path + the record (80; provenance = organising idea, D1; opens by walking the 1a example)

- MUST walk the IBAN example from 1a into the gateway [D12 · W6]
- MUST provenance → named here as the organising idea [D1]
- MUST every action → gateway, as a signed action envelope [F2 · T: gateway, action envelope]
- MUST adapters → read set + write set, row level; agents never self-report [F3 · D8 · T: read set, write set]
- MUST outcome: provenance graph, change → author, read → source [T: provenance graph]
- IF-ROOM bypass writes → caught by reconciliation [F2 · T: reconciliation]
- IF-ROOM agent signature + gateway signature; gateway assigns seq [F4 · T: sequence number (seq)]
- IF-ROOM MCP draft, no token passthrough, as alignment [#12]

Guard: bypass → "caught", ✗ "impossible" [F2]
Guard: signature ⇒ which key signed; ≠ intent [F4]
Guard: declared lineage ignored [D8]

### 2c. Identify (45)

Scores: brief's time-to-identify → TTI-detect / TTI-attribute (defined once, in 3b) [CHARTER]

- MUST invariant detector on the data → alert (IBAN changed, unapproved) [F5 · T: invariant detector, alert]
- MUST attribution = lookup on signed records ≠ inference [F5 · contrast #4–#6]
- MUST collusion / laundering → root candidates, ranked, not a verdict [L3 · X22 · T: root candidates]

Guard: different task from Who&When → ✗ "beats" [X20]

### 2d. Contain (65)

Scores: brief's time-to-contain → TTC (defined once, in 3b) [CHARTER]

- MUST graded containment: auto-suspend on hard evidence; anomalies one click; revoke after confirmation [F7 · X18 · T: graded containment, suspend, revoke]
- MUST hard evidence: scope breach · I-class invariant breach · reconciliation mismatch (class U) [F7 · D7 · T: class U]
- MUST lineage hold per action on tainted reads; inventory, docs keep running [F6 · D8 · T: lineage hold, independent agents]
- MUST payment + email → held in the outbox, never cancelled here [F11 · X29 · T: outbox]
- IF-ROOM anti-framing: bad signature → submitting connection suspended, not the agent [F8 · D7]
- IF-ROOM epoch bump → culprit's in-flight envelopes invalid [T: epoch]

Guard: ✗ kill · quarantine · block · cancel (as containment) [T §3 · X29]

### 2e. Recover (95; selective undo = the payoff, D1)

Scores: brief's clean recovery → residual damage R 0 + collateral loss C 0 (defined in 3b) [CHARTER]

- MUST payoff = selective undo: taint-scoped revert, only writes still at the culprit's after-version [D1 · F9 · T: taint-scoped revert]
- MUST triage later edits the same crm row → write-write conflict → flag, no overwrite [F9 · T: write-write conflict, flag]
- MUST dependants: deterministic → re-run via outbox, idempotency keys; LLM → re-plan, approval [F10 · D4 · X25 · T: re-run, re-plan]
- MUST irreversible: hold window → compensate or report; ✗ reverse [F11 · X14 · L1 · T: compensate]
- MUST held payment → cancel (outbox item), a step in the approved recovery plan [F11 · T: cancel (outbox item), recovery plan]
- MUST credit Taser, Retro, Warp, Aire → carried to multi-agent shared state + dependants [#14 · X5 · F1]
- IF-ROOM records append-only; nothing erased [F9]
- IF-ROOM over-taint > under-taint, by design (L2 states it in Limits) [F9 · L2]
- IF-ROOM recovery plan → dry-run diff → approval → run [T: dry-run diff]

Guard: "selective undo" in headline prose only; elsewhere taint-scoped revert [D1 · T §4]

### 2f. Audit (45)

- MUST hash chain + separate witness process, (seq, head, tick) per tick [F12 · D6 · T: witness]
- MUST `verify` → tamper-evident up to the last witnessed head [F12 · X15 · T: verify, tamper-evident]
- MUST jury break, live: `ks inject`, rogue agent, `state.db` bypass, record edit, chain rewrite [F13 · D11 · T: inject, rogue agent]
- IF-ROOM `verify` checks: chain · signatures · witness heads · seq gaps · reconciliation [F12]
- IF-ROOM tamper alert → recovery frozen, nobody suspended [X17 · D7]

Guard: detect ≠ prevent · ✗ Merkle · ✗ blockchain [X15 X16]

## 3. Why it matters (170)

### 3a. Testimony vs evidence (60; D1)

- MUST brief: "an agent that can be audited, not only demoed" → answered here [CHARTER]
- MUST agent's own record = testimony · gateway record = evidence [P5 · D1]
- MUST audit holds against the audited agent, within the threat model [W2 · L4]
- MUST trust placed only in gateway + witness [§3 "trustless" row]

Guard: "within the threat model" on every such claim [W2 · L4]

### 3b. Scored, not self-graded (70; D13)

- MUST brief's three scores: no agreed measurement in the standards we checked → we define checkable ones [RES-08 headline · W7]
- MUST TTI-detect t0 → alert · TTI-attribute alert → culprit · TTC alert → first denied envelope [§1.5 · D13 · CHARTER]
- MUST recovery scored vs oracle (S\*) = same run, culprit removed; not our taint graph [W1 · T: oracle (S*)]
- MUST residual damage R, collateral loss C (in full) · targets 0 → clean recovery [§1.5 · D13 · T §5 note · T: clean recovery]
- IF-ROOM targets 0: post-alert tainted, irreversible tainted released, re-emitted effects [§1.5]
- IF-ROOM re-plan and re-run cost → reported openly [W3 · X27]

Guard: TTI/TTC = definitions only; no seconds [§1.5 · D13 · X21]
Guard: alongside containment-style metrics, not instead; no second Airlock name [W1 · D3]
Guard: label "target"; future tense [D13]

### 3c. Path to banking (40)

- MUST "maps to" AI Act Art 12(1) logs, Art 14(4)(e) "safe state" [#15 · W4 · X19]
- MUST enterprise path: OTel export, policy-as-code; Dolt, agentgateway = production twins [W5]
- IF-ROOM high-risk dates 2 Dec 2027 / 2 Aug 2028 [#15]
- IF-ROOM NIST AI RMF MANAGE 4.3 → reference only, no number [W4 · RES-08 [19]]
- IF-ROOM RBI FREE-AI accountability line → only after checking exact words [R]

Guard: production twins ≠ integrations [W5 · X28]

## 4. Limits + what we will show (85)

### Limits (45; one or two lines)

- MUST irreversible effects → hold, compensate, report only [L1]
- MUST over-taint by design → collateral holds possible [L2]
- MUST deterministic finale agents; LLM → re-plan [L6]
- IF-ROOM out-of-scope list (host compromise, covert channels, injection) [L4]
- IF-ROOM collusion → root candidates [L3]
- IF-ROOM ~10 agents · single host · tick barrier [L7]

Guard: key isolation, if mentioned → enforced in production, detected here [L5 · X24]

### What we will show (40; future tense, D13)

- MUST ≥20 seeded runs · median, p95, max · "planned" [§1.5 · T: seeded run]
- MUST baselines: snapshot · revert-culprit-only · no-op [§1.5 · T: snapshot baseline, revert-culprit-only baseline]
- IF-ROOM hold window 0 vs >0; escaped payment at 0 → residual damage [D10 · T: hold window]
- IF-ROOM threat model published before the jury's break attempts [F13 · D11]

Guard: prototype from 25 Nov → ✗ achieved / showed / measured [GUARDRAILS tense rule]

---

## 5-minute writing plan (Aarav)

1. **Fix first (§2)**: you know the design best; walk the IBAN example from 1a through 2b–2f. Write every MUST; add IF-ROOM points only while the section total holds.
2. **Problem (§1)**: open on 1a with the IBAN example (show the gap, do not tell it), then 1b with FACT-CARD open beside you; write the Airlock clause last.
3. **Why it matters (§3), then Limits (§4)**, then pick the title from §0 keywords.
4. **Check**: section totals (850–950 overall) → every MUST present → GUARDRAILS §4, all 12 items → Ctrl-F the TERMS banned synonyms. Re-run §4 after any cut.
5. **Send for ABS-07**: own words only, typed in your editor, nothing pasted from this kit or any AI chat. Save as `abstract/DRAFT-R1.md`, one sentence per line (comments cite lines), then `python3 org/issue.py log ABS-07 --who aarav --msg "R1 draft ready: abstract/DRAFT-R1.md"`. Round 1 on 21 Nov AM, round 2 PM, 4 h turnaround each, comments only; you submit 22 Nov.

---

## Changes v2 (panel review, 19 Nov)

- Must-fix 1: every point bullet tagged MUST or IF-ROOM; 55 MUSTs against a cap of 60 (≈1 per 15 words), per-subsection counts in the budget table. Rules and ✗ lists moved to untagged `Guard:` lines (checks, no word cost).
- Demoted to IF-ROOM as listed: 1b #3 hindsight and #9 catalogued incidents (kept only as the "single-agent, in our search" qualifier); 1c sagas #13, OTel #11, FAMAS #6, random baseline #5; 2b MCP #12; 2d epoch and anti-framing; 2e append-only, over-taint, dry-run chain ("approved recovery plan" kept in the cancel bullet); 2f tamper-alert freeze.
- Airlock box: optional #7 numbers deleted, with the "dense spread" qualifier line that only applied to them; Guard added: no #7 numbers in the clause.
- TTI/TTC defined once, in 3b; duplicates in 2c/2d removed. Binding rule added under the budget table (section totals binding, subsections ±15, bullet order free).
- Must-fix 2: 1a reframed on the brief's own "without discarding" clause, shown with the IBAN example (moved from 2a; ×10 Guard moved with it; triage's write-write conflict now first appears in 2e). 2a deleted; 2b opens by walking the example.
- Rebudget: 1a 100 · 1b 90 · 1c 110 · 2b 80 · 2d 65 · 2e 95 · 2f 45; totals unchanged (300 / 330 / 900).
- `Scores:` line under 2c / 2d / 2e maps Identify / Contain / Recover 1:1 to the brief's time-to-identify / time-to-contain / clean recovery.
- Should-fix: 3a tags the brief's "audited, not only demoed" [CHARTER]; 3b adds the RES-08 headline bullet (no agreed measurement in the standards we checked → we define checkable ones), filed as GUARDRAILS W7.
- Nits: 1b → "✗ internal / cyber [#1]" (stale "card #1 overrides P2" flag dropped, P2 fixed in ABS-02 v2); 2d → "reconciliation mismatch (class U)"; 3c NIST MANAGE 4.3 tagged RES-08 [19]. Writing plan steps 1, 2 and 4 updated for the 1a move and MUST check.
