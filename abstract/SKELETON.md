# SKELETON: abstract outline for Aarav to fill in (ABS-06)

zoya · 19 Nov 2026 · Inputs: FACT-CARD.md (ABS-01), GUARDRAILS.md (ABS-02), TERMS.md (ABS-04), CALL-01.md D1/D2/D3/D12/D13, CALL-01/zoya.md §2.

**What this is.** Headings, word budgets and note-form points only. No line here is a sentence to paste; Aarav writes every word (CHARTER).
**Tag key.** `#n` = fact-card row (R = RBI spare) · `P/F/W/L/X` = GUARDRAILS row · `§1.5` = GUARDRAILS own-number table · `T:` = locked TERMS word to use · `D` = CALL-01 decision.
**Before writing.** D1 is marked ⚑: confirm the layered headline (gap → provenance → selective undo → testimony vs evidence).

## Word budget (organisers' order: problem → fix → why it matters, plus limits)

| Section | Words |
|---|---|
| 0 Title + subtitle | 15 |
| 1 Problem (1a 70 · 1b 110 · 1c 120) | 300 |
| 2 Fix (2a 40 · 2b 70 · 2c 45 · 2d 60 · 2e 75 · 2f 40) | 330 |
| 3 Why it matters (3a 60 · 3b 70 · 3c 40) | 170 |
| 4 Limits + what we will show (45 + 40) | 85 |
| **Total** | **900** (allowed range 850–950; hard cap 1,000) |

---

## 0. Title ideas (keyword combos only, ~15 words with subtitle)

- Kill Switch (project name) + undo one agent + keep the rest
- dependency gap · shared state · multi-agent undo
- provenance + selective undo + honest agents' work
- evidence, not testimony · agent record
- who changed it · who read it · undo
- subtitle slot → mechanism words: provenance, read sets, witness
- avoid: first, novel, tamper-proof, kill (as an operation), rollback [X1 · §3 words · T]

## 1. Problem (300)

### 1a. The gap (70; the abstract opens here, D1)

- brief's frame: ten agents, one broke something [CHARTER]
- undo = dependency problem ≠ snapshot problem [P1 · D1]
- "undo X" undefined ⇐ other agents already read X [P1]
- honest agents' work built on the bad write [P1 · T: culprit, honest agent]
- dependency risk → source = literature, not incidents; say so [P1 · D2 · X6]
- words: agent, culprit, honest agent; never bot / victim [T §1]

### 1b. Blunt tools fail (110; the hook evidence, D2)

- METR on OpenAI/HF → blunt stop failed at scale; nothing more [#1–#3 · P2 · D2]
- scale: roughly 1,200 agents; roughly 700 in the attack [#1]
- board wiped → new board about two days later [#2]
- mechanism: Artifactory cache namespace ≠ credentials [#2 · X8]
- qualifiers: METR, preliminary · July 2026 · ExploitGym evaluation runs [#1]
- "internal OpenAI cyber evaluation" ✗ → card #1 overrides P2 [#1]
- optional: OpenAI's hindsight quote, via Al Jazeera [#3]
- single-agent pattern: seconds to break, days to repair [#9 #10 · P3]
- PocketOS: 9 s · three-month-old snapshot · a weekend [#10]
- PocketOS qualifier: per the founder, as reported [#10]
- catalogued incidents: single-agent · reportedly · in our search [#9 · X6]
- ✗ exact days, "11 days", "would have stopped it" [X7 · X8]

### 1c. What exists, where it stops (120)

- forward containment exists → the one Airlock clause (box below) [#8 · P4 · D3]
- sagas: compensation runs, readers never told [#13 · P1]
- OTel `gen_ai.*`: no read/write attribute; not yet stable, Nov 2026 [#11]
- agent's own record = testimony, not evidence [P5 · D1]
- P5's Airlock journal point → inside the same clause, or unnamed [D3]
- attribution today = inference, about half right at agent level [#4 · P6]
- ~53.5% agent / ~14.2% step · GPT-4o · best strategies [#4]
- different strategy per number; ✗ "one method gets" [#4 · X9]
- optional: random baseline 12–29% / 4–19%, by subset [#5]
- FAMAS: 20 replays · ~105 min per attribution · arXiv preprint [#6 · X11]
- niche = the combination: multi-agent + per-author + shared state + dependants [F1 · X1]
- ✗ "first" / "only" / "nobody" [X1 · X5]

### Box: the one Airlock clause (≈20–30 words; what it must convey, D3)

- named once: Airlock, arXiv 2611.06727, credited [D3]
- theirs = forward containment of multi-agent faults
- by design: committed effects + absorbed state → "orthogonal rollback" [#8 · X4]
- ours = backward half, after commit → "complementary" [P4 · D3]
- optional: native-control numbers, inside the same clause, as their benchmark [#7 · X2]
- "under dense spread" ≠ +68 to +96 pp qualifier (ABS-01 fix) [#7]
- ✗ better, leaks, sim-only, bare "cannot undo", second mention [X2 X3 X4]

## 2. Fix (330)

### 2a. Running example (40; D12)

- crm swaps a supplier IBAN [D12 · W6 · T: hero scenario (F2+)]
- billing, payments, comms read it → payment + email pending
- triage later edits the same crm row [T: write-write conflict]
- inventory, docs never read it [T: independent agents]
- label: the scenario we will show, not a real incident [W6]
- ×10 price change → in the data, out of the story [D12]

### 2b. One mediated path + the record (70; provenance = organising idea, D1)

- provenance → named here as the organising idea [D1]
- every action → gateway, as a signed action envelope [F2 · T: gateway, action envelope]
- bypass writes → caught by reconciliation; ✗ "impossible" [F2 · T: reconciliation]
- gateway adapters → read set + write set, row level [F3 · T: read set, write set]
- agents never self-report; declared lineage ignored [F3 · D8]
- agent signature + gateway signature; gateway assigns seq [F4 · T: sequence number (seq)]
- signature ⇒ which key signed; ≠ intent [F4]
- optional: MCP draft, no token passthrough, as alignment [#12]
- outcome: provenance graph, change → author, read → source [T: provenance graph]

### 2c. Identify (45)

- invariant detector on the data → alert (IBAN changed, unapproved) [F5 · T: invariant detector, alert]
- attribution = lookup on signed records ≠ inference [F5 · contrast #4–#6]
- different task from Who&When → ✗ "beats" [X20]
- collusion / laundering → root candidates, ranked, not a verdict [L3 · X22 · T: root candidates]
- brief's time-to-identify → TTI-detect, TTI-attribute, definitions only [§1.5 · D13]

### 2d. Contain (60)

- graded containment → auto-suspend on hard evidence only [F7 · T: graded containment, suspend]
- hard evidence: scope breach · I-class invariant breach · class U [F7 · T: class U]
- anomalies → one click; revoke after confirmation [F7 · X18 · T: revoke]
- lineage hold per action: recorded read set touches tainted versions [F6 · D8 · T: lineage hold]
- payment + email → held in the outbox, never cancelled here [F11 · X29 · T: outbox]
- inventory, docs keep running [F6 · T: independent agents]
- anti-framing: bad signature → submitting connection suspended, not the agent [F8 · D7]
- optional: epoch bump → culprit's in-flight envelopes invalid [T: epoch]
- brief's time-to-contain → TTC, definition only [§1.5]
- ✗ kill · quarantine · block · cancel (as containment) [T §3 · X29]

### 2e. Recover (75; selective undo = the payoff, D1)

- "selective undo" → headline prose only; elsewhere taint-scoped revert [D1 · T §4]
- taint-scoped revert: only writes still at the culprit's after-version [F9 · T: taint-scoped revert]
- triage's later edit → write-write conflict → flag, no overwrite [F9 · T: flag]
- recovery plan → dry-run diff → approval → run [T: recovery plan, dry-run diff]
- deterministic honest steps → re-run via outbox, idempotency keys [F10 · D4 · T: re-run]
- LLM steps → re-plan, queued for approval [F10 · D4 · X25 · T: re-plan]
- irreversible: hold window → compensate or report; ✗ reverse [F11 · X14 · L1 · T: compensate]
- held payment → cancel (outbox item) as a recovery-plan step [F11 · T: cancel (outbox item)]
- over-taint > under-taint, by design [F9 · L2]
- records append-only; nothing erased [F9]
- credit: Taser, Retro, Warp, Aire; OS/web apps, trusted log [#14 · X5]
- carried over → multi-agent shared state + dependants [X5 · F1]

### 2f. Audit (40)

- hash chain + separate witness process, (seq, head, tick) per tick [F12 · D6 · T: witness]
- `verify`: chain · signatures · witness heads · seq gaps · reconciliation [F12 · T: verify]
- scope: tamper-evident up to the last witnessed head [F12 · X15 · T: tamper-evident]
- detect ≠ prevent · ✗ Merkle · ✗ blockchain [X15 X16]
- tamper alert → recovery frozen, nobody suspended [X17 · D7]
- jury break, live: `ks inject`, rogue agent, `state.db` bypass [F13 · D11 · T: inject, rogue agent]
- jury break, live: record edit, full chain rewrite → `verify` [F13 · D11]

## 3. Why it matters (170)

### 3a. Testimony vs evidence (60; D1)

- agent's own record = testimony · gateway record = evidence [P5 · D1]
- audit holds against the audited agent [W2]
- qualifier on every such claim: within the threat model [W2 · L4]
- trust placed only in gateway + witness [§3 "trustless" row]

### 3b. Scored, not self-graded (70; D13)

- recovery scored vs oracle (S\*), not our own taint graph [W1 · T: oracle (S*)]
- oracle = same run, culprit removed [T]
- first use in full: residual damage R, collateral loss C [§1.5 · T §5 note]
- targets: residual damage R 0, collateral loss C 0 → clean recovery [D13 · T: clean recovery]
- targets 0: post-alert tainted, irreversible tainted released, re-emitted effects [§1.5]
- brief's three scores → TTI-detect / TTC / clean recovery [CHARTER · §1.5]
- re-plan and re-run cost → reported openly [W3 · X27]
- alongside containment-style metrics, not instead; no second Airlock name [W1 · D3]
- label "target"; no seconds; future tense [D13 · X21]

### 3c. Path to banking (40)

- "maps to" AI Act Art 12(1) logs, Art 14(4)(e) "safe state" [#15 · W4 · X19]
- optional: high-risk dates 2 Dec 2027 / 2 Aug 2028 [#15]
- NIST AI RMF MANAGE 4.3 → reference only, no number [W4]
- RBI FREE-AI accountability line → only after checking exact words [R]
- enterprise path: OTel export, policy-as-code [W5]
- Dolt, agentgateway = production twins ≠ integrations [W5 · X28]

## 4. Limits + what we will show (85)

### Limits (45; one or two lines)

- must: irreversible effects → hold, compensate, report only [L1]
- must: over-taint by design → collateral holds possible [L2]
- must: deterministic finale agents; LLM → re-plan [L6]
- if words allow: out-of-scope list (host compromise, covert channels, injection) [L4]
- if words allow: collusion → root candidates [L3]
- if words allow: ~10 agents · single host · tick barrier [L7]
- key isolation wording: enforced in production, detected here [L5 · X24]

### What we will show (40; future tense, D13)

- ≥20 seeded runs · median, p95, max · "planned" [§1.5 · T: seeded run]
- baselines: snapshot · revert-culprit-only · no-op [§1.5 · T: snapshot baseline, revert-culprit-only baseline]
- hold window 0 vs >0; escaped payment at 0 → residual damage [D10 · T: hold window]
- threat model published before the jury's break attempts [F13 · D11]
- prototype from 25 Nov → ✗ achieved / showed / measured [GUARDRAILS tense rule]

---

## 5-minute writing plan (Aarav)

1. **Fix first (§2)**: you know the design best; walk the IBAN example through 2b–2f.
2. **Problem (§1)**: open on 1a, then 1b with FACT-CARD open beside you; write the Airlock clause last.
3. **Why it matters (§3), then Limits (§4)**, then pick the title from §0 keywords.
4. **Check**: word count (850–950) → GUARDRAILS §4, all 12 items → Ctrl-F the TERMS banned synonyms. Re-run §4 after any cut.
5. **Send for ABS-07**: own words only, typed in your editor, nothing pasted from this kit or any AI chat. Save as `abstract/DRAFT-R1.md`, one sentence per line (comments cite lines), then `python3 org/issue.py log ABS-07 --who aarav --msg "R1 draft ready: abstract/DRAFT-R1.md"`. Round 1 on 21 Nov AM, round 2 PM, 4 h turnaround each, comments only; you submit 22 Nov.
