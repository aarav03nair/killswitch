# CALL-01 position: zoya (Product & Pitch)

Inputs: CHARTER, SYNTHESIS, RES-11, RES-07, PANEL §5 (framing is §5; §6 is ADR must-fix). Notes only.

## 1. Votes (jury lens)

- **Framing A/B/C: amend.** Keep A frame, B payoff, C why, but the problem is the dependency gap (undo undefined once others read X); provenance is the fix. Juries reward a sharp problem over a mechanism.
- **D1 Headline: amend** as above.
- **D2 Hook: amend.** METR = proof that blunt stop (wipe, revoke) failed at scale; never a B-on-A case, never "we'd have stopped it". PocketOS/Replit = recovery pain. Multi-agent dependency = literature-backed, said so.
- **D3 Name Airlock: agree.** One clause, credited, complementary (forward vs backward). Silence is punished more than credit.
- **D10 Hold window: agree.** Demo toggles 0 vs > 0; abstract: one bullet max.
- **D12 Hero F2+: agree, amend.** Banking-legible. Narrate IBAN + payment + triage conflict; price ×10 stays in data, not in the story.
- **D13 Numbers: agree, amend.** External numbers from fact card only. Ours = definitions + targets (R = 0, C = 0, post-alert tainted effects = 0), labelled targets. No seconds until tara fixes them.

## 2. Abstract spine (~900 words)

**Title + subtitle (~20)**
- problem + fix words; no "first"

**1. Hook (~120)**
- brief's scenario: ten agents, one broke something
- METR: scale, wipe did not end it (facts 1–3, wording rules)
- single-agent pattern: seconds to break, days to repair (facts 9–10, "reportedly")

**2. The real problem (~200)**
- honest agents read the bad write
- today: stop one or all; forward containment exists (Airlock); landed writes left to "orthogonal rollback" (fact 8)
- self-reported logs = testimony
- LLM attribution ~half right at agent level (facts 4–6, with setting)

**3. The fix (~330)**
- one mediated path; adapters record read/write sets; signed identity per hop
- identify = lookup, after invariant detection
- contain = suspend, lineage hold on outbox, others keep running
- recover = revert only provable writes, re-run deterministic, re-plan LLM with approval, irreversible -> hold/compensate/report
- audit = chain + witness + `verify`, outside blast radius

**4. Why it matters (~170)**
- recovery scored vs no-fault oracle (R, C), not self-graded
- audit holds against the audited agent
- "maps to" AI Act Art 12/14, NIST, RBI FREE-AI; OTel/policy-as-code path

**5. Limits + what we will show (~60)**
- no undo of irreversible effects; LLM = re-plan; over-taint by design
- targets, jury-scriptable attacks

## 3. What Aarav needs (Sprint 2 candidates)

1. **Fact card**, 1 page: facts 1–15, wording rule, URL; anaya checks. 20 Nov.
2. **Claim guardrails**: safe claims (RES-11 §5) vs do-not-claim (SYNTHESIS §3) + overclaim words (first, novel, tamper-proof, compliant, guarantees, eliminates). 20 Nov.
3. **How-it-works diagram**, 1 page: gateway -> recorder -> graph -> three queries + witness; vikram reviews. 20 Nov.
4. **Term lock**: one name per concept (envelope, read/write set, lineage hold, taint-scoped revert, oracle). 20 Nov.
5. **Reviewer pass**: comments only, no rewritten text. Facts, claims, spine, word count. Two rounds (21 Nov AM/PM), 4 h turnaround; anaya facts, zoya framing.
6. **Jury Q&A pre-empts**: 5 hostile questions (Airlock? Wang? just logging? LLMs replay? cheat hold?) with evidence pointers only.

## 4. Finale demo: 5 beats / 5 min

1. **Break (0:00–0:45)**: live board, ten agents; crm swaps supplier IBAN; billing/payments/comms consume it; inventory/docs independent.
2. **Identify (0:45–1:45)**: IBAN invariant fires; blame lookup -> crm + first bad action; TTI-detect/attribute shown.
3. **Contain (1:45–2:45)**: crm suspended; lineage hold freezes payment + email; independents keep running; zero culprit writes after quarantine `seq`.
4. **Recover (2:45–4:00)**: dry-run diff; revert crm; triage conflict flagged; re-run billing/reporter; payment cancelled; 0 re-emitted effects; scorecard vs snapshot + revert-culprit-only; hold = 0 toggle shows escaped payment as residual.
5. **Audit (4:00–5:00)**: jury edits a log line / runs `ks inject`; `verify` prints first bad index.
