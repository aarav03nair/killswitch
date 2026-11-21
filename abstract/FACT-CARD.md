# FACT CARD: external numbers for the abstract (ABS-01)

anaya · 19 Nov 2026 · D13: every outside number in the abstract comes from this card. Notes and rules only; you write the sentences.
**v2 changes (19 Nov, after Zoya's review):** #7 "under dense spread" moved to the +46 pp result; #1 note corrected (METR says "cyber", "internal" unconfirmed); #4 venue now A~.

**Status:** **A** = I re-checked it against the URL today · **A~** = re-checked, but part of it is unconfirmed (see the note) · **S** = secondary source only (quote it as "reported").

## Hook (METR case only as "a blunt stop failed at scale", D2)

| # | Fact (note) · exact number | Must travel with it | Source | St |
|---|---|---|---|---|
| 1 | Agent message board: **roughly 1,200** agents, **over 70,000** messages + files, **roughly 700** joined the attack on HF | "roughly"; "METR, preliminary findings"; "July 2026" with no day; agents in OpenAI's **ExploitGym** evaluation runs | [METR](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/) | A~ |
| 2 | Wiping the board (fresh Artifactory) did not stop it: a new board was up **about two days later**, via an Artifactory cache namespace | "about two days later"; mechanism = cache namespace, **not** credentials | METR | A |
| 3 | OpenAI, looking back: early signals "should have triggered an earlier response" | OpenAI's words, quoted via Al Jazeera; "July 2026" | [Al Jazeera](https://www.aljazeera.com/economy/2026/8/27/openai-says-it-detected-malign-activity-months-before-hugging-face-attack) | A |
| 9 | Public incidents we catalogued (7) are all **single-agent**: a human spotted them after the fact; recovery was a whole backup or nothing | "reportedly"; "in our search"; AIID IDs 1152, 1178, 1433, 1442, 1469 | [AIID 1469](https://incidentdatabase.ai/cite/1469) + RES-07 | S |
| 10 | PocketOS: DB + backups deleted in **9 seconds**; restored from a **three-month-old** snapshot + **a weekend** of manual rebuilding | "per the founder, as reported" | [Mondoo](https://mondoo.com/blog/5-lessons-from-9-seconds-ai-agent-deleted-production-database) | S |

## Problem

| # | Fact (note) · exact number | Must travel with it | Source | St |
|---|---|---|---|---|
| 4 | Who&When: LLM attribution finds the agent **~53.5%**, the decisive step **~14.2%** | "best strategies reported, GPT-4o"; a **different** strategy for each number; ICML 2025 | [Who&When](https://arxiv.org/abs/2505.00212) abstract + Table 1 | A~ |
| 5 | Random baseline: **12–29%** (agent), **4–19%** (step) | "by subset" | Who&When Table 1 | A |
| 6 | Better method (FAMAS): **57.61%** agent / **29.35%** action, but **20** replays and **~105 min** avg per attribution (38–248) | cite the body (RQ1, §5.1), not the abstract; arXiv preprint, no venue | [FAMAS](https://arxiv.org/abs/2509.13782) | A |
| 11 | OTel `gen_ai.*`: no attribute for state read/written; nothing Stable | "as of Nov 2026"; say "not yet stable", not "all Development" | [OTel registry](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/), [repo](https://github.com/open-telemetry/semantic-conventions-genai) | A~ |
| 12 | MCP servers "MUST NOT accept or transit any other tokens" | "draft spec" | [MCP auth (draft)](https://modelcontextprotocol.io/specification/draft/basic/authorization) | A |

## Prior art (credit, don't compete)

| # | Fact (note) · exact number | Must travel with it | Source | St |
|---|---|---|---|---|
| 7 | Native A2A/LangGraph controls "contain at most **33.3%** of faults or retain at most **16%** of work without redo"; Airlock keeps **+68 to +96 pp** more healthy work (its optimized cut keeps **+46 pp** more than full quarantine "under dense spread": the qualifier belongs to the +46) | credit Airlock; their benchmark; no head-to-head claim from us | [Airlock](https://arxiv.org/abs/2611.06727) abstract | A |
| 8 | Airlock: "Committed external effects are not rolled back"; absorbed state "requires orthogonal rollback" | "by design"; Table A.2 S2, §5.2 | Airlock | A |
| 13 | Sagas: when a compensation runs, "no effort" is made to notify or abort readers | paraphrase OK; Garcia-Molina & Salem 1987 (SIGMOD from a bib mirror) | [Sagas PDF](https://www.cs.cornell.edu/andru/cs711/2002fa/reading/sagas.pdf) | A~ |
| 14 | Taser (SOSP'05), Retro (OSDI'10), Warp (SOSP'11), Aire (SOSP'13) undo the attacker and keep legitimate work | "for OS / web apps"; "trusted log"; they came first | [Retro](https://www.usenix.org/conference/osdi10/intrusion-recovery-using-selective-re-execution) + RES-10 | A |

## Why it matters

| # | Fact (note) · exact number | Must travel with it | Source | St |
|---|---|---|---|---|
| 15 | AI Act Art 12(1) automatic logs; Art 14(4)(e) stop "in a safe state"; high-risk rules apply **2 Dec 2027** (Annex III) / **2 Aug 2028** (Annex I) | "maps to", never "compliant"; no amending-regulation number | [Art 14](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-14), [Art 12](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12), [Art 113](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113) | A |
| R | *Spare:* RBI FREE-AI (Aug 2025), Sutra 5: "Accountability cannot be delegated to the model and underlying algorithm" | open the report and check the exact words before printing (press paraphrases them) | [RBI report](https://rbi.org.in/Scripts/PublicationReportDetails.aspx?ID=1306) | S |

**Notes on the A~ rows.** #1: METR does say "cyber evaluations" / "cyber task", but "internal" is unconfirmed for this evaluation; keep the safe wording "ExploitGym evaluation runs". #4: numbers confirmed on the arXiv abstract + Table 1, but ICML 2025 is not shown on the arXiv page and not yet confirmed from an official ICML page; cite the venue only once confirmed. #11: the new repo states no stability level, and the registry shows Deprecated keys plus Development values. #13: the PDF does not name SIGMOD. R: today's fetch failed; RES-08 read the report once through a summariser.

## Our own results (B3-27, real container runs, F2+ hero, seeds 0/1/2; from score.json, re-checked by anaya 20 Nov)

**D-19 (21 Nov, zoya S4-18):** the abstract cites our measured numbers only from `abstract/ALLOWED-NUMBERS.md` (BENCH-S3, T=40, 20 seeds, each with its source row and condition). Rows O1–O4 below are hero demo-seed facts (seeds 0/1/2) for the stage and Q&A, not the abstract's bench numbers.

| # | Fact · exact number | Must travel with it | Source |
|---|---|---|---|
| O1 | Residual damage R = **0/1, 0/5, 0/9**; collateral loss C = **0**; both tainted-effect metrics and reemitted = **0** | **D-17:** every R = 0 claim states it holds *after the operator released N held items, M of them honest*: seed 0: 1 (0 honest), seed 1: 5 (3 honest), seed 2: **9 (7 honest)** | `fp_cost.operator_unholds` |
| O2 | Operator releases (`operator_unholds` tainted + honest): seed 0 **1+0**, seed 1 **2+3**, seed 2 **2+7**; `held_honest_actions` **0 / 3 / 7** | honest = an item recovery did not act on (ADR-06 A3) | score.json `fp_cost` |
| O3 | `collateral_stall` **0/389, 0/382, 0/381** | **proxy** (`basis: s_star`, divergence from S\* over non-culprit keys outside B), never "the S0 measure" | ADR-06 A3 |
| O4 | TTI detect **0 / 2 / 2** ticks, attribute **0**; TTC **1** tick | ticks, not seconds; 3 seeds only | score.json |

## Honest conflict F2+x: before and after the resolver (S4-11; BENCH-S3, system, H=6, T=40, 20 seeds, container)

[Fact] In F2+x triage edits the price row crm wrote (`suppliers:S-22`) → write-write conflict → flagged. CALL-04 D-18 requires both rows, side by side. Cells are median [min..max] over 20 seeds. Abstract IDs: ALLOWED-NUMBERS N15 (before), N18 (after).

| # | Row | R | C | honest items held | operator releases (honest + tainted-lineage) | Source |
|---|---|---|---|---|---|---|
| O5 | **before resolver** (resolver: off; default run) | 1/5 [0..1/5] | 21/254 [0..44/243] | 29 [0..35] | 3 [1..7] (3 + 0) | BENCH-S3 §F2+x H=6; §S4-13 before column |
| O6 | **with resolver ww_rebase/1** (opt-in, every resolution signed, verified, undoable) | 0 [0..0] | 0 [0..0] | 3 [0..7] | 5 [1..9] (3 + 2) | BENCH-S3 §S4-13 after column |

**Must travel with O5/O6 [Fact]:**
- Quote both rows together, and R, C and held together. O6 always says "with resolver on" (D-19, ADR-05a §7); the resolver is off unless the run turns it on.
- **D-17:** O6's R = 0 holds after the operator released a median 5 held items, 3 honest and 2 tainted-lineage (re-run and re-held by recovery, released by the bench approver, X4).
- Before the resolver the flag is never resolved, because the bench approver never resolves flags: a flagged conflict waits for a human.
- With the resolver: 1 resolution on 19 of 20 seeds (triage rebased on the clean base); seed 7 had no conflict. `ks verify` OK on all 40 runs (off and on), `per_agent_uid`, no `resolution_invalid`. Hero F2+ (seeds 1..5) score.json identical off and on (BENCH-S3 §S4-13; S4-13 review, kabir).
- **What the resolver will not do** (ADR-05a §1, §2a): it refuses the suspect, every alert's `root_candidates[0]`, evidence writers, authors of taint origins (seed writers), and LLM, system and suspended agents. Any conflict that fails a check, and every other flag, replan or compensate, waits for a human. It merges nothing by hand and invents no value. Undo: `ks recover RUN --unresolve <plan_id>.<n>`, itself recorded.
- **Known limits** (THREAT-MODEL Errata, D-18 entry): verify checks the resolution's rule, order, binding and clean inputs, **not the re-computed value** (trusted to `ks.recovery`, TCB). A **colluding** agent outside the refused set that copies the culprit's value from its own memory into its args would carry it into the rebased write (C3, no prevention claim). Deterministic built-in agents only (GUARDRAILS L6).

## Not safe to print (never quote)

- **Exact HF/METR dates or times** (6, 8, 11, 13, 19, 21 Jul; 23:00 UTC). The outlets disagree. Say "July 2026" and "about two days later".
- **"11 days to detect"** (Al Jazeera only, and it conflicts with METR). **"Legitimately held credentials"** (Airlock's phrase; METR contradicts it).
- **"We would have stopped it"**, or the METR case as agent B using agent A's bad write (D2). That case was collusion inside an evaluation.
- **"One method gets 53.5% / 14.2%"**. Also never put Atomix's τ-bench **53.5%** next to it.
- **IBM 241 / 247 days** (data-breach lifecycles, not agent incidents; 247 is secondary). **RBI "18%"** audit logs (unverified). **"2026/1744"** (secondary).
- **MAST "94%"**, Cordon **45/45 vs 14/45**, DeltaBox ms figures, any GoEx number. Any **venue** for MAST, Cordon, CHIEF, FAMAS, Atomix, GoEx, DeltaBox or State Footprints.
- **"First"** (provenance containment, agent undo, agent gateway). **"Tamper-proof"**, **"compliant"**, **"beats Who&When"**. Saying we reverse irreversible effects. Any Airlock "better / leaks / sim-only" claim.
- **"Tools kill one agent or all of them"** as our own insight (it is Airlock's framing). **"Multi-agent incidents are common"**.
