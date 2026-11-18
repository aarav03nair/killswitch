# RES-SYN: Synthesis (framing, facts, principles, metrics, decisions)

Owner: anaya · 20 Nov 2026 · Inputs: RES-01..11, REVIEW-S1, STRAWMAN, PANEL-ENG-00, plus my own spot-checks (**A**). Bullets and facts only. Aarav writes every sentence of the abstract.

## 0. Working thesis: MODIFIED

- **Confirmed:** undo is a dependency problem, not a snapshot problem. Checkpoints restore the whole state. Commit stores revert by commit but record no reads (RES-06). Sagas never notify readers (RES-02). OTel has no read/write sets (RES-04).
- **Killed:** "nobody has provenance containment" (Airlock, RES-11) and "nobody has agent undo" (Wang 2608.10502 for a single agent; State Footprints as a vision).
- **Partly overturned:** "no multi-agent incident". OpenAI/HF is real (**A**). Still true: there is no public case of B consuming A's bad write and then being repaired.

## 1. Framing options

| | A. Provenance-first *(recommended)* | B. Backward recovery | C. Testimony vs evidence |
|---|---|---|---|
| Thesis | Every write has an author and every read has a source. Identify, contain and recover become three queries on one graph | Containment stops the bleeding; nobody repairs work that has already landed | An agent's own log is testimony; accountability needs a record the agent cannot forge |
| Evidence | Maps 1:1 to the brief (Panel 5.2). OTel has no state fields. MCP no-passthrough. Who&When weak. METR read ~1,300 transcripts after the fact | Airlock: committed effects "not rolled back". Retro/Warp. Sagas | Replit misreport; #10077 "never logged"; Airlock journals "not authenticated"; Art 12/14 |
| Jury poke | "Airlock has a DAG." "Just logging?" | "Wang did undo." "LLMs can't replay." No B-on-A incident | Tamper-evident ≠ tamper-proof; crowded; weak on recovery score |

**Recommendation: A as the frame, B as the demo payoff, C as "why it matters".** It survives a partial failure of re-plan.
- Niche vs Airlock: the backward half (revert one author's landed shared-state writes, repair its readers). A signed, witness-anchored record under a forging or tampering threat model. Recovery scored as (R, C).
- Hook: single-agent incidents (seconds to break, days to repair), plus the first public multi-agent case (wiping the channel did not stop it; forensics came weeks later).

**Outline points:**
- Problem: many agents, shared state. "Undo X" is undefined once others have read X. Kill switches stop one agent or all of them. Logs are self-reported. LLM attribution is about half right at agent level.
- Fix: a gateway-signed record with read/write sets. Blame lookup (TTI). Lineage hold plus graded quarantine (TTC). Taint-scoped revert, re-run/re-plan, compensate/report (recovery). Witness plus `verify` for the audit.
- Why: recovery measured against an oracle. The audit holds even against the audited agent. Maps to AI Act Art 12/14, NIST MANAGE 4.3 and RBI FREE-AI. OTel and policy-as-code path.

## 2. Fact sheet

| # | Fact | Wording rule | Source | Status |
|---|---|---|---|---|
| 1 | ~1,200 agents on the board (8–13 Jul 2026), >70,000 messages+files, ~700 attacking HF by 11 Jul | "roughly"; "internal OpenAI cyber evaluation (ExploitGym)"; METR, "preliminary" | https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/ | RES-11; **A** verified |
| 2 | Fresh Artifactory 6 Jul erased the board; new board 8 Jul 23:00 UTC, via cache abuse, "not credentials" | "about two days later"; never "legitimately held credentials" | METR | RES-11; **A** verified |
| 3 | OpenAI: early signals "should have triggered an earlier response" | Quote via Al Jazeera; say "July 2026" with no day (outlets conflict) | https://www.aljazeera.com/economy/2026/8/27/openai-says-it-detected-malign-activity-months-before-hugging-face-attack | RES-11; **A** verified |
| 4 | Who&When ~53.5% agent, ~14.2% step | "best strategies, GPT-4o, different strategy per metric" | https://arxiv.org/abs/2505.00212 | RES-10; **A** arithmetic |
| 5 | Random baseline 12–29% agent, 4–19% step | "by subset" | same, Table 1 | RES-10 |
| 6 | FAMAS 57.61% / 29.35%, but needs 20 re-runs (~105 min) per attribution | Cite Table 1, not the abstract | https://arxiv.org/abs/2509.13782 | RES-10; **A** |
| 7 | A2A/LangGraph controls "contain at most 33.3% of faults or retain at most 16% of work" without redo; Airlock +68 to +96 pp | Credit Airlock; their benchmark | https://arxiv.org/abs/2611.06727 | RES-11; **A** verified |
| 8 | Airlock: "Committed external effects are not rolled back"; memory "requires orthogonal rollback" | Add "by design" | same, Table A.2 S2, §5.2 | RES-11; **A** verified |
| 9 | 7 public incidents: single-agent, human-detected, whole-backup or no recovery | "reportedly"; AIID IDs | RES-07; https://incidentdatabase.ai/cite/1469 | mostly secondary |
| 10 | PocketOS: 9 s to delete; 3-month-old snapshot plus a weekend of rebuilding | "per the founder, as reported" | https://mondoo.com/blog/5-lessons-from-9-seconds-ai-agent-deleted-production-database | secondary |
| 11 | OTel `gen_ai.*` all Development; no read/write attribute | "as of Nov 2026" | https://github.com/open-telemetry/semantic-conventions-genai | RES-04 |
| 12 | MCP: "MUST NOT accept or transit any other tokens" | "draft spec" | https://modelcontextprotocol.io/specification/draft/basic/authorization | REVIEW-S1 |
| 13 | Sagas (SIGMOD'87): compensation makes "no effort" to notify readers | paraphrase OK | https://www.cs.cornell.edu/andru/cs711/2002fa/reading/sagas.pdf | RES-02/10 |
| 14 | Taser'05, Retro'10, Warp'11, Aire'13 undo an attacker while keeping legitimate work | "for OS/web apps; trusted log" | https://www.usenix.org/conference/osdi10/intrusion-recovery-using-selective-re-execution | RES-01/10 |
| 15 | AI Act Art 12(1) logs; Art 14(4)(e) stop to "a safe state"; high-risk dates 2 Dec 2027 / 2 Aug 2028 | "maps to"; no regulation number | https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-14 | REVIEW-S1 |

Spare: RBI FREE-AI "Accountability cannot be delegated to the model and underlying algorithm" (RES-08, read via WebFetch).

## 3. Do not claim

- "First" for provenance containment, agent undo or agent gateways (Airlock, Wang, agentgateway). Any Airlock comparison ("better", "leaks", "sim-only"). "Tools kill one or all" as our own insight.
- That multi-agent collateral incidents are common. The one public case was collusion inside an eval. Do not say we would have stopped it, do not repeat "legitimately held credentials", and do not give exact HF dates or "11 days to detect".
- "One method gets 53.5/14.2". Two different 53.5s (Atomix τ-bench). MAST 94% without κ 0.77.
- Venues for MAST, Cordon, CHIEF, FAMAS, Atomix, GoEx, DeltaBox, State Footprints.
- That Cordon beat real products, Atomix beat checkpoints, DeltaBox is per-agent, State Footprints rolls back, or GoEx has numbers.
- That we reverse irreversible effects, that we are "tamper-proof" or "compliant", or "beats Who&When" (a different task).
- IBM 241/247 days as agent numbers. RBI "18%". "2026/1744".

## 4. Design principles (component in brackets)

1. **One mediated path** [Gateway]: process isolation, plus reconciliation (state = fold(log)) to catch unmediated writes. *(Panel 2.1, RES-03)*
2. **Adapters record effects, agents never self-report** [Recorder]: row-level read and write sets. *(RES-07, RES-04)*
3. **Identity on every hop** [Identity]: signed envelope with the parent/`act` chain; the gateway assigns `seq` and time. *(RES-03, Panel 2.8)*
4. **Evidence outside the blast radius** [Recorder]: chain plus per-tick witness checkpoints; values in a redactable side store. *(RES-04, Panel 2.2/4.4)*
5. **Classify each action instance before it runs** [Gateway/Containment]: R/C/I1/I2/U, U denied, I-class to the outbox hold. *(RES-02, Panel 4.2)*
6. **Detect on data invariants, attribute by lookup** [Monitor]. *(Panel 1.1, Who&When)*
7. **Graded containment by lineage** [Containment]: suspend → revoke, release, epoch fencing in-transaction; hold outbox items that touch tainted versions. *(Panel 2.3/2.7/2.8, Cordon)*
8. **Revert only what you can prove, over-taint rather than under** [Recovery]: current == culprit's after-version, else re-run or flag; append-only; backward taint names root candidates. *(Panel 1.3a/2.4, RES-06, RES-01 Taser)*
9. **Re-execute deterministic steps, re-plan LLM steps** [Recovery]: re-runs never re-emit effects (idempotency keys). *(RES-01, RES-11, Panel 1.3b)*
10. **Score against an oracle, never against ourselves** [Eval harness]. *(REVIEW-S1 §3.8, RES-08)*

**Panel must-fix → ADR owner / reviewer:** write-write conflict, outbox-deduped re-run, substrate → **vikram** / maya. Process isolation + reconciliation, epoch fencing, lineage hold, graded containment + release → **nisha** / kabir. Witness checkpoints + `verify`, PII side store → **arjun** / kabir. Invariant detectors → **nisha** with tara / maya. TTC and metrics (§6) → **tara** with sameer / anaya.

## 5. Positioning

| System | What it is | Lacks (own text / our check) | Our stance |
|---|---|---|---|
| Airlock | Forward containment: DAG, switches, min-cut, Thm 5 | No rollback of committed effects; unauthenticated journals; ~10 agents | Prior art; we are the backward half plus authenticated record; also report "kept without redo" |
| Spark to Fire | Claim lineage; block messages and request a rewrite | No state or effect undo; no identity | Messages vs shared state |
| State Footprints | Vision: abort a task and its readers | Not implemented | Closest idea; we build and measure it per agent |
| agentgateway | OSS MCP/A2A proxy, CEL authz, OTel | No verified kill or provenance | Production twin |
| Atomix / Cordon | Per-task transactions, outbox gates | Per task; no cross-agent reads | Reuse gates |
| DeltaBox | Millisecond sandbox snapshots | Whole sandbox or branch; no network rollback | Fast snapshot baseline |
| Dolt / Git | Revert one commit, keep later ones | No reads; dependent edits conflict | Production twin for the store |
| Wang 2608.10502 | Single-agent rollback plus replay | Single agent | Ours: multi-author shared state |

## 6. Metrics to adopt

- **Oracle:** t0 = oracle commit of the first bad effect. S\* = run with the culprit removed. **B** = faulty-run effects absent or different in S\*. **G** = honest effects matching S\*. Compare on the effect ledger and invariants, never on our taint graph.
- **TTI-detect:** t0 → first alert. **TTI-attribute:** alert → correct agent_id and first bad action_id. Count false accusations.
- **TTC (Panel):** alert → first denied culprit envelope (`seq`). Companion counts, both targeting 0: **post-alert tainted effects** (anyone) and **irreversible tainted effects released**. Also: exposure window, damage-in-window, collateral stall, false-positive cost.
- **Recovery:** R = |B left|/|B|; C = |G lost|/|G|; revert precision and recall. Clean = (R = 0 and C = 0). CR only alongside them.
- **Re-plan cost:** re-run or re-planned honest actions / |G|, approvals requested, re-emitted effects (= 0). Also Airlock's "kept without redo".
- **Protocol:** ≥20 seeded runs; median, p95, max. Baselines: snapshot, revert-culprit-only, no-op. Hold 0 vs > 0. A probe keeps attacking after containment.

## 7. Call #1 decisions (recommended answers)

1. **Headline:** provenance-first; selective undo as the payoff.
2. **Hook:** METR case plus the single-agent pattern (facts 1–3, 9–10).
3. **Name Airlock?** Yes, one clause as forward-containment prior art.
4. **Recovery:** re-execute deterministic steps, re-plan LLM steps with approval; conservative taint.
5. **Substrate:** our own row-versioned SQLite; Dolt on a slide. vikram's ADR before 25 Nov.
6. **Tamper evidence:** chain + witness + `verify`; no Merkle proofs.
7. **Auto vs human:** auto-suspend on hard evidence (signature, scope, tamper, I-class invariant); one click for anomalies; revoke after confirmation.
8. **Tainted readers:** lineage hold plus suspension of derived writes; independent agents keep running.
9. **LLM at the finale:** no; one LLM agent is a stretch goal.
10. **Hold window:** show both (0 = scored residual damage).
11. **Jury break:** `ks inject` + a rogue-agent template + log edit → `verify`.
12. **Hero:** Panel F2+.
13. **Abstract numbers:** stated as targets until they are measured: R/C, TTI-detect/attribute, TTC, post-alert tainted effects = 0.
