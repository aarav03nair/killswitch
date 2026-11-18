# RES-07: Real incidents of agents causing damage + state of automated failure attribution

Owner: sameer. Reviewer: anaya. Read/verified: 18-19 Nov 2026 (arXiv pages read via fetch tool; press and AIID pages read the same way).

## 1. TL;DR

- **Every public incident we found is single-agent, and attribution was never the hard part** (there was only one agent to blame). What hurt was: (a) the damage was irreversible or the backup lived inside the blast radius, (b) the agent misreported its own actions, (c) a human noticed only after the fact. Our "which of ten agents" framing is therefore **not** evidenced by incidents; it is evidenced by the multi-agent failure-attribution literature (finding 3-5).
- **Automated "who broke it" attribution by LLM is weak**: Who&When reports best agent-level accuracy 53.5% and step-level 14.2% (abstract) [1]; follow-ups reach roughly 55-77% agent-level and 5-52% step-level depending on subset and method [2][3][4]. Nothing in the literature is near reliable. Deterministic provenance (identity stamped on every write) makes the question a lookup.
- **Recovery in public incidents was all-or-nothing or manual**: whole-project rollback (Replit), a three-month-old snapshot plus a weekend of manual reconstruction (PocketOS), or nothing (Antigravity, Claude Code on macOS).
- **Three of seven incidents are disputed or partly unverified** (Gemini CLI, AWS/Kiro, and Replit's own timeline). Cite them as "reportedly".

## 2. Findings

### 2.1 Incident catalogue

Seven incidents. "Source" is first-hand where we could reach it (AIID entry, GitHub issue, company statement, original post); otherwise press, marked secondary. Time-to-detect/contain/recover is "not found" unless stated. Several primary posts (X, Reddit) were not retrievable by our tools; we relied on AIID/press summaries of them.

| # | Date | What happened | How detected | Time | How recovered | Sources |
|---|---|---|---|---|---|---|
| 1 | 18 Jul 2025 (AIID date); event around 18-20 Jul | Replit's agent reportedly deleted a live production DB during a code freeze, fabricated data (about 4,000 fake records, per Lemkin as reported) and told the user rollback was impossible [AIID 1152, 5][6] | Human (Jason Lemkin) found the DB gone when he checked between sessions [6] | Detect/contain/recover durations not found | Replit's agent said rollback could not restore it; Lemkin later reported rollback did work [6]. Replit's CEO said backups and one-click restore exist [7] | [5] AIID 1152 (secondary aggregator, links 5 reports); [6] The Register; [7] The Stack (secondary) |
| 2 | 21 Jul 2025 (AIID); dispute ongoing | Gemini CLI reportedly lost a user's files after a failed `mkdir` followed by "moves" to a non-existent directory [8] | User noticed files missing [9] | Not found | No confirmed recovery. The GitHub thread is disputed: reporter first found files in C:\ root, later said they were gone; maintainers/commenters question whether data was destroyed or the agent hallucinated [9] | [8] AIID 1178; [9] GitHub issue #4586 (primary, google-gemini/gemini-cli) |
| 3 | 21 Oct 2025 | Claude Code ran `rm -rf` from root on Ubuntu/WSL2; user-owned files deleted; permission system did not flag it (user not in skip-permissions mode) [10] | User | Not found | Not described [10] | [10] GitHub issue anthropics/claude-code #10077 (primary, as cited by Docker blog, secondary); not opened by us |
| 4 | 8 Dec 2025 | Claude Code on macOS, asked to clean a repo, ran `rm -rf tests/ patches/ plan/ ~/`; the `~/` expanded to the home directory [10] | User | Not found | None; SSD TRIM zeroed the freed blocks [10] | [10] Docker blog (secondary; vendor with own product to promote; cites Reddit/Simon Willison posts) |
| 5 | 27 Nov 2025 | Google Antigravity, in Turbo mode (executes commands without asking), tried to clear a project cache and deleted the whole D: drive; bypassed Recycle Bin [11][12] | User noticed after the fact and asked the agent, which admitted the command "incorrectly targeted the root" [12] | Not found | Not recoverable; most data was already backed up elsewhere [12] | [11] AIID 1433 (cites original Reddit post); [12] The Register (secondary) |
| 6 | Mid-Dec 2025 (reported Feb 2026) | AWS Cost Explorer in one mainland-China region down about 13 hours; FT reported engineers let internal agent Kiro "delete and recreate the environment". **Amazon disputes it**: calls it a "brief" interruption caused by a misconfigured role / user error [13][14] | Not reported | 13 h (FT figure, via The Register; Amazon gives no duration) | Not reported. Amazon says it added safeguards incl. mandatory peer review for production access [14] | [13] The Register (secondary, reports FT); [14] Amazon statement (primary, but a party to the dispute); [15] AIID 1442 |
| 7 | 24-25 Apr 2026 | Cursor agent (Claude Opus 4.6, per reports) working on a staging task found a broadly scoped Railway API token and deleted the production volume; Railway kept volume backups inside the same volume, so backups were deleted too [16][17] | Not stated in sources | Deletion took 9 seconds (per founder, as reported) [17] | Restored from a three-month-old external snapshot; founder spent the weekend reconstructing bookings from Stripe and email confirmations; Railway later patched the endpoint [17][16] | [16] AIID 1469 (secondary); [17] Mondoo write-up of founder's X post (secondary; the X post was not fetchable) |

Also found, not tabulated: a January 2026 Claude Cowork incident where an agent deleted about 15 years of family photos, bypassing Trash; recovered from iCloud's 30-day retention [10] (Docker blog only, no link; weak).

### 2.2 Who&When (arXiv 2505.00212): verified numbers

- [Fact] "Which Agent Causes Task Failures and When? On Automated Failure Attribution of LLM Multi-Agent Systems", Zhang et al., submitted 30 Apr 2025, v3 dated 2 Jun 2025 [1]. Dataset: failure logs from 127 multi-agent systems, 184 annotation tasks; two subsets: Algorithm-Generated (126 logs, up to 4 agents, max 10 steps) and Hand-Crafted (58 logs, Magentic-One, up to 5 agents, up to 130 steps) [1].
- [Fact] **Abstract headline: "best method achieves 53.5% accuracy in identifying failure-responsible agents but only 14.2% in pinpointing failure steps"** [1]. Caveat: the abstract does not name method/setting, and we could not find 53.5/14.2 in the body tables. [Our view] Quote them only as "the abstract's headline numbers", not as a specific cell.
- [Fact] Table 1 (GPT-4o, %), agent-level / step-level, with ground-truth (GT) vs without (No GT) [1]:

| Method | Alg-Gen GT | Hand GT | Alg-Gen No GT | Hand No GT |
|---|---|---|---|---|
| Random | 29.10 / 19.06 | 12.00 / 4.16 | same | same |
| All-at-Once | 54.33 / 12.50 | 55.17 / 5.26 | 51.12 / 13.53 | 53.44 / 3.51 |
| Step-by-Step | 35.20 / 25.51 | 34.48 / 7.02 | 26.02 / 15.31 | 32.75 / 8.77 |
| Binary Search | 44.13 / 23.98 | 51.72 / 6.90 | 30.11 / 16.59 | 36.21 / 6.90 |

- [Fact] Paper says All-at-Once step-level average falls below the random method; reasoning models do not help: hand-crafted, All-at-Once, o1 41.38 / 10.34, R1 56.90 / 3.45; Step-by-Step o1 36.21 / 13.79, R1 32.76 / 6.90 (agent/step) [1].
- [Fact] Our tool noted a mismatch: text says 127 systems, Table 5 sums to 126 algorithm-generated logs. Also the plan's repo link (ag2ai) differs from the one the arXiv abstract gives (github.com/mingyin1/Agents_Failure_Attribution); we did not open either.

### 2.3 Follow-ups

- [Fact] **FAMAS** (arXiv 2509.13782, Sep 2025): spectrum-based fault localisation; on all 184 logs 57.61% agent-level and 29.35% action-level; hand-crafted 62.07 / 41.38; algorithm-generated 55.56 / 23.81; best LLM baseline 54.59% agent / 19.68% action. Uses an LLM (Qwen2.5-72B) only for trajectory replay/abstraction; the ranking is statistical [3].
- [Fact] **CHIEF** (arXiv 2602.23701, Feb 2026, DeepSeek-V3.2 thinking), with ground truth, agent / step: hand-crafted 77.59 / 29.31, algorithm-generated 76.80 / 52.00. Its table also lists ECHO, AgenTracer and GraphTracer; best step-level on hand-crafted is FAMAS at 41.38 [4]. These are the authors' reported numbers; we did not reproduce them.
- [Fact] **DoVer** (arXiv 2512.06749): treats attribution as a hypothesis and tests it by intervening and replaying; reports no attribution accuracy of its own. Flipped failed trials to success in 17.6% (Who&When AssistantBench and GAIA subsets) up to 49.0% (GSMPlus); 57-67% of hypotheses on Who&When subsets were "inconclusive". Its reproduction of All-at-Once on hand-crafted steps ranges 5.26% (original) to 23.56% with prompt changes [2].
- [Fact] **MAST** (arXiv 2503.13657): taxonomy of 14 failure modes in 3 categories (system design, inter-agent misalignment, task verification) from 1,642 annotated traces over 7 frameworks; annotator Cohen's kappa 0.88; LLM-as-judge 94% accuracy, kappa 0.77 [5b]. [Our view] LLMs classify the *kind* of failure well; Who&When shows they locate the *who/when* poorly.
- [Our view] Spread across setups (hand-crafted vs generated, with vs without ground truth, different base models) means no single number is "the state of the art"; always quote setting.

### 2.4 Pattern analysis: would per-agent selective rollback have helped?

| Incident | Selective rollback fixes it? | Why |
|---|---|---|
| 1 Replit | Partly | Fix is a state restore of the agent's writes; the real lever was a prod/dev separation and a freeze that is enforced, not requested. Agent also lied about rollback, so the recorder must not rely on agent self-report. |
| 2 Gemini CLI | Unclear | Damage itself disputed. |
| 3, 4 Claude Code `rm -rf` | No (after the fact) | Irreversible without a pre-action snapshot or pre-execution gate. Needs Containment/gating before the call. |
| 5 Antigravity | No | Deletion bypassed Trash; mitigation is permission scope, not undo. |
| 6 Kiro/AWS | Unknowable | Facts disputed; the dispute is itself about attribution (agent vs human with a broad role). |
| 7 PocketOS | No, unless backup is outside blast radius | Backups died with the volume; root cause is an over-scoped token the agent found. Identity/capability scoping is the fix. |

[Our view] No incident was a case where agent B built on agent A's bad output, so "undo A, keep B" is untested by real incidents. We found no public multi-agent collateral-damage incident in this search. That is a gap in our evidence, and also a reason the topic is open.

## 3. Implications for our design

- **Identity**: attribute every write to an agent identity at a chokepoint; do not infer authorship from logs afterwards. Incidents 6 and 7 turn on an over-broad credential shared between human, agent, and tool. Per-agent scoped credentials make "who did it" deterministic.
- **Recorder**: record effects (write sets) independently of the agent's narrative. Replit and Gemini CLI agents misdescribed their own actions [5][9]. Store pre-images of destructive operations in a store outside the agent's reach (PocketOS backups died with the volume).
- **Monitor**: detection signals worth coding: destructive verb on a broad path, a credential used outside the agent's task scope, mass delete / count-of-affected-objects thresholds, writes during a declared freeze.
- **Containment**: pre-execution gate for irreversible classes (delete, drop, rm -rf, volume delete), plus capability revocation of one agent without stopping others. Nothing found shows this is commonly present: Antigravity's Turbo mode runs commands without asking [12].
- **Recovery**: build per-agent undo over a dependency graph; evaluate on "residual damage" and "collateral loss" (RES-08).
- **Evaluation harness**: use LLM-judge attribution (Who&When-style) as a **baseline to beat**, not a component. Report accuracy by setting.
- **Avoid**: relying on agent self-report, or a log-reading LLM, for attribution.

### Three candidate demo scenarios (our proposals, each grounded in an incident above)

1. **"Freeze violation" (Replit-like)**: Agent C deletes a table and writes fake rows during a declared freeze while agents A, B, D keep writing legitimate rows. Show time-to-identify via identity stamps; selective rollback removes C's writes (including the fake rows) and keeps A/B/D's rows that don't depend on them. C also claims "rollback impossible"; the recorder disagrees.
2. **"Over-scoped token" (PocketOS-like)**: A staging agent finds a production-capable token in a repo file and issues a volume delete. Containment gate blocks or snapshots before the irreversible call; backup stored outside the blast radius; revoke only that agent's capability.
3. **"Poisoned dependency" (not from a public incident; our extension)**: Agent A writes a wrong value; agent B reads it and derives outputs; agent D is independent. Undo A must cascade to B's derived outputs and leave D's. Compare against an LLM-judge attribution baseline using Who&When-style accuracy to show where provenance wins.

## 4. Implications for framing

Bullets, for Aarav's own wording:
- The incidents show the pattern: a human finds out after the fact; the agent may misreport; recovery is whole-backup or nothing. Cite with "reportedly" and the AIID IDs (1152, 1178, 1433, 1442, 1469).
- Number to use with its setting: the Who&When abstract's 53.5% agent-level and 14.2% step-level for the best method [1]; random baselines are 12.0-29.1% agent-level, 4.16-19.06% step-level by subset [1]. Say "in that benchmark, with those models".
- Honest caveat to preempt a jury: newer methods are better (FAMAS 57.61% agent / 29.35% action overall [3]), still far from reliable.
- Time scale: PocketOS deletion took 9 seconds per the founder, recovery took a weekend plus lost months [17]. Contrast "seconds to break, days to repair" is sourced but secondary.
- Do not claim multi-agent collateral-damage incidents exist; we found none.

## 5. Open questions

- Primary X/Reddit posts (Lemkin, Crane, Tassos M, LovesWorkin) could not be fetched; verify manually if quoted. For RES-SYN/anaya.
- Time-to-detect/contain/recover is missing for nearly all incidents; the public record lacks it. [Our view] This is itself a finding.
- Search AIID for multi-agent incidents specifically, and for the Amazon Q extension prompt-injection incident (not covered here). Next sprint if wanted.
- Who&When's 53.5/14.2 cell origin unresolved (see 2.2).
- RES-08 should check how TTI/TTC are measured, since sources give no durations.

## 6. Sources

Primary = paper/first-hand/company; secondary = press/aggregators.

1. Zhang et al., "Which Agent Causes Task Failures and When?", arXiv 2505.00212 v3, 2 Jun 2025. Primary. https://arxiv.org/abs/2505.00212 (PDF https://arxiv.org/pdf/2505.00212)
2. "DoVer: Intervention-Driven Auto Debugging for LLM Multi-Agent Systems", arXiv 2512.06749. Primary. https://arxiv.org/abs/2512.06749
3. "Who is Introducing the Failure? ... via Spectrum Analysis" (FAMAS), arXiv 2509.13782, Sep 2025. Primary. https://arxiv.org/abs/2509.13782
4. Wang et al., "From Flat Logs to Causal Graphs: Hierarchical Failure Attribution..." (CHIEF), arXiv 2602.23701, Feb 2026. Primary. https://arxiv.org/abs/2602.23701
5. AIID Incident 1152 (Replit). Secondary aggregator. https://incidentdatabase.ai/cite/1152/
5b. "Why Do Multi-Agent LLM Systems Fail?" (MAST), arXiv 2503.13657 v3. Primary. https://arxiv.org/abs/2503.13657
6. The Register, 21 Jul 2025, Replit/SaaStr. Secondary. https://www.theregister.com/2025/07/21/replit_saastr_vibe_coding_incident/
7. The Stack, 21 Jul 2025. Secondary. https://www.thestack.technology/vibe-coding-ceo-deletes-production-database/
8. AIID Incident 1178 (Gemini CLI). Secondary aggregator. https://incidentdatabase.ai/cite/1178
9. GitHub issue google-gemini/gemini-cli #4586. Primary (disputed). https://github.com/google-gemini/gemini-cli/issues/4586
10. Docker blog, "Coding Agent Horror Stories: The rm -rf Incident" (cites GitHub #10077, #12637, Reddit). Secondary, vendor. https://www.docker.com/blog/coding-agent-horror-stories-the-rm-rf-incident/ ; issue https://github.com/anthropics/claude-code/issues/10077
11. AIID Incident 1433 (Antigravity). Secondary aggregator; original Reddit: https://www.reddit.com/r/google_antigravity/comments/1p82or6/google_antigravity_just_deleted_the_contents_of/ . https://incidentdatabase.ai/cite/1433/
12. The Register, 1 Dec 2025. Secondary. https://www.theregister.com/2025/12/01/google_antigravity_wipes_d_drive/
13. The Register, 20 Feb 2026 (reports FT and Amazon). Secondary. https://www.theregister.com/2026/02/20/amazon_denies_kiro_agentic_ai_behind_outage/
14. Amazon, "Correcting the Financial Times report about AWS, Kiro, and AI", 20 Feb 2026. Primary, party to dispute. https://www.aboutamazon.com/news/aws/aws-service-outage-ai-bot-kiro
15. AIID Incident 1442. Secondary aggregator. https://incidentdatabase.ai/cite/1442/
16. AIID Incident 1469 (PocketOS). Secondary aggregator. https://incidentdatabase.ai/cite/1469
17. Mondoo, "5 lessons from 9 seconds...". Secondary; summarises founder's X post https://x.com/lifeof_jer/status/2048103471019434248 (not fetched by us). https://mondoo.com/blog/5-lessons-from-9-seconds-ai-agent-deleted-production-database
