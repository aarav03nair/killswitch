# RES-08: Metrics for TTI / TTC / clean recovery, and regulatory and bank-audit hooks

Owner: sameer. Reviewer: anaya. Read date: 19 Nov 2026. Tags: **[Fact]** = stated in a cited source; **[Our view]** = our inference.

## 1. TL;DR

- **No standard defines "clean recovery", and the standards we checked do not define TTI/TTC either.** NIST SP 800-61r3 contains no "mean time to" metrics and names "performance measures" without defining any [2]. Google SRE says mean-time statistics are "poorly suited for decision making or trend analysis" [3]. So we define the three metrics ourselves, with exact start/stop events, and report distributions rather than means. **[Our view]** This is a framing opportunity: the jury's three scoring terms have no agreed measurement, and we offer one that is checkable.
- **The EU AI Act high-risk delay is real, and it is in the law text, not only in press reports.** The EC AI Act Service Desk's consolidated Article 113 now applies Chapter III Sections 1-3 (which include Arts 12, 14, 19, 26) from **2 December 2027** for Annex III systems and **2 August 2028** for Annex I systems [14]. The general application date stays 2 August 2026 [14]. Caveat on sourcing in section 6.
- **Proposed clean recovery formula:** report the pair (residual damage R, collateral loss C), with R = bad effects still present and C = good effects lost, both computed against a counterfactual "culprit never acted" run. Section 3.
- Every regulator we checked wants the same four things our architecture already has: logs retained over time (Recorder), anomaly monitoring (Monitor), a stop/deactivate path (Containment), and documented incident handling (Recovery plus after-action report).
- Bank-relevant hooks: EU DORA (applies from 17 Jan 2025) [23], PRA SS1/23 [21][22], RBI FREE-AI (13 Aug 2025) [24] and CERT-In's 6-hour reporting and 180-day log rule [25].

## 2. Findings: how incident metrics are defined today

1. **[Fact]** NIST SP 800-61r3 (final, April 2025) frames response around CSF 2.0 functions: Detect "Possible cybersecurity attacks and compromises are found and analyzed"; Respond "Actions regarding a detected cybersecurity incident are taken"; Recover "Assets and operations affected by a cybersecurity incident are restored" [1][2]. It uses no "mean time" or "time to" metrics, and lists "Performance measures" among policy elements without defining them (section 2.3) [2]. Recovery text relevant to us: "Check restored assets for indicators of compromise, and remediate the root causes of the incident before production use" (RC.RP-05 R1), and "Recovery actions should take timeliness, precision, and reliability" (RC.RP-02 R1) [2]. **[Our view]** "Precision" in recovery is the hook for our revert precision/recall.
2. **[Fact]** Google SRE, "Incident Metrics in SRE" (Davidovič): MTTR and MTTM "are often measured" but are "poorly suited for decision making or trend analysis in the context of production incidents", based on Monte Carlo simulation [3]. The page excerpt we read did not give the reasons or a date; read the linked full paper before quoting reasons. **[Our view]** Report median, p95 and max over many seeded runs, not a mean.
3. **[Fact]** DORA (DevOps research): the original metric "mean time to recover" (2014) was renamed in 2023 to failed deployment recovery time, because "previous definitions did not distinguish between a failure initiated by a software change and a failure caused by external factors" [5]. The 2024 definition is "Time to recover from a failed deployment" [5]; the current guide says "The time it takes to recover from a deployment that fails and requires immediate intervention" and does not state start/stop events [4]. **[Our view]** The same distinction matters to us: our recovery clock should cover failures caused by one agent's change, not generic outages.
4. **[Fact]** IBM Cost of a Data Breach: 2025 edition, "Global average breach lifecycle: 241 days", "dropped to 241 days", a 17-day reduction; global average cost $4.44 million [6]. Organizations using AI and automation extensively "reduced the breach lifecycle by an average of 80 days" and saved $1.9 million [6]. 2026 edition (published 30 Jul 2026, 602 breaches, 17 industries per [9]): "Mean time to identify and contain a breach rose to 247 days, reversing five straight years of decline" [8], average cost $4.99 million [7][8]. IBM's own page states $4.99M [7]; the 247-day figure comes from secondary coverage [8][9] and we did not find it on IBM's primary page. IBM's headline figure combines identify and contain; the sources we read give no separate identify and contain numbers [9]. **[Our view]** Cite 247 days only as "reported by Help Net Security / Baker Donelson from IBM's 2026 report" until checked against IBM's PDF.
5. **[Fact]** NIST AI 600-1 (GenAI profile, 26 Jul 2024) measures incidents as "(e.g., incidents detected and response times)" (GV-6.1-003) and asks that "Protocols are put in place to ensure GAI systems are able to be deactivated when necessary" (GV-1.7-001) [20]. Our read of the first 100,000 characters only; MANAGE actions were beyond the truncation.

## 3. Proposed benchmark definitions (our design, not from a source)

Setup: each scenario has a ground-truth label file. Let **t0** = commit time of the first bad effect (the fault injector writes this). **B** = set of bad effects, including effects transitively derived from the culprit's outputs (taint). **G** = set of good effects by other agents not in B. Oracle state **S\*** = final state of a replay of the same scenario with the culprit agent's actions removed (compare on declared invariants and a ledger of effects, not on bytes, because LLM agents are non-deterministic).

| Metric | Start event | Stop event | Notes |
|---|---|---|---|
| **TTI** time-to-identify | t0 | First system output naming culprit agent_id and the first bad action_id, later scored correct against ground truth | Report two stages: t0 to first alert (cf. MTTD) and alert to correct attribution. Wrong agent = not identified; count false accusations. Also TTI-scope: time until the claimed blast radius reaches recall >= 0.9 of B. |
| **TTC** time-to-contain | t0 | Culprit's capability revoked at the chokepoint AND no new bad effect from it is committed afterwards, verified by a red-team probe that keeps trying | Also report **damage-in-window** = |B committed between t0 and containment|, and **collateral stall** = good-agent actions blocked during containment. Time alone rewards killing everything. |
| **Clean recovery** | Containment time | State reaches S\* on invariants (time-to-clean), or end of run | See formula below. |

**Clean recovery formula.** Let X = set of effects the system reverted or compensated, and S the final state.
- Residual damage **R = |B still present in S| / |B|** (equals 1 - revert recall). Irreversible effects (sent email, payment) count in R unless compensated; tag them separately (see RES-02).
- Collateral loss **C = |G missing from S or invalidated| / |G|**.
- Revert precision **P = |X intersect B| / |X|**; revert recall **Rc = |X intersect B| / |B|**.
- **Clean recovery = (R = 0 and C = 0)**; report the continuous form **CR = 1 - (R + C) / 2** only alongside R and C, never alone. **[Our view]** Weights are arbitrary; the pair is the claim. Snapshot-restore baseline will show R near 0 and C high; no-op baseline the reverse. Both baselines must be in the harness.

## 4. Requirements table: regulation and audit hooks

Dates: AI Act Chapter III Sections 1-3 (Arts 9-27 range, including those below) apply from **2 Dec 2027** for Annex III high-risk, **2 Aug 2028** for Annex I [14]. **[Our view]** Our ten agents are not themselves a listed high-risk system; the hooks are design alignment and a way to speak the regulator's language. A bank's credit-scoring AI is high-risk under Annex III 5(b), fraud detection excluded [15].

| Source clause (official text) | Requirement | Our component |
|---|---|---|
| EU AI Act Art 12(1) [10] | "technically allow for the automatic recording of events (logs) over the lifetime of the system" | Recorder |
| Art 12(2) [10] | Events relevant to identifying risk situations, post-market monitoring (Art 72) and operation monitoring (Art 26(5)) | Recorder, Monitor |
| Art 12(3) [10] | Minimum log content (use start/end, reference database, matched input, verifier identities) is specified only for Annex III 1(a) systems | Recorder (adopt as field checklist) |
| Art 14(4)(a) [11] | Overseer can "duly monitor its operation, including in view of detecting and addressing anomalies, dysfunctions and unexpected performance" | Monitor |
| Art 14(4)(d) [11] | Decide "not to use", "disregard, override or reverse the output" | Recovery (selective revert) |
| Art 14(4)(e) [11] | "interrupt the system through a 'stop' button or a similar procedure that allows the system to come to a halt in a safe state" | Containment (kill switch; "safe state" means no half-applied writes) |
| Art 14(5) [11] | Two-person separate verification applies to Annex III 1(a) only | Optional design: two-person approval for irreversible actions |
| Art 19(1)-(2) [12] | Logs kept "at least six months"; financial-institution providers keep them as part of financial-services-law documentation | Recorder retention policy |
| Art 26(2), 26(5), 26(6) [13] | Deployer assigns competent human oversight; on suspected risk "shall suspend the use of that system"; serious incident reported to provider first; logs kept at least six months | Identity (named overseer), Containment, Recorder |
| NIST AI RMF 1.0 MANAGE 2.4, MANAGE 4.1, MANAGE 4.3 [19] | Mechanisms "to supersede, disengage, or deactivate"; post-deployment monitoring; "Processes for tracking, responding to, and recovering from incidents and errors are followed and documented" | Containment, Monitor, Recovery |
| NIST AI RMF GOVERN 4.3 [19]; AI 600-1 GV-4.3-002, GV-1.7-001 [20] | Incident identification; minimum criteria for GAI incident reporting; ability to deactivate | Monitor, Containment, Evaluation harness |
| EU DORA Arts 10, 12, 17 [23] (applies from 17 Jan 2025, Art 64) | Mechanisms to "promptly detect anomalous activities"; backup and restoration with minimum downtime; "record all ICT-related incidents" and run response procedures | Monitor, Recovery, Recorder |
| PRA SS1/23 Principles 1, 3, 5 [22] | Model inventory (1.2); regular testing of outcomes (Principle 3) and documentation (3.5(a)); use of model "only under strict controls or mitigants" when under-performing (5.2(a)(i)). Text does not mention AI/ML or "audit trail" | Identity (inventory), Recorder, Containment |
| RBI FREE-AI Report, 13 Aug 2025 [24] | Sutra 2: "final authority should rest with humans, who should be able to override AI"; Sutra 5: "Accountability cannot be delegated to the model and underlying algorithm"; calls for incident-reporting and audit expansion to cover AI; reports "only 18% maintained audit logs" among surveyed AI-using entities (Section 3.3.13) | Identity, Recorder, Containment |
| CERT-In Directions, 28 Apr 2022 [25] | Report listed incidents "within 6 hours of noticing"; "maintain [logs of all ICT systems] securely for a rolling period of 180 days" within Indian jurisdiction; Annexure I item 20 covers incidents affecting AI/ML systems | Monitor (6-hour clock), Recorder (retention, data residency) |

## 5. Implications for our design

- **Evaluation harness (primary ask).** Ship a scenario runner with a ground-truth label file (t0, B, G, taint edges) per scenario, and compute: TTI (two stages), TTI-scope, false-accusation count, TTC, damage-in-window, collateral stall, R, C, P, Rc, CR, and irreversible-effect count. Run >= 20 seeded runs per scenario; report median, p95, max, never mean alone [3]. Include two baselines (snapshot-restore, no-op) and one red-team probe agent that keeps attacking after containment so TTC is verifiable by the jury.
- **Oracle S\*.** Build the counterfactual replay (culprit removed) and compare on invariants and the effect ledger. Avoid byte comparison.
- **Recorder.** Capture the fields regulators ask for: timestamp, agent_id, overseer identity (Art 26(2)), action, inputs/outputs, and retention config defaulting to >= 6 months (Art 12, 19, 26(6)) and a configurable 180-day in-region mode (CERT-In).
- **Containment.** Implement "halt in a safe state" explicitly (Art 14(4)(e)): in-flight writes either complete or are rolled back; test it.
- **Monitor.** Expose a "time since first anomaly signal" clock and an export in the CERT-In 6-hour format as a stretch demo.
- **Avoid** claiming "EU AI Act compliant". **[Our view]** Claim "maps to Art 12/14 and NIST MANAGE 2.4 / 4.3".

## 6. Implications for framing (facts only)

- Regulators and standards ask for incident detection, stop, and recovery, but publish no measurement for any of them [2][3].
- Reported industry scale: 241 days (IBM 2025) and 247 days (IBM 2026, secondary reports) from breach to identify-and-contain [6][8]. These are data-breach lifecycles, not agent incidents; do not present them as agent-incident numbers.
- RBI FREE-AI: "Accountability cannot be delegated to the model and underlying algorithm" [24].
- Verification of the AI Act timeline: 2 Dec 2027 (Annex III) and 2 Aug 2028 (Annex I) appear in the EC AI Act Service Desk's consolidated Art 113, marked AMENDED [14]; the Art 12 page states its text is "based on the EUR-Lex consolidated version as at 27 July 2026" [10]. Secondary sources: provisional agreement 6 May 2026, confirmed by Coreper 13 May 2026 [16]; "Regulation (EU) 2026/1744, in force since 27 July 2026" [17]. We could not open the Council, Parliament or Official Journal pages (egress proxy blocked those hosts), so the regulation number and publication date are secondary-sourced and unverified.

## 7. Open questions

- Confirm regulation number and Official Journal date from EUR-Lex (anaya or RES-SYN, when network access allows).
- Read the full Google SRE paper for the stated reasons mean metrics fail [3], and IBM's 2026 PDF for the separate identify/contain split.
- PRA's page shows a current SS1/23 version "effective from 23 April 2026 (LIAF01/26)", with 17 May 2024 as the past version [21]. The PDF we read states 17 May 2024 [22]. Check what changed before citing clause numbers.
- RBI FREE-AI numbered recommendations were beyond the text we could read; check for any on kill switch/fallback.
- Taint/dependency definition for set B depends on RES-01 and RES-04 designs.

## 8. Sources

Primary unless marked. Pages marked (WF) were read through the web-fetch tool; direct download of some hosts was blocked.

1. NIST, SP 800-61r3 landing page, April 2025. https://csrc.nist.gov/pubs/sp/800/61/r3/final
2. NIST, SP 800-61r3 "Incident Response Recommendations and Considerations for Cybersecurity Risk Management" (PDF, WF). https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
3. Google SRE, Davidovič, "Incident Metrics in SRE" (undated on page). https://sre.google/resources/practices-and-processes/incident-metrics-in-sre/
4. DORA (research programme), DORA metrics guide, page updated 5 Jan 2026. https://dora.dev/guides/dora-metrics/
5. DORA, history of delivery metrics. https://dora.dev/insights/dora-metrics-history
6. IBM newsroom, 30 Jul 2025, Cost of a Data Breach 2025. https://newsroom.ibm.com/2025-07-30-ibm-report-13-of-organizations-reported-breaches-of-ai-models-or-applications,-97-of-which-reported-lacking-proper-ai-access-controls
7. IBM, Cost of a Data Breach report page (shows $4.99M; page metadata date inconsistent). https://www.ibm.com/reports/data-breach
8. Help Net Security, 30 Jul 2026 (secondary). https://www.helpnetsecurity.com/2026/07/30/ibm-cost-of-a-data-breach-2026/
9. Baker Donelson, "Ten takeaways from IBM's 2026 Cost of a Data Breach Report" (secondary). https://www.bakerdonelson.com/ten-takeaways-from-ibms-2026-cost-of-a-data-breach-report
10. European Commission AI Act Service Desk, Article 12. https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12
11. Same, Article 14. https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-14
12. Same, Article 19. https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-19
13. Same, Article 26. https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-26
14. Same, Article 113 (consolidated, with Digital Omnibus amendments marked). https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113
15. Same, Annex III. https://ai-act-service-desk.ec.europa.eu/en/ai-act/annex-3
16. Gibson Dunn, EU AI Act omnibus agreement (secondary, law firm). https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/
17. Usercentrics, EU AI Act deal (secondary, vendor; used only for regulation number). https://usercentrics.com/knowledge-hub/eu-ai-act-high-risk-delay-article-50-transparency-consent/
18. NIST, AI RMF page (AI RMF 1.0 released 26 Jan 2023; AI 600-1 26 Jul 2024). https://www.nist.gov/itl/ai-risk-management-framework
19. NIST AI 100-1, AI RMF 1.0 (PDF, WF, first 100,000 characters). https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
20. NIST AI 600-1, GenAI Profile (PDF, WF, first 100,000 of 162,139 characters). https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
21. Bank of England PRA, SS1/23 page. https://www.bankofengland.co.uk/prudential-regulation/publication/2023/may/model-risk-management-principles-for-banks-ss
22. Bank of England PRA, SS1/23 PDF (WF). https://www.bankofengland.co.uk/-/media/boe/files/prudential-regulation/supervisory-statement/2023/ss123.pdf
23. EUR-Lex, Regulation (EU) 2022/2554 (DORA), full text (WF, excerpts via paged read). https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32022R2554
24. Reserve Bank of India, FREE-AI Committee Report, 13 Aug 2025 (WF, first 100,000 of 297,585 characters). https://rbi.org.in/Scripts/PublicationReportDetails.aspx?ID=1306
25. CERT-In, Directions under section 70B(6), 28 Apr 2022. https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf
