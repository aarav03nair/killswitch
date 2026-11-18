# RES-09: Lacuna sweep: 2025-26 ML papers on multi-agent accountability, attribution, rollback

## Errata (v2, 20 Nov 2026)

Changes after review by anaya (body otherwise unchanged):
1. BICR corrected to "Benign Infection Control Rate" = 1 - ASR (RES-11), not "benign infection control".
2. Removed the inference "14.2% vs 55.2%, so a deterministic recorder beats LLM judges". The numbers come from different methods and splits, and provenance answers "who wrote the effect", not "whose reasoning failed". Kept only: structure helps attribution.
3. OpenAI-Hugging Face July 2026 incident is now marked verified (RES-11, METR 26 Aug 2026); "unverified" removed.
4. Added Wang et al. 2608.10502 and State Footprints 2610.03140 as closest selective-undo prior art (section 4, sources 20-21). Wang is read from the Lacuna summary only.

Owner: meera. Reviewer: anaya. Run 19 Nov 2026 with the Lacuna Research connector (search_lacuna: paper, cluster, hypothesis, resource; then get_paper / get_direction / get_hypothesis / get_resource). Method note: "[Lacuna summary]" means I read Lacuna's generated summary of the paper, not the PDF. Numbers below are quoted from those summaries and must be checked against the papers before a jury sees them. Lacuna covers ML/AI only, so systems work (Retro, Warp, OTel, SPIFFE) is not in it; see RES-01..RES-08.

## 1. TL;DR

- **Closest competitor: Airlock (arXiv 2611.06727, 4 Nov 2026) [5].** Same problem as ours ("bound the blast radius without killing healthy concurrent work"): append-only provenance DAG, forward taint trace on alert, min-cut containment, per-object switches such as credential revoke. Reports +68 to +96 pp more healthy work retained than native controls. It is **containment, not rollback**: its own limitations say it does not un-taint internal memory and needs "orthogonal rollback mechanisms". [Fact, Lacuna summary]
- Our differentiator therefore survives but narrows. "Provenance graph keyed by agent identity" is no longer novel. What Airlock does not do, per its summary, is **undo already-landed writes of one agent and re-plan its dependants**. Frame ours as "containment (Airlock-style) + selective undo + audit", not as a first.
- Second closest: **From Spark to Fire (arXiv 2603.04474) [9]**: lineage graph of atomic facts, message-level interception, automated rollback-and-rewrite to the upstream agent. Its ablation says removing rollback collapses containment (BICR 3.1%; BICR = Benign Infection Control Rate = 1 - ASR, attack success rate). It rolls back *messages*, not external state effects. [Fact, Lacuna summary]
- Automated attribution is weak without structure. Who&When (ICML 2025) best agent-level 53.5%, step-level 14.2% [1]; structured dependency-graph reading lifts exact step accuracy to 55.20% on the algorithm-generated split [2]. The two numbers use different methods and splits, so they do not show that any approach beats another; they only suggest that structure helps attribution. Separately, a recorder answers "who wrote the effect" (provenance), not "whose reasoning failed" (what Who&When measures). Counterpoint: MP-Bench (2603.25001) says single-oracle labels are themselves contested (only 16.2% of failure steps had 100% annotator consensus) [10].
- Reusable for our 10-agent eval: Who&When for the attribution baseline, ARIA dataset, Agent-ZTA's `normal/restricted/jail` model, Airlock's metrics (healthy work retained, post-alert leaks). No ready-made "10 agents + injected faults + selective rollback" benchmark was found in Lacuna. That is a gap we can claim [Our view].

## 2. Ranked papers (2025-2026), relevance in one line

Ranking = closeness to "per-agent accountability + containment + selective recovery". All URLs are canonical Lacuna URLs (utm params dropped).

1. **Airlock: Bounding the Multi-Agent Blast Radius via Selective Online Containment**, arXiv 2611.06727, Nov 2026 [5]. Provenance DAG + deadline-aware min-cut over control switches; closest competitor (section 4).
2. **From Spark to Fire: Modeling and Mitigating Error Cascades in LLM-Based Multi-Agent Collaboration**, arXiv 2603.04474, Mar 2026 [9]. Lineage graph plus rollback directive; shows hub agents are most dangerous (up to 10.31x impact vs leaf nodes, per summary), so our eval should corrupt a hub as well as a leaf.
3. **Agent-ZTA: Chain-Aware Zero Trust for Multi-Agent Delegation**, arXiv 2611.18999, 13 Nov 2026 [6]. Branch-scoped containment (`normal/restricted/jail`), fail-closed, effective authority E_i(t) vs granted D_i; formal only, no empirical eval; direct input to Identity + Containment.
4. **Which Agent Causes Task Failures and When? (Who&When)**, ICML 2025, OpenReview GazlTYxZss [1]. Baseline for "LLM-judge attribution is weak": 127 systems, 184 annotated failure tasks, best 53.5% agent / 14.2% step accuracy; humans disagree 15-30% on the decisive error.
5. **Adaptive Influence Graphs for Failure Attribution**, arXiv 2608.24361, Aug 2026 [2]. Dependency graph instead of flat log: 55.20% exact step accuracy vs 51.60% prior best; deep failures (step 5+) 10.8% to 40.5%. Supports "structure beats reading logs", and shows our recorder's read/write graph is the right object.
6. **From Agent Traces to Trust: Evidence Tracing and Execution Provenance in LLM Agents (survey)**, arXiv 2606.04990, Jun 2026 [3]. Concludes no current framework combines fine-grained provenance with runtime enforcement and recovery (their words, via Lacuna); 9 provenance relations incl. DEPEND-ON; names "recovery-oriented evaluation" as open. Strong citation for our framing and for the schema.
7. **PACE: Provenance-Aware Capability Enforcement for Tool-Using LLM Agents**, arXiv 2610.01349, Oct 2026 [4]. Evidence graph at the tool boundary, executable cuts, effect verification; 62 of 79 attack categories strictly lowest ASR. Single-agent, injection-focused; reuse the "mediate at the last boundary" argument for our gateway.
8. **ARIA: Runtime Inspection and Amendment for Multi-Agent Systems**, arXiv 2610.20780, Oct 2026 [7]. Live detect-and-patch; 3,953 verified repairs, 4 MAS frameworks, harmful-intervention rate about 1.5-2.0% vs 5-14%. Repairs by substituting one message, cannot roll back earlier state (per its limitations).
9. **Rollback the World, Keep the Reflection (RIR)**, arXiv 2609.18304, Sep 2026 [8]. Single-agent environment rollback with retained failure memory; under 1.3 rollbacks per task on average. Evidence that whole-state rollback is what the literature does today, and that localisation depends on an accurate diagnosis.
10. **Rethinking Failure Attribution: Multi-Perspective Benchmark (MP-Bench)**, arXiv 2603.25001, Mar 2026 [10]. 289 logs, 121 MAS configs, 346 expert-hours; warns that single-label attribution is contested. Caveat for how we claim "ground truth" in our own eval.
11. **AgentTrace: Causal Graph Tracing for Root Cause Analysis in Deployed MAS**, AIWILD @ ICLR 2026 [11]. Causal graphs from logs. Seen only as a title and one-line description in a Lacuna direction page; not read.
12. **Binding Agent ID / Identity Management for Agentic AI**, arXiv 2510.25819 (Oct 2025) [12]. Identity surveys, relevant to RES-03. Title and metadata only; not read.

Also seen by title only (not read; chase in Sprint 2 if needed): AgenTracer (ICLR 2026), Aegis automated error generation and attribution (ICLR 2026), Agent-Diff state-diff evaluation of enterprise API agents (EvalEval @ ACL 2026), all listed in direction 20356 [14]. Aegis and Agent-Diff look relevant to fault injection and state-diff scoring.

## 3. Research directions (who leads) and open hypotheses

- **Failure Detection Through Multi-Agent Social Monitoring** (direction 1274, 11 papers) [13]. Lacuna lists Milind Tambe and Gal Kaminka (Bar-Ilan) as top authors; the classical MAS-diagnosis lineage (2003-2022: socially attentive monitoring, model-based diagnosis of coordination failures). Not LLM-specific; useful as prior art vocabulary. [Fact, Lacuna]
- **Autonomous Error Recovery for Interactive Agents** (direction 20356, 227 papers) [14]. Top authors listed include Yejin Choi and several Zhejiang/Southeast Univ. authors; related: "Compounding Errors in Long Horizon Agent Execution" (26796) and "Learning to Recover from Compounding Errors" (17234). OrchDAG is cited there for re-planning only the dependent steps of a plan DAG: the nearest single-agent analogue to "undo and re-plan dependants". [Fact, Lacuna]
- **Credit Assignment in Cooperative Multi-Agent Systems** (27071) is RL credit assignment, not accountability; skip [15].
- **Hypotheses (generated proposals, not results; treat as idea prompts):** none states "per-agent selective undo" directly.
  - *Compiled Side Effects as Interference Checks for Multi-Agent LLM Plans* [16]: pre-dispatch conflict check via compiled effect sets E_i, P_i, G_i. Useful for our reversibility/effect-class declaration (RES-02).
  - *Calibrated Rollback: Using Step-Level Confidence to Decide Where and How an Agent Recovers* [17]: choose (resume point, action) by calibrated success probability; names fault-injection suites (ResiliBench, Aegis, "Broken Calculator") as testbeds.
  - Also surfaced: Retraction-Aware Rollback for Streaming Literature Agents (f32723ef34950890); not opened.
  - [Our view] The absence of a hypothesis on selective undo, plus the survey's "recovery-oriented evaluation" gap [3], suggests the niche is open in this corpus.

## 4. Closest competitor to per-agent selective undo, and how we differ

| Dimension | Airlock [5] | Spark to Fire [9] | Ours (planned) |
|---|---|---|---|
| Goal | Contain a fault, keep healthy concurrent work | Stop error cascades in messages | Identify, contain, and undo one agent's damage, keep others' work |
| Record | Append-only provenance DAG, per-site ordered journals | Lineage graph of atomic facts | Per-agent signed action log, read/write sets, hash-chained |
| Identity | Tree authority hierarchy, per-credential switches | Not the focus | Identity on every action; attribution from the record, not an LLM |
| Containment | Min-cut over switches; fence-then-prune | Message screening (green/yellow/red) | Revocation at a chokepoint, quarantine state |
| Undo of landed effects | No; "does not un-taint memory", needs pairing with rollback | Rollback-and-rewrite of upstream message only | Core: revert A's writes, re-plan/re-approve B's dependants |
| Irreversible effects | Blocks before they commit (sinks) | Not addressed | Effect classes gated pre-execution (RES-02) |
| Audit evidence | Journals | Not the focus | Tamper-evident log verifiable by a third party |

[Fact] for Airlock and Spark to Fire columns (Lacuna summaries); the Ours column is [Our view] and is the plan, not a result.

**Closest selective-undo prior art (added in v2).** Airlock is the closest containment work; the closest selective-undo work is:
- **Wang et al., From Faulty Memories to Corrected Actions: Dependency-Guided Rollback Repair for Memory-Augmented Agents**, arXiv 2608.10502, 11 Aug 2026 [20]. Single agent. Builds a memory-to-action dependency graph from runtime provenance, traces forward from a faulty memory, keeps nodes with independent clean support, then selectively replays only the answer-relevant affected steps. Reports 85.3% recovery vs 77.3% for LLM-judge repair on its own 150-case benchmark (68.0% vs 54.0% on an adapted LongMemEval-V2 subset). Limits per its summary: needs an instrumented runtime, cannot undo irreversible external side effects. [Fact, Lacuna summary] We differ: multi-agent, per-agent identity, external-effect classes, tamper-evident audit.
- **State Footprints (Mraz et al.), arXiv 2610.03140, Oct 2026** [21]. Vision paper: nested transaction IDs, abort one task's writes plus the tasks that read them. Rollback is not implemented or measured (RES-10). We differ by building and measuring it with identity and containment. Cite as framing prior art, not as evidence that rollback works.

**How we differ (honest version):** (1) Airlock stops the bleeding forward in time; we also repair backward in time. (2) Airlock's taint is data-exposure and conservative; it says endorsements may be needed to declassify. Our design should use read-set vs write-set plus a human/agent re-approval step for dependants, so the repair set is explicit and auditable. (3) Airlock targets distributed physical/service workflows; we target an auditable log a jury can attack. (4) We must NOT claim novelty for "provenance DAG + containment". Claim the combination with undo and the audit evidence, and cite Airlock as related work. Also reconcile with RES-05's gap statement (it said no tool does agent-level quarantine tied to provenance): Airlock is a research prototype doing exactly that; RES-05's conclusion holds for OSS tools only.

## 5. Reusable code, datasets, benchmarks for the 10-agent eval

- **Who&When** dataset and code (127 systems, 184 failure tasks) [1]. Lacuna search did not link a resource entry for it; the GitHub URL in PLAN.md (ag2ai/Agents_Failure_Attribution) is unverified by me. Use for the "LLM judge vs recorder" attribution baseline.
- **MP-Bench** (289 logs; arXiv 2603.25001) [10] for multi-label attribution scoring; resource link not checked.
- **ARIA dataset**: 3,953 execution-verified repairs over MetaGPT, OpenManus, Magentic-One, AG2; 26-category failure taxonomy [7]. Availability of the release not checked.
- **Airlock testbeds**: HomeSvc (3 agents, 81 tasks), a 7-agent workflow suite, simulator over 24,266 records; metrics: healthy work retained without redo, post-alert leaks, makespan within +-8.5% [5]. Release not checked; we can mimic the metrics regardless. Strong candidates for our TTI / TTC / clean-recovery definitions.
- **Injection suites cited by PACE**: AgentDojo, InjecAgent, ASB, MCPTox, WASP [4]; useful for fault scenarios. Repos not checked.
- **Hell or High Water** (JHU-CLSP, MIT licence, Python; COLM 2025; 5 stars) [18]: tool-failure benchmark on Spider-derived DB tasks. Single-agent; low priority.
- **MedAgentAudit** (github.com/yhzhu99/MedAgentAudit, no licence listed, 11 stars) [19]: failure-mode audit of medical MAS; domain-specific, low priority.
- Verdict [Our view]: build our own 10-agent scenario generator with scripted fault injection and ground-truth write sets (so attribution and collateral loss are exact, no human labelling), and report Airlock-style "healthy work retained" next to a new "residual damage" metric (RES-08).

## 6. Open questions

- Airlock cites a "July 2026 OpenAI-Hugging Face incident" as motivation [5]. **Verified** in RES-11 (METR investigation, 26 Aug 2026, plus press coverage); safe to cite with METR as the source.
- Does Airlock release code or data? Fetch the arXiv PDF (2611.06727) and check how it handles agent-written state; **anaya/RES-SYN**. Lacuna summary only; a full read could change the competitor assessment.
- Several arXiv IDs and dates here are as listed by Lacuna; confirm on arxiv.org before citing in the abstract.
- Which of Aegis / AgenTracer / Agent-Diff offer reusable fault-injection or state-diff scoring: Sprint 2 eval harness task.

## 7. Sources (all primary papers, read as Lacuna summaries unless noted; accessed 19 Nov 2026)

1. Zhang et al., Which Agent Causes Task Failures and When?, ICML 2025. https://lacuna.tiptreesystems.com/work/which-agent-causes-task-failures-and-when ; https://openreview.net/forum?id=GazlTYxZss
2. Adaptive Influence Graphs for Failure Attribution in Multi-Agent Systems, arXiv 2608.24361. https://lacuna.tiptreesystems.com/work/adaptive-influence-graphs-for-failure-attribution
3. From Agent Traces to Trust: A Survey of Evidence Tracing and Execution Provenance in LLM Agents, arXiv 2606.04990. https://lacuna.tiptreesystems.com/work/from-agent-traces-to-trust-a-survey
4. PACE: Provenance-Aware Capability Enforcement for Tool-Using LLM Agents, arXiv 2610.01349. https://lacuna.tiptreesystems.com/work/pace-provenance-aware-capability-enforcement-for-tool
5. Airlock: Bounding the Multi-Agent Blast Radius via Selective Online Containment, arXiv 2611.06727. https://lacuna.tiptreesystems.com/work/airlock-bounding-the-multi-agent-blast-radius
6. Agent-ZTA, arXiv 2611.18999. https://lacuna.tiptreesystems.com/work/agent-zta-a-chain-aware-zero-trust-model
7. ARIA: Runtime Inspection and Amendment for Multi-Agent Systems, arXiv 2610.20780. https://lacuna.tiptreesystems.com/work/aria-runtime-inspection-and-amendment-for-multi-agent
8. Rollback the World, Keep the Reflection, arXiv 2609.18304. https://lacuna.tiptreesystems.com/work/rollback-the-world-keep-the-reflection-rollback-induced
9. From Spark to Fire, arXiv 2603.04474. https://lacuna.tiptreesystems.com/work/from-spark-to-fire-modeling-and-mitigating-error
10. Rethinking Failure Attribution in Multi-Agent Systems (MP-Bench), arXiv 2603.25001. https://lacuna.tiptreesystems.com/work/rethinking-failure-attribution-in-multi-agent-systems
11. AgentTrace, AIWILD @ ICLR 2026. https://lacuna.tiptreesystems.com/work/agenttrace-causal-graph-tracing-for-root-cause-analysis (title/description only)
12. Identity Management for Agentic AI, arXiv 2510.25819, DOI 10.48550/arXiv.2510.25819. https://lacuna.tiptreesystems.com/work/identity-management-for-agentic-ai-the-new-frontier (search metadata only)
13. Direction 1274. https://lacuna.tiptreesystems.com/direction/failure-detection-through-multi-agent-social-monitoring-1274
14. Direction 20356. https://lacuna.tiptreesystems.com/direction/autonomous-error-recovery-for-interactive-agents-20356
15. Direction 27071. https://lacuna.tiptreesystems.com/direction/credit-assignment-in-cooperative-multi-agent-systems-27071 (search result only)
16. Hypothesis 562c4405f016b982. https://lacuna.tiptreesystems.com/hypothesis/compiled-side-effects-as-interference-checks-for-multi-agent-llm-plans-562c4405f016b982
17. Hypothesis 9f292f39602d7760. https://lacuna.tiptreesystems.com/hypothesis/calibrated-rollback-using-step-level-confidence-to-decide-where-and-how-an-agent-9f292f39602d7760
18. Resource, JHU-CLSP/hell-or-high-water. https://lacuna.tiptreesystems.com/resource/jhu-clsp-hell-or-high-water/art_87dcf3f8af124c8a8eeff8230e0e4dae ; https://github.com/jhu-clsp/hell-or-high-water
19. Resource, yhzhu99/MedAgentAudit. https://lacuna.tiptreesystems.com/resource/yhzhu99-medagentaudit/art_2589f03d7df84af394f6b9591855bd8f ; https://github.com/yhzhu99/MedAgentAudit
20. Yu et al., From Faulty Memories to Corrected Actions, arXiv 2608.10502 (Lacuna summary only). https://lacuna.tiptreesystems.com/work/from-faulty-memories-to-corrected-actions-dependency-guided ; https://arxiv.org/abs/2608.10502v1
21. Mraz et al., Tracking State Footprints, arXiv 2610.03140 (not in Lacuna; checked in RES-10, Tier B). https://arxiv.org/abs/2610.03140
