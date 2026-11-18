# Sprint 1 Research Plan (ORG-02)

Owner: anaya (Research Lead). Reviewer: maya. Status: plan only; the research itself is RES-01..RES-08 plus RES-SYN.

## 1. Why this sprint exists

The brief is "Ten agents are working. One just broke something." Teams are scored on **time-to-identify (TTI)**,
**time-to-contain (TTC)** and **clean recovery**, and the jury "rewards the team that frames the problem best".
Sprint 1 has two jobs:

1. **Framing evidence.** Facts, numbers and real incidents that let Aarav state the problem more sharply than other teams.
   (Reminder: the team never writes abstract prose. We hand Aarav framing options, an outline of points and sourced facts.
   The abstract is due 22 Nov, so every report needs to be finished and reviewed by 21 Nov.)
2. **Design evidence.** What to reuse and what to build for an accountability layer over ~10 agents: identity on every
   action, a recorder, live monitoring, containment, and **selective rollback of one agent's damage that keeps the other
   agents' work**.

## 2. Working thesis (to be confirmed or killed, not assumed)

> Rolling back one agent is a **dependency problem, not a snapshot problem**. Once agent B has read or built on agent A's
> output, "undo A" has no clear meaning unless we recorded *who wrote what, who read it, and with what authority*.
> Snapshots and checkpoints can only take the whole system back to an earlier point, which also throws away the good work.
> The 2010-era intrusion-recovery work (Retro, Warp) already solved a version of this for OS and web apps, using action
> history graphs and selective re-execution. Agent stacks today record traces, not dependencies.

If this holds, it becomes the core of the framing ("everyone has a kill switch, nobody has selective undo") and the core
of the architecture (a provenance graph keyed by agent identity). If it fails, we fall back to "attribution + containment"
as the headline.

## 3. Research questions and hypotheses

| # | Question | Hypothesis to confirm or kill | Issue |
|---|---|---|---|
| Q1 | How did Retro, Warp and similar systems undo an attacker's actions while keeping legitimate users' work, and which parts carry over to LLM agents? | H1: The action-history-graph + selective re-execution pattern carries over directly. The hard part is **non-deterministic re-execution**: an LLM agent won't produce the same output twice. | RES-01 |
| Q2 | What do we do about effects that can't be rolled back (sent email, payment, external API calls)? | H2: Actions fall into three classes (*reversible / compensable / irreversible*). Clean recovery needs this class **before** the action runs, so irreversible actions can be gated. Sagas, plus GoEx's "undo + damage confinement", give us the vocabulary. | RES-02 |
| Q3 | How should each agent be identified on every action, including through delegation chains and shared tools such as MCP servers? | H3: Workload identity (SPIFFE/SPIRE, OAuth token exchange) is a solved problem. **Per-action** attribution is not. It breaks at shared tools and services that act with a single service credential. | RES-03 |
| Q4 | What should an action record contain, how does it map to OpenTelemetry GenAI conventions, and how do we make it tamper-evident? | H4a: OTel GenAI spans capture *what an agent called* but not *what state it changed* (write sets, read sets). H4b: Plain logs are not audit evidence. A misbehaving agent can alter or misreport them (in the Replit incident, per reports, the agent misreported what it had done), so the log needs to be append-only and hash-chained or Merkle-backed. | RES-04 |
| Q5 | Which open-source observability and guardrail tools could we reuse for attribution, monitoring and containment? | H5: Observability tools (Langfuse, Phoenix, OpenLLMetry and others) are good at tracing but don't contain anything. Guardrails and policy engines block a single call but have no notion of quarantining an *agent*. Containment through **capability revocation at a chokepoint** (gateway or proxy) is missing. | RES-05 |
| Q6 | Which checkpoint / time-travel / versioned-store tools could give us per-agent selective rollback? | H6: LangGraph time-travel, Dolt, lakeFS and VM/FS snapshots all roll back *a whole state or branch*. None of them roll back *one author's commits while keeping later commits from other authors that depend on them*. That is the gap we fill. | RES-06 |
| Q7 | What do real incidents of agents causing damage look like (detection, containment, recovery), and how good is automated "which agent broke it" attribution? | H7a: In public incidents, humans detected the damage, after a delay, and recovery came from backups (all or nothing). H7b: LLM-judge failure attribution is unreliable. The Who&When benchmark (arXiv 2505.00212) reportedly shows low agent- and step-level accuracy; *verify the numbers*. Deterministic provenance should beat LLM judges on TTI. | RES-07 |
| Q8 | How do we measure TTI, TTC and "clean recovery" in a way the jury can verify, and which regulatory or audit requirements does the design satisfy? | H8a: There is no standard metric for clean recovery. We can define one: **residual damage** (bad effects left behind) plus **collateral loss** (good work discarded). H8b: EU AI Act Art. 12 (automatic logging) and Art. 14 (human oversight), NIST AI RMF, and bank model-risk and operational-resilience rules map directly onto identity, recorder and kill-switch components. Check the current EU high-risk timeline; reports suggest it was delayed to Dec 2027. | RES-08 |
| Q9 | Overall: which framing wins, and what are the design principles? | Synthesis of the above. | RES-SYN |

## 4. How each issue feeds the abstract and the architecture

Abstract structure (Aarav writes it): **Problem → Fix → Why it matters**.
Architecture components (draft): **Identity**, **Recorder** (action and provenance log), **Monitor**, **Containment**,
**Recovery**, **Evaluation harness**.

| Issue | Owner | Abstract section fed | Architecture component fed |
|---|---|---|---|
| RES-01 Selective undo / intrusion recovery | meera | Fix (prior art that proves it's possible) | Recorder (dependency graph), Recovery |
| RES-02 Compensation and irreversible actions | meera | Problem (why "just roll back" fails), Fix | Recovery, Containment (pre-execution gating) |
| RES-03 Agent identity and delegation | rohan | Fix (who did it) | Identity, Containment (revocation) |
| RES-04 Action record, OTel GenAI, tamper-evident log | rohan | Why it matters (auditable, not demoed) | Recorder, Monitor |
| RES-05 OSS observability and guardrails | leela | Fix (what's new vs. existing tools) | Monitor, Containment (reuse decisions) |
| RES-06 OSS checkpoint / versioned stores | leela | Problem (gap in existing tools) | Recovery (storage substrate choice) |
| RES-07 Real incidents and failure attribution | sameer | Problem (hook, real numbers) | Monitor (detection signals), eval scenarios |
| RES-08 Metrics and regulatory hooks | sameer | Why it matters (bank/regulator relevance) | Evaluation harness, Recorder (fields required) |
| RES-SYN Synthesis | anaya | All: framing options, outline, fact sheet | Design principles → Sprint 2 ADRs |

## 5. Concrete starting points (from the planning searches; researchers must verify)

- **Selective undo:** Retro (Kim et al., OSDI 2010) https://people.csail.mit.edu/nickolai/papers/kim-retro.pdf ;
  Warp (SOSP 2011) and follow-ups Dare and Aire; Taesoo Kim's PhD thesis https://vm-web.pdos.csail.mit.edu/papers/taesoo-phd-thesis.pdf
- **LLM runtime with undo:** GoEx (Berkeley Gorilla) https://arxiv.org/abs/2404.06921 , https://gorilla.cs.berkeley.edu/blogs/10_gorilla_exec_engine.html
- **OTel GenAI semconv:** the official spec on opentelemetry.io (semantic-conventions repo, `gen_ai.*`, agent/tool spans).
  Blogs found (secondary sources only): https://www.dash0.com/knowledge/opentelemetry-genai-semantic-conventions-explained
- **Agent identity:** IETF draft-klrc-aiagent-auth https://www.ietf.org/archive/id/draft-klrc-aiagent-auth-03.html ;
  draft-rampalli-pedigree https://datatracker.ietf.org/doc/html/draft-rampalli-pedigree-00 ; SPIFFE spec (spiffe.io);
  MCP authorization spec (modelcontextprotocol.io); RFC 8693 (token exchange); RFC 9421 (HTTP message signatures)
- **Tamper-evident logs:** RFC 9162 (Certificate Transparency v2), Sigstore Rekor, Trillian
- **Incidents:** Replit production-database deletion (Jul 2025), AI Incident Database https://incidentdatabase.ai/ ,
  e.g. https://incidentdatabase.ai/reports/5577/ ; OECD AI Incidents Monitor
- **Failure attribution:** Who&When https://arxiv.org/abs/2505.00212 , code https://github.com/ag2ai/Agents_Failure_Attribution
- **Versioned stores / checkpoints:** LangGraph persistence and time-travel docs; Dolt (dolthub.com); lakeFS; Replit snapshot
  engine blog https://blog.replit.com/inside-replits-snapshot-engine ; DeltaBox https://www.alphaxiv.org/abs/2605.22781
- **Regulation:** EU AI Act Art. 12 https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12 (also Art. 14, 19, 26);
  NIST AI RMF 1.0 and NIST AI 600-1 (GenAI profile); NIST SP 800-61r3 (incident response)

## 6. Schedule

- 19–20 Nov: RES-01..RES-08 in parallel (no dependencies between them).
- 20 Nov evening: anaya reviews each report (done / changes).
- 21 Nov: RES-SYN produces framing options, an outline and a fact sheet for Aarav. Aarav drafts on 21–22 Nov and the team reviews his draft.

---

## Brief for researchers

**Scope.** One issue = one focused question = one report at the path the issue gives (`research/RES-xx.md`). Stay inside
your question. If you find something important for another issue, add one line under "Open questions" naming that issue.

**Report template (use these headings, in this order):**

1. **TL;DR**: 3–5 bullets. The single most important finding goes first.
2. **Findings**: numbered findings, each with inline citations `[n]` that resolve to the Sources list.
   Mark each claim **[Fact]** (stated in a source) or **[Our view]** (our inference or opinion).
3. **Comparison table**: required where the issue asks for it, and encouraged elsewhere. Rows = systems/tools/sources,
   columns = the dimensions in the acceptance criteria.
4. **Implications for our design**: concrete, opinionated bullets tied to architecture components (Identity, Recorder,
   Monitor, Containment, Recovery, Evaluation harness). Say what to **reuse, build, or avoid**.
5. **Implications for framing** (optional but valued): facts or angles Aarav could use. Give bullets and numbers with sources,
   **never** finished abstract sentences.
6. **Open questions**: what you couldn't resolve, and which issue or sprint should pick it up.
7. **Sources**: numbered list with title, author/org, date, URL. Say whether each source is primary or secondary.

**Quality bar.**
- **Primary sources first:** papers, specs/RFCs, official docs, source code, regulator texts, first-hand incident
  write-ups. Blogs and vendor marketing are secondary: use them only to find primary sources, and label them.
- **Every factual claim has a URL.** No invented citations, numbers, quotes or paper titles. If you can't find a source,
  say "not found" and don't guess.
- **Separate fact from opinion** with the [Fact] / [Our view] tags. Numbers must be quoted exactly, with units and context
  (e.g. "agent-level accuracy on dataset X"). Don't round a number into a stronger claim.
- **Dates matter.** Standards and drafts move fast (OTel GenAI conventions are still in development; IETF drafts have version
  numbers). Give the version or date you read.
- For OSS tools: link the repo, check the README/docs/code yourself, and note the licence, last release and stars/activity
  if visible. Say "claimed in README" vs "verified in code".
- No submission-ready abstract prose anywhere.

**Length.** 800–1,800 words, not counting tables and the Sources list. Shorter and sharper beats longer.

**Done means:** every acceptance criterion on your issue is visibly met in the report, the file is at the deliverable path,
you have posted a `summary` on the issue (3–5 lines: headline finding and anything that surprised you), and the issue is
moved to `in_review`.
