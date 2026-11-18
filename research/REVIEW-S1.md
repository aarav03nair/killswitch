# REVIEW-S1: Lead review of RES-01..RES-08

Reviewer: anaya, 19 Nov 2026. All eight reports meet their acceptance criteria. Each had 1–2 claims spot-checked. RES-10 owns the paper numbers. Detail is in each issue's `review` field.

## 1. Verdicts

| Issue | Verdict | Note |
|---|---|---|
| RES-01 | done | Graph + selective revert carry over; replay does not. Retro OSDI'10 confirmed. Overheads need a PDF check. |
| RES-02 | done | Strong taxonomy. TL;DR bullet 1 over-claims "every mechanism classifies first". Sagas = SIGMOD'87. |
| RES-03 | done | MCP "MUST NOT accept or transit any other tokens" verified, so attribution lives at our gateway. |
| RES-04 | done | `gen_ai.*` has no read/write sets. Repo move verified. Span requirement levels unverified. |
| RES-05 | done | agentgateway already exists (Apache-2.0, ~5.7k stars, CEL RBAC). The gap is quarantine that knows provenance. |
| RES-06 | done | Revert-one-keep-later exists, but nothing tracks reads. Dolt not accepted: never run, and outside the CHARTER deps. |
| RES-07 | done | All incidents are single-agent and human-detected. #10077 confirmed ("tool_use command was never logged"). PocketOS details are secondary. |
| RES-08 | done | Art 113 dates verified (2 Dec 2027 / 2 Aug 2028). Don't cite "2026/1744". |

## 2. Hypothesis scoreboard

| H | Result |
|---|---|
| Thesis | **Confirmed**: stores can revert by commit, but none knows who *read* what (RES-06). |
| H1 | **Refined**: the graph carries over; LLM re-execution does not, so we re-plan with approval. |
| H2 | **Confirmed + refined**: 5 classes, assigned per action instance. |
| H3 | **Confirmed**: attribution collapses at MCP no-passthrough and shared credentials. |
| H4a/b | **Confirmed**: OTel has no state fields; agents misreport and logs miss commands. A Merkle log is needed, a bare chain is not enough. |
| H5 | **Refined**: a gateway isn't new; quarantine linked to provenance and rollback is. |
| H6 | **Confirmed** for checkpoints, **refined** for commit-graph stores. |
| H7a | **Confirmed, with a twist**: single-agent only. |
| H7b | **Confirmed**, pending RES-10 (Who&When 53.5% / 14.2%). |
| H8a/b | **Confirmed + refined**: no standard metric exists; we "map to" the rules, we are not "compliant". |

Killed: none. Weakened: "ten agents" as a documented real-world problem.

## 3. Contradictions to resolve

1. **Dolt vs own store.** RES-06 recommends Dolt; the strawman uses `sqlite3`. My view: build our own row-versioned SQLite store, since we need read tracking regardless, and present Dolt as the production twin.
2. **Re-execute vs re-plan.** RES-02 option 3 and strawman A1 re-execute agent B; RES-01 says don't. Proposal: re-run deterministic tool steps (deduplicated by idempotency key) and re-plan LLM steps.
3. **"Nobody has a gateway" vs agentgateway.** That claim is dead. Novelty must rest on dependency-aware quarantine plus selective undo. RES-11 (Airlock) may narrow it further.
4. **No public multi-agent incidents.** The hook becomes single-agent incidents + benchmark failure rates + "the next failure will be multi-agent".
5. **Who&When ≠ our attribution.** Who&When finds whose *reasoning* failed; provenance finds who *wrote* an effect. Don't claim to beat Who&When at its own task.
6. **Tamper evidence.** Strawman A4 says a hash chain is enough; RES-04 and the panel say no. Use Merkle checkpoints held outside the agents' reach.
7. **Classify-before-run.** We *choose* this; it isn't established practice (RES-01 vs RES-02).
8. **Metric circularity.** RES-08's B set must come from the scenario oracle, not our recorder. Add a cost term for tainted good work that has to be re-planned.

## 4. Call #1 agenda

1. Headline: "selective undo" vs "attribution + containment" (items 3–5, RES-11).
2. Recovery semantics: re-plan vs re-execute; conservative vs optimistic taint as the default.
3. Substrate ADR: own SQLite store vs Dolt. Needs an owner before 25 Nov.
4. Honest-framing rules for Aarav (items 3–5; AI Act "maps to").
5. Metrics: merge RES-08 with the panel's TTC redefinition; B from the oracle; re-plan cost term.
6. Tamper-evidence level for the prototype.
7. Verification backlog outside RES-10: overhead figures, Crosby & Wallach, RBI 18%, PRA clauses, IBM 247 days.
