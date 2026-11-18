# RES-05: OSS survey of agent observability, guardrails and policy engines (reuse vs. build)

Owner: leela. Reviewer: anaya. Read on 19 Nov 2026 from shallow clones (`git clone --depth 1`, read-only, nothing executed) at the commits listed in section 3. GitHub API was blocked in this sandbox, so **stars and release dates could not be fetched**; "activity" below is the date of the last commit on the default branch. Version strings come from each repo's `pyproject.toml`/`package.json`.

## 1. TL;DR

- **No surveyed tool can quarantine an agent.** Observability tools (Langfuse, Phoenix, OpenLLMetry, AgentOps) record and alert but never block. Guardrail libraries (NeMo, Guardrails AI, Invariant, LlamaFirewall) judge one input, output or tool call. H5 is mostly confirmed.
- **H5 needs one correction.** The chokepoint idea already exists as a product: **agentgateway** (Apache-2.0, very active) is an MCP/LLM/A2A proxy with JWT/API-key auth, CEL authorization rules on MCP tools, OTel export and file-watch config reload. A "deny identity X" rule is plausible there, but we did not verify it. The gap is therefore not "a gateway", it is **agent-level quarantine state tied to provenance and rollback**.
- **Policy engines (OPA, Cedar) are permissive, offline and embeddable**, but have no notion of an agent. They are the right *policy-as-code* vocabulary for Barclays-style audiences, not a containment feature.
- **Licence traps:** Phoenix is Elastic License 2.0 (not OSI open source); Langfuse is MIT except `ee/` directories; LlamaFirewall's own folder is MIT but its default scanners need a gated Hugging Face model and a Together API key.
- **Verdict: build a thin Python enforcement point (gateway + kill registry + recorder hook) ourselves; reuse standards and patterns, not runtimes.** Map it to agentgateway/OPA/Cedar in the "production path" story.

## 2. Findings

1. **[Fact] Observability tools attribute by user/session, not by agent identity.** Langfuse's OTel ingestion handles `userId`/`sessionId`/`tags` on traces (test fixtures in `packages/shared/src/server/otel/`) [1]. Phoenix exposes a `user.id` span attribute in its GraphQL `Span` type [2]. OpenLLMetry attaches arbitrary key/values with `set_association_properties` [3]. "Which of ten agents did it" is therefore a convention we would have to impose (e.g. an `agent.id` attribute), not something these tools enforce. **[Our view]** None can stop a spoofed or missing agent id.
2. **[Fact] Langfuse is the only observability tool where we verified alerting.** A `monitorQueue` worker publishes monitor alerts to a webhook queue; automation trigger sources include `monitor` [1]. The monitors code is under `packages/shared/src/features/monitors`, outside the `ee/` directories, so it falls under MIT [1]. It does not call back into any agent runtime.
3. **[Fact] Phoenix** ingests OTLP at `/v1/traces` and runs locally via `pip install arize-phoenix` [2]. We found no alert/webhook feature in its Python source (only unrelated Kubernetes-webhook text). Licence is ELv2 [2]. **[Our view]** Use as an optional viewer only, never a dependency of our code.
4. **[Fact] OpenLLMetry** is a set of OTel instrumentation packages, including `opentelemetry-instrumentation-mcp`, `-openai-agents`, `-crewai`, `-langchain` and a semantic-conventions package [3]. It is a library; it has no server, alerting or blocking.
5. **[Fact] AgentOps** (MIT) depends on the OTel SDK [4]. Its README lists prompt-injection detection via a third party as a feature (claimed, not verified). The last commit is 25 Jun 2026, about five months before reading. We did not find `agent_id` in its semantic-convention module.
6. **[Fact] NeMo Guardrails** (Apache-2.0, 0.25.0-rc1, active) has "tool call rails ... applied to tool calls before they are executed" and a `hooks-server` command with an allow-list of tools/arguments; OTel tracing is an optional extra [5]. It blocks a single call, per config. No per-agent identity or quarantine found. It normally needs an LLM to run Colang flows (claimed, not tested offline).
7. **[Fact] Guardrails AI** (Apache-2.0, 0.11.0) validates LLM input/output; failure actions are `reask, fix, filter, refrain, noop, exception, fix_reask, custom` [6]. We found no tool-call or agent concept in its README. Hub validators involve a hub token module (whether it is mandatory was not checked).
8. **[Fact] Invariant Guardrails** (Apache-2.0, 0.3.5; last commit 12 Jan 2026, the quietest repo here) offers a rule language over traces, including **cross-call flow rules** such as "get_inbox then send_email to unknown address" [7]. The analyzer runs locally (`Policy.analyze`, `Monitor.check` over past and pending events) [7]. The proxy ("Gateway") is a separate repo we did not read (claimed in README). **[Our view]** Best-in-class idea for stateful single-call blocking; useful as a design reference for our detection rules.
9. **[Fact] LlamaFirewall** decisions are `ALLOW / HUMAN_IN_THE_LOOP_REQUIRED / BLOCK`, trace-aware, with scanner types prompt_guard, agent_alignment, code_shield, hidden_ascii, pii, regex [8]. README prerequisites: access to Hugging Face Meta models; AlignmentCheck needs `TOGETHER_API_KEY` [8]. Its folder is MIT, but the PurpleLlama repo-root licence is the Llama 3.2 community agreement [8]. **[Our view]** Fails our "offline, no keys" constraint except for the regex scanner.
10. **[Fact] OPA** (Apache-2.0, CNCF graduated) is a general policy engine with decision logs (events describing each policy query, reportable to remote HTTP servers), Wasm compilation and an Envoy integration in-tree [9]. **Cedar** (Apache-2.0, Rust crates) is an authorization policy language with CLI, formatter and wasm build [10]. Both run offline as a library/binary. Neither has any agent concept. **[Our view]** Revocation = update the data/entity store the policy reads; this is our design, not a documented feature.
11. **[Fact] agentgateway** (Apache-2.0, Rust, committed 18 Nov 2026) is "an open source proxy built on AI-native protocols (MCP & A2A)" with JWT and API-key auth modules, `mcpAuthorization` CEL rules evaluated on individual returned tools/prompts/resources, `mcpGuardrails`, OTLP exporters (`opentelemetry-otlp` in Cargo.toml, `telemetry/` module) and a file watcher that reloads config on change (`state_manager.rs`) [11]. Not verified: that a deny-by-identity rule is enforced mid-session, reload latency, or any per-agent kill API.

## 3. Capability matrix

Legend: **V** = verified in code/docs we read; **C** = claimed (README/docs only, or not tested); **N** = not found in what we read; **-** = not applicable to this kind of tool. "OTel" = emits or ingests OpenTelemetry.

| Tool (licence; version; last commit; HEAD) | Per-agent attribution | OTel | Live alerting | Block single call | Quarantine whole agent | Revoke credentials | Offline / no key |
|---|---|---|---|---|---|---|---|
| Langfuse [1] (MIT + `ee/`; 4.82.0; 2026-11-18; 6dfeb60) | user/session only **V**; agent id N | ingest **V** | **V** (monitors to webhooks) | N | N | N | self-host via docker compose **C** (multi-service) |
| Arize Phoenix [2] (ELv2; 12.16.1; 2026-11-18; e37d177) | `user.id` **V**; agent id N | ingest **V** | N | N | N | N | local `pip` **C** |
| OpenLLMetry [3] (Apache-2.0; n/a; 2026-11-16; 864f859) | arbitrary props **V** | native **V** | - | - | - | - | **V** (library) |
| AgentOps [4] (MIT; 0.4.21; 2026-06-25; f8e907b) | N found | SDK dep **V** | N found | injection detection **C** | N | N | hosted service default **C** |
| NeMo Guardrails [5] (Apache-2.0; 0.25.0-rc1; 2026-11-18; 7f9ea4d) | N | optional extra **V** | N | **V** (tool rails, hooks-server allow-list) | N | N | needs an LLM **C** |
| Guardrails AI [6] (Apache-2.0; 0.11.0; 2026-08-26; 06d0ff2) | N | N found | N | I/O validation **V**; tool calls N | N | N | partial **C** (hub token) |
| Invariant Guardrails [7] (Apache-2.0; 0.3.5; 2026-01-12; 2340fe2) | N | N found | N | **V** (rules, stateful over trace) | N | N | **V** (local analyzer) |
| LlamaFirewall [8] (MIT in subfolder; n/a; 2026-11-12; 0654501) | N | N found | N | **V** (BLOCK/HITL) | N | N | regex only; others need HF + Together key **V** |
| OPA [9] (Apache-2.0; n/a; 2026-11-18; 4f0a67c) | - (caller supplies input) | N found | decision logs **V** | **V** (allow/deny) | N | via data/bundles **C** | **V** |
| Cedar [10] (Apache-2.0; n/a; 2026-11-18; 4ff0bb0) | - (principal in request) | N | N | **V** (authz decision) | N | via entity data **C** | **V** |
| agentgateway [11] (Apache-2.0; n/a; 2026-11-18; e40abf5) | JWT claims / API key **V** (agent id mapping is our view) | export **V** | metrics/logs only; alert rules N | **V** (CEL on MCP tools) | N verified | JWT/API-key validation **V**; revoke at runtime N verified | binary, no LLM needed **C** |

Stars and release dates: **not found** (API blocked). "n/a" version means the repo has no single package version file we read.

## 4. Implications for our design

- **Monitor.** *Reuse* OTel as the wire format and `gen_ai.*`/OpenLLMetry attribute names; *build* our own detector over our recorder (tamper-evident log, RES-04) because no tool alerts on cross-agent write/read conflicts. *Optional reuse:* point OTLP at Langfuse or Phoenix purely as a demo viewer. *Avoid* making either a runtime dependency (multi-service stack; Phoenix ELv2).
- **Containment.** *Build* a small stdlib Python enforcement point (HTTP/MCP-style proxy or in-process wrapper) with a **kill registry**: `agent_id -> {active, quarantined, revoked_scopes}` checked on every action, fail-closed. This is the missing piece in every tool above. *Reuse the idea* of Invariant's stateful flow rules and NeMo's tool-call rails for what to block.
- **Policy format.** *Reuse* Cedar/OPA-style semantics (principal, action, resource; default deny; decision log with reasons). Implement a minimal evaluator in Python so it runs offline, and show a mapping to Cedar/OPA/agentgateway CEL as the production path. **[Our view]** This lands well with a Barclays/OTel/policy-as-code audience.
- **Identity/credentials.** *Reuse* JWT-style per-agent tokens (matches agentgateway's auth model) but *build* short-lived tokens plus a revocation list at our chokepoint; coordinate with RES-03.
- **Avoid:** LlamaFirewall as a core dependency (gated model, API key); Guardrails AI (no tool-call focus); Phoenix as a library; AgentOps (hosted-first, quiet since June, no verified agent id).
- **Stretch only if time permits:** run agentgateway with a CEL deny rule and show it as the real-world twin of our registry. Verify runtime reload and per-identity deny before claiming it.

**Reuse / build / avoid summary**

| Decision | Item |
|---|---|
| Reuse (standards/patterns) | OTel + `gen_ai.*` names, OpenLLMetry attributes, Cedar/OPA policy model and decision logs, Invariant-style flow rules |
| Reuse (optional viewer) | Langfuse or Phoenix via OTLP |
| Build | Kill registry + enforcement chokepoint, per-agent attribution enforcement, cross-agent detector, quarantine-to-rollback link |
| Avoid | LlamaFirewall (keys/gated model), Guardrails AI, AgentOps, any ELv2/`ee/` code in our core |

## 5. Implications for framing

- **[Our view]** "Observability tells you what happened, guardrails judge one call, nobody connects *which agent* to *contain and undo it*." Our evidence: the matrix has no tool with a V in "quarantine whole agent".
- **[Fact]** Existing open-source gateways (agentgateway) already do identity-aware tool authorization [11]; do not claim "nobody has a gateway". Claim the missing agent-level quarantine and provenance link instead.
- Juries "try to break" things (CHARTER): fail-closed behaviour and unspoofable agent ids are a stronger story than adding another classifier.

## 6. Open questions

- Does agentgateway enforce a deny-by-JWT-claim rule mid-session, and how fast does reload take? (Sprint 2 spike; also relevant to RES-03.)
- Stars/release dates for all repos could not be fetched (sandbox). Anaya or coordinator can add via a networked check.
- Invariant Gateway repo and NeMo/Guardrails AI offline behaviour were not tested (read-only constraint).
- Container/VM kill (process-level containment) is outside this survey: see RES-06.

## 7. Sources (all primary: source repos read at the stated HEAD on 19 Nov 2026)

1. Langfuse, https://github.com/langfuse/langfuse (LICENSE, `ee/LICENSE`, `worker/src/queues/monitorQueue.ts`, `packages/shared/src/domain/automations.ts`, `web/src/pages/api/public/otel/v1/traces`)
2. Arize Phoenix, https://github.com/Arize-ai/phoenix (LICENSE, README, `src/phoenix/server/api/types/Span.py`, `server/telemetry.py`)
3. OpenLLMetry (Traceloop), https://github.com/traceloop/openllmetry (`packages/`, `traceloop-sdk/.../tracing.py`)
4. AgentOps, https://github.com/AgentOps-AI/agentops (LICENSE, README, `pyproject.toml`)
5. NVIDIA NeMo Guardrails, https://github.com/NVIDIA/NeMo-Guardrails (`nemoguardrails/rails/llm/config.py`, `pyproject.toml`)
6. Guardrails AI, https://github.com/guardrails-ai/guardrails (`guardrails/types/on_fail.py`)
7. Invariant Guardrails, https://github.com/invariantlabs-ai/invariant (README, `invariant/analyzer/policy.py`, `monitor.py`); gateway: https://github.com/invariantlabs-ai/invariant-gateway (not read)
8. LlamaFirewall in Meta PurpleLlama, https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall (README, `llamafirewall_data_types.py`)
9. Open Policy Agent, https://github.com/open-policy-agent/opa (README, `docs/docs/management-decision-logs.md`)
10. Cedar, https://github.com/cedar-policy/cedar (README, crate layout)
11. agentgateway, https://github.com/agentgateway/agentgateway (README, `crates/agentgateway/src/mcp/rbac.rs`, `types/local.rs`, `state_manager.rs`, `Cargo.toml`)
