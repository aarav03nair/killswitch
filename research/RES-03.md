# RES-03: Per-agent identity and delegation on every action

Owner: rohan. Reviewer: anaya. Read on 19 Nov 2026. Versions are given per source.

## 1. TL;DR

- Workload identity (SPIFFE/WIMSE) answers "which agent process is this". It does **not** answer "which agent did this action". SPIFFE is workload-level by design [8]; SPIRE has no documented SVID revocation, only short TTLs (defaults 1h X.509, 5m JWT) and a node ban [1]. Per-action attribution needs a second layer: a signed action record.
- Attribution collapses at shared tools. MCP forbids token passthrough: a server calling an upstream API must use its own, separate token [2]. So the upstream service sees the MCP server, not the agent. The fix is to make the **tool gateway** the place where attribution is written, and to carry the agent id as a signed claim and in the audit record, not rely on the downstream credential.
- Recommended scheme: SPIFFE-style ID per agent, a short-lived delegation token with nested `act` chain (RFC 8693) [3], and an Ed25519 signature per action over a canonical action record (HTTP Message Signatures, RFC 9421, where the call is HTTP) [4]. Containment = revoke at the gateway (instant, our own deny-list) plus let the short TTL expire (bounded, minutes).
- Surprise: the current IETF agent drafts (klrc-03, txn-tokens-for-agents-05, pedigree-00) all agree on short-lived tokens and audit logging, but none of them defines fast revocation by itself. klrc points to Shared Signals; txn-tokens says nothing on revocation; pedigree-00 has cascading revocation but is expired and single-author [5][6][7].

## 2. Findings

1. **[Fact]** A SPIFFE ID is a URI `spiffe://trust-domain/path`, max about 2048 bytes; an SVID carries that ID with a signature in X.509, JWT or WIT form. The spec describes identity of a workload or caller and does not discuss per-request identity [8].
2. **[Fact]** SPIRE server defaults: `default_x509_svid_ttl` 1h, `default_jwt_svid_ttl` 5m. `spire-server agent ban` stops a banned node from re-attesting. The docs I read describe no SVID revocation mechanism and do not say what happens to already-issued SVIDs when an entry is deleted [1]. The SPIRE concepts and SVID pages also state no revocation behaviour [9][10] ("not found" there, not "absent").
3. **[Fact]** draft-klrc-aiagent-auth-03 (6 Jul 2026, expires 7 Jan 2027; authors from Defakto, AWS, Zscaler, Ping, OpenAI, Okta): each agent MUST have exactly one WIMSE identifier, which MAY be a SPIFFE ID; static API keys are called an antipattern; tools forwarding the agent's access token onward is called an anti-pattern; short-lived credentials reduce reliance on revocation, with Shared Signals (CAEP/RISC) for change notices; audit records MUST be tamper-evident and log agent id, delegated subject, resource, action, decision, timestamp and correlation id. It does not address shared services and does not use the term non-repudiation [5].
4. **[Fact]** RFC 8693 (Jan 2020): delegation keeps the actor's own identity (`act` claim); impersonation makes the actor "indistinguishable". Nested `act` claims form a history of prior actors, but prior actors are "informational only" and not for access control decisions [3]. `may_act` states who is authorized to act for a subject [3].
5. **[Fact]** draft-oauth-transaction-tokens-for-agents-05 (4 Apr 2026, expired 6 Oct 2026, single author, Amazon): adds `actor`, `principal` and optional `agentic_ctx` to Transaction Tokens; example lifetime 300 s; actor and principal must stay unchanged in replacement flows; SHOULD log actor and principal; revocation not addressed [6].
6. **[Fact]** draft-rampalli-pedigree-00 (25 Apr 2026, expired 27 Oct 2026, single author): per-agent EdDSA-signed JWT with parent chain, depth, scopes, Cedar mandate and consent chain; verifiers check scopes only narrow at each hop; agents sign completion records; revoking a parent cascades to descendants; designed to extend SPIFFE. Implementation listed is one Go project; comparisons to other drafts are the author's own claims, unverified [7].
7. **[Fact]** MCP authorization (draft spec page; the example in it uses protocol version 2026-07-28): OAuth 2.1 based, authorization optional, tokens MUST be audience-bound via RFC 8707 `resource`; servers MUST reject tokens not issued for them; "MCP servers MUST NOT accept or transit any other tokens"; authorization servers SHOULD issue short-lived tokens; HTTP clients identify via Client ID Metadata Documents, pre-registration or deprecated DCR; STDIO transport should use environment credentials instead of this flow [2][11].
8. **[Fact]** RFC 9421 (Feb 2024): signs selected HTTP components; parameters include `created`, `expires`, `nonce`, `keyid`, `tag`; `ed25519` is a registered algorithm; a valid signature alone does not prove the right party signed; replay is possible unless `nonce` is used; for non-repudiation applications may stipulate extra covered components [4]. Ed25519 signatures are deterministic (RFC 8032) [12].
9. **[Our view]** None of these specs binds an *action* to an agent in a way an auditor can verify independently. They bind a credential to a workload. An action record signed by a per-agent key (key held by the agent's runtime, not the LLM) is what gives non-repudiation, within the limit that a compromised runtime can sign anything until its key is revoked.
10. **[Our view, from MCP spec and klrc-03]** Where attribution collapses: (a) shared MCP server using one service credential toward upstream APIs (the upstream log shows only the service); (b) a tool or orchestrator that re-uses the caller's token (forbidden by MCP, called an anti-pattern by klrc, but still easy to do wrongly); (c) in-process agents sharing one OS user or DB role; (d) RFC 8693 chains where only the current actor is checked, so a bad upstream hop is invisible to the verifier; (e) STDIO MCP servers, which skip the OAuth flow [2].

## 3. Comparison table

| Approach | Granularity | Delegation chain | Non-repudiation | Revocation latency | Prototype effort |
|---|---|---|---|---|---|
| SPIFFE/SPIRE SVIDs [1][8] | Workload (process/pod). No per-request notion [8] | None native; federation only | None beyond signature; bearer JWT-SVID | Bounded by TTL (defaults 1h X.509 / 5m JWT) [1]; node ban stops re-attest [1] | High (running SPIRE); Low if we imitate with a local CA |
| OAuth RFC 8693 token exchange [3] | Token per exchange (can be per task) | Yes: `act` nesting, `may_act`; prior actors informational only [3] | Bearer token, not by itself | Token TTL plus AS-side revocation (our view) | Medium (needs an AS; mockable in stdlib) |
| MCP authorization [2][11] | Client/session to one MCP server (audience-bound) | None; passthrough forbidden, so chain breaks at the server [2] | None | Short-lived tokens SHOULD [11] | Medium; optional in spec |
| draft-klrc-aiagent-auth-03 [5] | Workload (one WIMSE id per agent) plus audit-event fields | Via OAuth delegation and token exchange [5] | Tamper-evident audit MUST; term not used [5] | Short TTL plus Shared Signals [5] | Low to adopt as a model, no reference code found |
| Txn-Tokens for Agents-05 [6] | Per transaction; `actor` + `principal` | Actor/principal fixed through call chain [6] | Signed token, not action | Not addressed [6]; 300 s example TTL | Low-Medium |
| Pedigree-00 (expired) [7] | Per agent, with completion records signed per outcome | Signed parent chain, scopes narrow per hop, cascade revoke [7] | Signed completion blocks [7] | Cascade revoke, latency not stated | Medium; one Go impl, unverified |
| RFC 9421 signed requests [4] | Per request/action | None; combine with the above | Strongest of the set, if asymmetric key per agent; limits in [4] | Key revocation is our job (deny-list) | Low (Ed25519 via `cryptography`) |

## 4. Implications for our design

**Identity**
- Build: agent ID as a SPIFFE-format URI, e.g. `spiffe://killswitch.demo/agent/<name>` (format per [8]); do not run SPIRE, issue it from a local CA in the prototype and say it maps to SPIRE/WIMSE in production (klrc-03 supports that mapping [5]).
- Build: one Ed25519 keypair per agent; the runtime wrapper signs, the LLM never sees the key. Reuse the `cryptography` library.
- Reuse the RFC 8693 shape: delegation token with `sub` (principal), `act` (agent), nested `act` for sub-agents, `may_act` for allowed delegations [3]. Avoid the pitfall in [3]: our gateway must verify the **whole** chain and record it, not only the top actor.

**Action signing (Recorder interface)**
- Every tool call produces a record: agent id, `act` chain, tool, canonical hash of arguments, read set and write set refs (RES-04), `created`, `nonce`, previous-record hash; signed Ed25519. Where the call is HTTP, use RFC 9421 field names (`keyid`, `created`, `nonce`, `tag`) so it stays standards-shaped [4]. Always use `nonce`, since [4] says replay is possible otherwise.
- [Our view] Sign at the gateway **and** at the agent: two signatures per action, so a forged log line needs both keys.

**Shared tools (where attribution collapses)**
- Make a **tool gateway** the only path to tools. It validates the agent token, mints a per-call downstream credential or request that carries the agent id (a header, a DB session variable, or a per-agent upstream token where the upstream supports it), and writes the signed record. This respects MCP no-passthrough [2] and klrc's anti-pattern warning [5].
- Where the upstream only accepts one service credential, attribution lives in our gateway log only. State that limit honestly in the abstract/jury demo rather than hide it.
- Per-agent DB roles or row-level `agent_id` stamping for the demo's shared store keeps attribution when agents share a backend.

**Containment (revocation)**
- Two layers: (1) gateway deny-list keyed by agent id and key id, checked on every call, so effect is immediate (our own latency to measure, not a sourced number); (2) short TTLs (we choose about 60 to 300 s, consistent with the 5m JWT default [1] and 300 s example [6]) so tokens die on their own. Cascade: revoking an agent also revokes sub-agents whose `act` chain contains it (idea from [7], which is an expired single-author draft, so label it as our design).
- Emit a Shared-Signals-style event (CAEP is named in [5]) on revoke so caches drop. Reuse concept only; no need to implement the protocol.

**Evaluation harness**
- Measure: time from revoke call to first denied call; count of post-revoke actions that succeed (target 0); % of actions with verifiable signature and complete chain.

**Avoid**
- Static API keys per agent [5]. Forwarding the agent's token to tools [2][5]. Relying on JWT bearer alone for non-repudiation [4].

## 5. Implications for framing (bullets only)

- "Workload identity is solved; action attribution is not": SPIFFE identifies a workload and not a request [8]; RFC 8693 says prior actors are informational only [3].
- The MCP spec itself guarantees the attribution gap at shared servers: no passthrough means the upstream cannot see the agent [2].
- Standards effort in 2026 is active (klrc-03 includes AWS, OpenAI, Okta authors [5]) but two of the three agent-specific drafts I read are expired single-author drafts [6][7]; the gap is real, and the field has no settled answer.

## 6. Open questions

- Does SPIRE revoke or just let SVIDs expire after entry deletion? Not found in the docs read; check JWT-SVID/X509-SVID specs and source. (Sprint 2 ADR.)
- CAEP/RISC details (event types, latency) were not read; only named in [5]. (RES-08 or ADR.)
- MCP spec: no agent-identity field; check whether the MCP auth extensions repo adds one. Not read. (RES-05.)
- Record schema and tamper-evident chaining: hand off to RES-04.
- Real latency of gateway revocation: to be measured in the prototype, not claimed here.

## 7. Sources

All read 19 Nov 2026 via fetch. "Primary" = spec/draft/official docs.

1. SPIRE Server reference (spiffe/spire, `doc/spire_server.md`). Primary. https://github.com/spiffe/spire/blob/main/doc/spire_server.md (page truncated at 100k chars when read)
2. MCP Authorization spec, draft, modelcontextprotocol.io. Primary. https://modelcontextprotocol.io/specification/draft/basic/authorization
3. RFC 8693, OAuth 2.0 Token Exchange, Jan 2020. Primary. https://www.rfc-editor.org/rfc/rfc8693
4. RFC 9421, HTTP Message Signatures, Feb 2024 (Backman, Richer, Sporny). Primary. https://www.rfc-editor.org/rfc/rfc9421 (sections 7.x read via partial fetch)
5. draft-klrc-aiagent-auth-03, AI Agent Authentication and Authorization, 6 Jul 2026, expires 7 Jan 2027. Primary (Internet-Draft). https://www.ietf.org/archive/id/draft-klrc-aiagent-auth-03.html
6. draft-oauth-transaction-tokens-for-agents-05, A. Raut, 4 Apr 2026, expired 6 Oct 2026. Primary (Internet-Draft). https://www.ietf.org/archive/id/draft-oauth-transaction-tokens-for-agents-05.html
7. draft-rampalli-pedigree-00, K. Rampalli, 25 Apr 2026, expired 27 Oct 2026. Primary (Internet-Draft). https://datatracker.ietf.org/doc/html/draft-rampalli-pedigree-00
8. SPIFFE ID standard (spiffe/spiffe). Primary. https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
9. SPIRE concepts, spiffe.io. Primary (docs). https://spiffe.io/docs/latest/spire-about/spire-concepts/
10. SPIFFE SVIDs deployment docs, spiffe.io. Primary (docs). https://spiffe.io/docs/latest/deploying/svids/
11. MCP Authorization Security Considerations, draft. Primary. https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations
12. RFC 8032, EdDSA, Jan 2017. Primary. https://www.rfc-editor.org/rfc/rfc8032
