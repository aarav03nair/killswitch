# RES-04: Action record schema, OpenTelemetry GenAI conventions, tamper-evident log

Owner: rohan. Reviewer: anaya. Read on 19 Nov 2026. Tags: **[Fact]** = stated in a source, **[Our view]** = our inference.

## 1. TL;DR

- OTel GenAI spans record *what an agent called* (agent, tool, model, conversation) but have **no attribute for state read or written**. The read/write-set fields our selective rollback needs are a gap in OTel, so we must add them as custom attributes. (H4a confirmed.)
- Every `gen_ai.*` convention is still **Development**, none Stable, and the spec moved to a new repo in June 2026 with no tagged release found. Use OTel attribute names but keep our own schema versioned; do not depend on stability.
- Recommended tamper-evidence: **per-agent hash chain inside one RFC 9162-style Merkle log with signed checkpoints**, with the checkpoint published outside the agents' reach. A bare hash chain is not enough against a writer who can rewrite the whole file.
- Prototype effort is small: a hash chain is about 30 lines and a Merkle tree with inclusion and consistency proofs is a few hundred lines of Python stdlib + `cryptography` (Ed25519). Running Rekor/Trillian is not worth it in a one-week prototype. [Our view]
- H4b (plain logs are not audit evidence): supported by the logging literature, but the Replit "misreporting" claim is not verified here (RES-07 owns it).

## 2. Findings

1. **OTel GenAI status and location.** [Fact] The GenAI conventions page on opentelemetry.io now says they "have moved to the OpenTelemetry GenAI semantic conventions repository" and is no longer maintained there; the docs sidebar shows semantic conventions 1.45.0 [1][2]. The new repo `open-telemetry/semantic-conventions-genai` is Apache-2.0, 504 stars, 689 commits on `main`, **no releases listed**, and its stability section says only "TODO" [3]. The attribute registry marks the old attributes deprecated (moved) and well-known values as **development** [2]. A secondary source says the move happened 12 Jun 2026 with v1.42.0 and that no `gen_ai.*` item is Stable [4] (secondary, not verified against primary release notes). I could not fetch the new repo's `docs/` (robots/client error), so agent and tool span details below come from an older mirrored commit of the main repo [5], which is **Development**; verify against the new repo before Sprint 2.
2. **Agent spans.** [Fact] `create_agent` and `invoke_agent` exist; span name is `invoke_agent {gen_ai.agent.name}`; kind CLIENT; Required: `gen_ai.operation.name`, `gen_ai.provider.name`; conditionally required: `gen_ai.agent.id`, `gen_ai.agent.name`, `gen_ai.conversation.id`, `error.type` [5]. A secondary source reports v1.41.0 split `invoke_agent` into client and internal spans and added `invoke_workflow` [4].
3. **Tool spans.** [Fact] `execute_tool` is a well-known `gen_ai.operation.name` value (Development) [5]; the registry defines `gen_ai.tool.name`, `.type`, `.call.id`, `.call.arguments`, `.call.result` (arguments and result "may be sensitive"), plus `gen_ai.agent.id/.name/.description/.version` and `gen_ai.conversation.id` [2]. I did not retrieve the Execute Tool span page, so its requirement levels are **not verified**.
4. **What OTel does not carry.** [Fact] No attribute in the registry [2] names a resource written, a resource read, a state version, an effect class, a delegating principal, or a causal parent other than the span tree. [Our view] That is exactly the gap for selective undo: the span tree gives call order, not data dependency.
5. **Hash chains.** [Fact] Schneier and Kelsey's secure audit log (ACM TISSEC 1999) targets logs on an untrusted machine: entries made before compromise cannot be altered or destroyed without detection [6]. [Our view] A chain proves ordering and detects edits to the middle, but whoever controls the whole store can recompute the chain from the edit point, so it needs an externally held head or signature.
6. **History trees.** [Fact] Crosby and Wallach (Rice, USENIX Security 2009) treat the logger as untrusted, aim at tamper *detection* not prevention, and need at least one incorruptible auditor. Their Merkle-style history tree gives membership proofs and incremental proofs; they report 3100 bytes for a random-event proof in an 80-million-event log where a hash chain would need an "800 MB trace", and 1,750 events/s insert-and-sign with DSA on one core, 10,500 events/s with signing offloaded [7]. [Our view] These are 2009 prototype numbers; treat as order of magnitude.
7. **RFC 9162 (CT v2.0).** [Fact] Published Dec 2021, status **Experimental**, obsoletes RFC 6962. A log is "a single, append-only Merkle Tree"; leaf hashes use prefix 0x00 and node hashes 0x01; the signed tree head carries `tree_size`, `root_hash`, `timestamp` and a signature; consistency proofs are bounded by ceil(log2(n)) + 1 nodes; monitors fetch new entries and anyone holding a receipt can request an inclusion proof, and failure to provide one indicates misbehaviour [8].
8. **Sigstore Rekor.** [Fact] Rekor is a transparency log for signed supply-chain metadata, built on a verifiable data structure, where auditors can check it is append-only; the CLI can fetch inclusion proofs and a monitor audits the log [9]. Rekor v2 (`rekor-tiles`) moves to a tile-backed log, Apache-2.0, with GCP/AWS/POSIX storage backends; no formal GA label was stated [10]. [Our view] Running either needs a server and a signing identity; too heavy for the prototype, but we should emit the same proof formats so Rekor-style verifiers could be swapped in.

## 3. Draft action-record field list

One record per agent action (tool call, file/DB write, message send, delegation). Fields marked gap are not in OTel; we add them under a `ks.*` prefix. [Our view]

| # | Field | OTel attribute | Why TTI / TTC / recovery needs it |
|---|---|---|---|
| 1 | `record_id`, `seq` (per log) | gap | Stable reference for causal edges and proofs (recovery) |
| 2 | `ts` (UTC, ns) | span start time | Ordering, TTI timeline |
| 3 | `trace_id`, `span_id`, `parent_span_id` | OTel trace context | Join to existing traces and dashboards (TTI) |
| 4 | `agent_id` | `gen_ai.agent.id` | Per-agent attribution; unit of containment (TTI, TTC) |
| 5 | `agent_version` | `gen_ai.agent.version` (registry [2]) | Which prompt/model build misbehaved (TTI) |
| 6 | `principal` and `delegation_chain` | gap | Who authorised it; revoke at the right level (TTC) |
| 7 | `conversation_id` / `task_id` | `gen_ai.conversation.id` | Groups one agent's task for bulk undo (recovery) |
| 8 | `operation` | `gen_ai.operation.name` (`execute_tool`, `invoke_agent`) | Filter action types (monitor) |
| 9 | `tool_name`, `tool_call_id`, `tool_type` | `gen_ai.tool.name`, `.call.id`, `.type` | What was called (TTI) |
| 10 | `args_hash` (+ args in a separate redactable store) | `gen_ai.tool.call.arguments` (may be sensitive [2]) | Proves what was asked without putting PII in the immutable log |
| 11 | `result_hash` | `gen_ai.tool.call.result` | Detect misreporting: compare claimed vs actual result |
| 12 | `effect_class` (reversible / compensable / irreversible) | gap | Gate irreversible actions before they run (TTC, recovery) |
| 13 | `write_set` (resource id, version/hash before and after) | gap | Exactly what to revert (recovery) |
| 14 | `read_set` (resource id, version read) | gap | Finds downstream agents who consumed bad output (recovery, collateral) |
| 15 | `caused_by` (record_ids) | gap (span links partly) | Dependency edges for selective undo (recovery) |
| 16 | `policy_decision` (allow/deny, rule id) | gap | Shows containment actually applied (TTC, audit) |
| 17 | `outcome`, `error_type` | `error.type` | Failure signal for monitor (TTI) |
| 18 | `compensation_ref` | gap | Handle to the undo action (recovery) |
| 19 | `prev_hash`, `entry_hash`, `agent_chain_seq` | gap | Per-agent chain (tamper evidence) |

Records should be written by the **gateway or tool wrapper**, not by the agent itself, so an agent cannot omit or misreport its own writes. [Our view]

## 4. Tamper-evidence comparison

| Option | Guarantee | Verification cost | Prototype effort |
|---|---|---|---|
| Hash chain (each entry hashes the previous) [6] | Detects edits, deletions, reordering in the middle if the head is held elsewhere; does not detect truncation or full rewrite by the log holder without that anchor | O(n) to verify a whole range; proving one entry needs the chain from it to the head (Crosby and Wallach contrast this with 3 KB vs 800 MB [7]) | Lowest: about 30 lines, `hashlib` |
| Merkle log with signed tree head [7][8] | Append-only via consistency proofs; membership via inclusion proofs; split-view detectable if heads are compared | Inclusion O(log n); consistency bounded by ceil(log2 n)+1 nodes [8] | Medium: a few hundred lines; `cryptography` for Ed25519 |
| Public transparency log (Rekor / Trillian / Tessera) [9][10] | As Merkle log plus independent operator and monitors | Same proofs; needs network, service, identity | Highest: server deployment; unnecessary offline |

[Our view] Choose the middle row, with a per-agent chain field inside each leaf. Publish the signed head to a second location the agents cannot write (a file owned by another user, a separate process, or a git-pushed checkpoint) to supply Crosby and Wallach's "incorruptible auditor".

## 5. Implications for our design

**Recorder**
- Build: append-only Merkle log, leaf = canonical JSON of the record (sorted keys, fixed encoding) hashed with 0x00/0x01 prefixes as in RFC 9162 [8]; Ed25519-signed checkpoint every N records or T seconds.
- Build: per-agent `prev_hash` chain so one agent's history can be verified or quarantined independently.
- Reuse: OTel attribute names for fields 3-5, 7-11, 17 so records export to any OTel backend; add `ks.*` for the gaps. Pin the spec commit we used, since it is Development.
- Avoid: raw arguments and results in the immutable log; store hashes and keep the content in a redactable side store. [Our view, driven by the "may be sensitive" notes in [2]]
- Build a `verify` CLI that checks chain, inclusion, consistency and prints the first bad index; this is the "agent can be audited, not only demoed" artefact for jurors who try to break it.

**Monitor**
- Consume the record stream; rules over `effect_class`, `write_set` size, deny rate, and rate per `agent_id`. The read/write sets let the monitor compute blast radius (agents that read what a suspect agent wrote) at detection time, which shortens TTI.
- Alarm on log integrity itself: checkpoint not advancing, consistency proof failing, sequence gaps.
- Compare claimed `result_hash` against gateway-observed result to catch misreporting.

## 6. Implications for framing (bullets only)

- The agent-observability standard is still Development and has no state-change fields [1][2][3].
- Hash chain vs Merkle: 800 MB vs about 3 KB proof for one event in an 80M-event log (Crosby and Wallach, 2009 prototype) [7].
- Auditability argument: logger is untrusted; detection not prevention; one external auditor [7].

## 7. Open questions

- Execute Tool span requirement levels and current `gen_ai.agent.version` status: read the new repo's `docs/` (RES-05/Sprint 2).
- Replit agent "misreporting" claim: owned by RES-07.
- Regulatory retention and tamper-evidence wording (EU AI Act Art. 12): RES-08.
- Canonical serialisation choice (JSON Canonicalization, RFC 8785 vs fixed-order encoding): decide in the Recorder ADR; not researched here.

## 8. Sources

1. OpenTelemetry, "Generative AI (moved notice)", https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/ and `.../gen-ai-agent-spans/` (read 19 Nov 2026). Primary.
2. OpenTelemetry, "GenAI attribute registry" (deprecated-moved listing), https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/ (19 Nov 2026). Primary.
3. `open-telemetry/semantic-conventions-genai` README and repo page, https://github.com/open-telemetry/semantic-conventions-genai (19 Nov 2026). Primary.
4. Azena AI, "OpenTelemetry's GenAI semantic conventions are not stable yet" (Jul 2026), https://dev.to/azena-ai/opentelemetrys-genai-semantic-conventions-are-not-stable-yet-heres-what-actually-shipped-in-2026-3mke. Secondary.
5. OpenTelemetry semantic-conventions `docs/gen-ai/gen-ai-agent-spans.md` at commit 15be6b32 (mirror, date not shown), https://gitea.cncfstack.com/open-telemetry/semantic-conventions/src/commit/15be6b3216997a798de45cf8df2486e060dab36f/docs/gen-ai/gen-ai-agent-spans.md. Primary content via third-party mirror; older than current.
6. Schneier and Kelsey, "Secure Audit Logs to Support Computer Forensics", ACM TISSEC 1(3), 1999, https://www.schneier.com/academic/archives/1999/05/secure_audit_logs_to.html. Primary (abstract only read).
7. Crosby and Wallach, "Efficient Data Structures for Tamper-Evident Logging", USENIX Security 2009, https://www.usenix.org/legacy/event/sec09/tech/full_papers/crosby.pdf. Primary (year per venue URL; text lacked date).
8. Laurie, Messeri, Stradling, RFC 9162 "Certificate Transparency Version 2.0", Dec 2021 (Experimental), https://www.rfc-editor.org/rfc/rfc9162.html. Primary (first 100k of 139k characters read).
9. Sigstore, "Rekor / Logging overview", https://docs.sigstore.dev/logging/overview/. Primary (docs).
10. Sigstore `rekor-tiles` (Rekor v2), https://github.com/sigstore/rekor-tiles. Primary (README).
