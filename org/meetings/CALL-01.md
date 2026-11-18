# Call #1 — Research readout → decisions → Sprint 2 plan

**Date:** 19 Nov 2026 (IST) · **Chair:** Claude (PMO) · **Attendees:** Maya (Eng), Anaya (Research), Kabir (Security), Zoya (Pitch), The Panel (review) · **Product Owner:** Aarav (async; decisions marked ⚑ need his confirmation)
**Inputs:** research/SYNTHESIS.md, research/REVIEW-S1.md, org/reports/PANEL-ENG-00.md, CALL-01/{maya,zoya,kabir}.md

## 1. Readout (Anaya)
- Thesis **modified**. Confirmed: undo is a dependency problem, not a snapshot problem. Killed: "nobody has provenance-based containment" (Airlock) and "nobody has agent undo" (Wang 2608.10502, State Footprints as vision).
- A public multi-agent incident exists (METR on the OpenAI/HF evaluation, July 2026), but no public case of one agent consuming another's bad write and then being repaired.
- Our niche: the **backward half**. Revert one agent's landed shared-state writes and repair their readers. The record is **authenticated and witness-anchored** under a forging/tampering threat model. Recovery is **scored against an oracle**.

## 2. Discussion and resolutions

| # | Topic | Positions | Resolution |
|---|---|---|---|
| D1 ⚑ | Headline | Panel/Anaya: provenance-first. Zoya: lead with the *problem* (undo undefined once others read the bad write); provenance is the fix | **Both, layered.** The abstract opens on the dependency gap (problem-first is also the organisers' required order). Provenance is the fix's organising idea, selective undo is the payoff, "testimony vs evidence" is why it matters. Aarav confirms |
| D2 | Hook | Zoya: METR only as proof that a blunt stop (wipe/revoke) failed at scale | Adopted. Never present it as a B-on-A case, never say "we would have stopped it" |
| D3 | Name Airlock | All agree | One credited clause: forward containment, complementary |
| D4 | Recovery | Maya: we build no LLM re-planner | Re-execute deterministic steps (idempotency-keyed, through the outbox). LLM steps become a `replan` item queued for console approval. Conservative taint |
| D5 | Storage | Anaya: own SQLite. Maya: ADR earlier | Own row-versioned SQLite. Dolt appears only as the "production twin". ADR-05 first |
| D6 | Tamper evidence | Kabir: witness must be a separate process | Hash chain + agent sig + gateway sig. A separate witness process takes a signed (seq, head, tick) every tick. `verify` checks chain, signatures, witness heads, seq gaps and reconciliation. Claim: "tamper-evident up to the last witnessed head". No Merkle proofs |
| D7 | Auto vs human | Kabir: bad sig suspends the *connection*. Maya: also on reconciliation mismatch | Auto-suspend on hard evidence: scope breach, I-class invariant breach, reconciliation mismatch (class U). A **bad signature suspends the submitting connection, never the claimed agent** (anti-framing). A tamper alert freezes recovery and suspends nobody. Anomalies need one click. Revoke only after confirmation |
| D8 | Tainted readers | Maya: per action. Kabir: lineage from recorded read sets only | Hold **per action**: the gateway holds writes and outbox items whose *recorded* read set touches tainted versions. Agent-declared lineage is never trusted |
| D9 | LLM at finale | — | No. One LLM agent is a stretch goal, only if the hero path is green by 30 Nov |
| D10 | Hold window | — | One config value. The demo toggles 0 vs >0; at 0 the escaped payment is scored as residual damage |
| D11 | Jury break | Maya: add DB bypass. Kabir: arbitrary Python inside the rogue subprocess | `ks inject`, a rogue-agent template (arbitrary Python), a direct `state.db` bypass caught by reconciliation, a log-line edit and a full chain rewrite → `verify`. F5/F6 run **live**, F3 stays a pytest. Threat model published to the jury first |
| D12 | Hero scenario | Zoya: narrate banking-legibly | F2+: crm swaps a supplier IBAN; billing, payments and comms consume it; triage edits a crm row later (write-write conflict); inventory and docs stay independent. Price ×10 is in the data, not the story |
| D13 | Numbers in abstract | — | External numbers come only from the fact card. Ours are definitions + **targets** (R=0, C=0, post-alert tainted effects = 0), labelled targets until measured |

### Engineering resolutions
- **Determinism (Maya's top risk):** the gateway is the scheduler. A tick barrier collects one envelope (or no-op) per agent and executes in agent_id order. **Day-1 test:** the same seed run twice gives byte-identical records, and the faulty run equals S\* before t0.
- **Key isolation (Maya vs Kabir):** agents run as separate subprocesses holding only a socket and a signer handle; keys never enter the agent process. Use a separate uid if the runtime allows it; otherwise claim "enforced in production (uid/container), **detected** here by reconciliation".
- **Release semantics:** we hold, never cancel, so `release` = un-hold + restore epoch.
- **Early hold** is a general policy rule on `sensitive`-tagged fields, not IBAN-specific code.
- **Attribution of laundered writes (Kabir):** a laundered write carries the launderer's signature. Backward taint names **root candidates**; we claim nothing stronger.
- Kabir's 11 day-one interface rules are **binding** on all contracts (see CALL-01/kabir.md §4).

### Threat model (Kabir), adopted
In scope: buggy agent, rogue agent (arbitrary code in its process), colluding agents (we name root candidates; no prevention claim), insider log tamper without keys. Out of scope: gateway/witness host compromise, covert channels, semantic influence (we over-taint), preventing prompt injection.

## 3. Decisions logged
D-02…D-09 on the board (headline, recovery semantics, storage, tamper evidence, auto-vs-human, per-action lineage hold, determinism via tick barrier, honest-claims rules).

## 4. Sprint 2 — "Frame & Design" (opened by the leads after this call)
- **Pitch track (Zoya):** fact card, claim guardrails, how-it-works diagram, term lock, jury Q&A pointers, then two comment-only review rounds of Aarav's draft. Bundled as the **Abstract Kit** for Aarav.
- **Eng track (Maya):** contracts C1–C6 frozen first; ADR-00…07 (owners per maya.md §3); walking skeleton (agent → gateway stub → recorder → verify) with the determinism test.
- **Security track (Kabir):** threat-model doc + red-team catalogue as the Sprint 4 test spec; security review of contracts.

## 5. Dissent recorded
- Zoya: "provenance" alone is a mechanism, not a headline. Accommodated by the layered D1.
- Maya: full key isolation is unenforceable in this container. Accepted, with honest wording.
