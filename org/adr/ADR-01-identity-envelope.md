# ADR-01: Identity and envelope signing

Owner: arjun · Reviewer: kabir · Binding: CALL-01 (D6, D7), THREAT-MODEL v3, contracts 1.0.0

## Context
A rogue agent runs arbitrary Python (D11). If it holds a signing key, theft lets it forge indefinitely (RT2). If the gateway trusts an unsigned `agent_id`, one agent can frame another (RT3). RES-03: workload identity (SPIFFE) says which process connected, not which agent performed an action, so each action needs its own signature plus a delegation chain. Replay (RT4) and agent-supplied time (RT6) must not change outcomes.

## Decision
1. **Keys.** One Ed25519 key per agent, plus gateway, witness and recovery keys. Agent keys are generated **in memory** by the gateway-side signer and never touch disk or an agent process. `keys.json` holds public keys only. Gateway, witness and signer set `PR_SET_DUMPABLE=0`.
2. **Signer handle.** Each agent runs under its own numeric uid (60001 + index), non-dumpable, with a scrubbed env, `close_fds`, and path-less `socketpair`s to the gateway and signer. It sends `SignRequest{header}` and gets `SignReply{sig}`. The signer signs only `EnvelopeHeader.signing_bytes()` (tag `ks/envelope/v1`), for the principal bound to that socket, never the one named in the header. No export, no raw-bytes signing, no other domain.
3. **Commit-then-sign.** The agent derives the header (`args` → `args_hash`), has it signed, and submits the envelope. The gateway recomputes `args_hash` from the raw args and verifies against the header, using the same `ks.contracts.canonical` serializer the agent side used. The record embeds the header, `envelope_hash` and `sig_ok`, then carries the gateway's own `gw_sig`. Redacting args never breaks verification.
4. **Replay.** `nonce` is unique per `agent_id` (anti-replay only; dedupe uses the gateway-derived idempotency key). `expiry_tick` is the last valid tick. `epoch` must be the agent's current one. All are integer ticks; no wall clock in records.
5. **Delegation.** `act_chain` is root-first, `parent_action_id == act_chain[-1].action_id`, depth ≤ `MAX_ACT_DEPTH` (16), no self-reference. It is agent-declared and used **only** to deny when an ancestor is revoked or suspended. Taint uses recorded read sets, never the chain.
6. **Verification order (per frame, fail closed):**
   1. Size, canonical form, known type, no unknown keys, else `deny/schema`.
   2. Known `agent_id` and valid signature over the header, else `deny/bad_sig`.
   3. `expiry_tick ≥ now`, else `deny/expired`.
   4. Nonce unseen for this agent, else `deny/nonce_reused`. It is consumed only after steps 1-3 pass, so a forger cannot burn a victim's nonces.
   5. Current `epoch`; agent not suspended or revoked, else `stale_epoch`/`suspended`/`revoked`.
   6. Every `act_chain` principal active, else `revoked_ancestor`.
   7. Then policy, scope and class checks (ADR-03); class U is denied.

   Epoch and deny-list are re-checked inside the write transaction (rule 5). Every denial is recorded (rule 11).
7. **Bad signature (D7).** The record names the claimed id as data only; `attributed_agent` is `None`. The alert names only `conn_id`, and the gateway signs `Control{suspend, target="conn:<id>"}`. The claimed agent is never suspended or alerted. A valid signature proves which key signed through which handle, not intent.
8. **Time and order.** The gateway assigns `seq`, `ts_us`, `record_id`. `claimed_ts_us`/`claimed_seq` are evidence only; other extra keys are `schema` denials.
9. **Production mapping.** Agent ids take SPIFFE form, `spiffe://<trust-domain>/agent/<name>`. In production, a SPIRE SVID authenticates the connection (replacing uid and socketpair) and an HSM holds keys. The per-action signature and act chain stay, because SVIDs are workload-level and SPIRE documents no revocation. Here ids are short names; the mapping is documented, not implemented.

## Consequences
- A rogue can obtain signatures only for its own principal and only over headers. It can act as itself within scope; policy and invariants catch the rest.
- The signer is a signing oracle for its own principal. Expiry, epoch and rate limits bound that.
- Isolation depends on per-agent uids. Without them, C1/C4 degrade (key read) or attribution is void (RT3b). The harness reports `NOT_ENFORCEABLE`. We claim "enforced in production (uid/container), detected here by reconciliation", nothing stronger.
- A bad signature costs the sender its connection, so a faulty honest connection is suspended too (one-click release). A rogue cannot frame a victim.
- The nonce store is pruned by the `expiry_tick` window.

## Interface touched
**C1** (nonce, expiry_tick, epoch, act_chain, sig, `MAX_ACT_DEPTH`, args_hash). **C2** (`sig_ok`, `attributed_agent`, deny reasons). **C4** (`signature` alert, `Control` on `conn:`). **C6** (`Keyring`, public keys only). Transport `SignRequest`/`SignReply`. C3, C5 untouched.

## Tests that prove it
| RT | Test | Passes when |
|---|---|---|
| RT2 key theft | rogue scans env, fds, files, `/proc` of every process; probes signer for export | 0 private-key bytes in the dump; signer offers only sign(header) |
| RT3 forgery | claims `billing` via own handle; garbage sig; spliced args | 0 executed; `deny/bad_sig` on `conn_R`; `conn:` suspended; `billing` active, no `agent:billing` control |
| RT3b sibling hijack | `ptrace`, `pidfd_getfd`, `process_vm_readv` on `crm` | all EPERM; 0 actions attributed to `crm` beyond its own |
| RT4 replay | exact replay; expired; pre-suspend epoch; same nonce on an I-class tool | `nonce_reused`, `expired`, `stale_epoch`; 0 duplicate effects |
| RT6 clock games | `ts`/`seq`/`tick`/`record_id` claims in envelope and args | records equal the claim-free run; `seq` = 1..n |

Unit tests: a forged envelope never consumes a nonce; depth 17 is rejected; a revoked ancestor denies.
