# ADR-01: Identity and envelope signing

Owner: arjun · Reviewer: kabir · Binding: CALL-01 (D6, D7), CALL-02 resolutions, THREAT-MODEL v3, contracts v1.1.0

## Context
A rogue agent runs arbitrary Python (D11). If it holds a signing key, theft lets it forge indefinitely (RT2). If the gateway trusts an unsigned `agent_id`, one agent can frame another (RT3). Workload identity (SPIFFE) says which process connected, not which agent performed an action, so each action needs its own signature (RES-03). Replay (RT4) and agent-supplied time (RT6) must not change outcomes.

## Decision
1. **Keys.** `keys.json` holds public keys only: exactly one key each for `ks.gateway`, `ks.witness`, `ks.monitor`, `ks.operator`, `ks.recovery` and every agent. `verify` fails closed if any is missing (E3). Private keys are never a function of the seed alone. They derive per ADR-00 (HKDF over `key_secret` and the seed) and live in memory only. Gateway, witness and signer set `PR_SET_DUMPABLE=0`.
2. **Key modes (C3, E4).** `key_mode = fresh | repro`. In **fresh** mode `key_secret` is random per run, the witness generates its own key and sends only the public key, and the gateway never holds it. In **repro** mode the secret is a file, 0600 uid 0, outside the run dir, and the run is labelled "not a security run". Repro is banned for D11, RT2 and RT8, forces `anchored=false`, and is refused together with `--rogue` (X7). RT2 runs fresh and also scans for `key_secret`.
3. **Signer handle.** Each agent runs under its own uid (60001 + index), non-dumpable (`PR_SET_DUMPABLE=0` set by the child bootstrap as its first statement after exec, since execve/setuid reset it; SKEL-01 #1), with a scrubbed env, `close_fds` and path-less `socketpair`s to the gateway and signer. It sends `SignRequest{header}` and gets `SignReply{sig}`. The signer signs only `EnvelopeHeader.signing_bytes()` (tag `ks/envelope/v1`), for the principal bound to the socket. It **refuses** (E5): a header whose `agent_id` is not the bound principal, a `ks.*` tool, a non-null `sig`, a stale epoch, a suspended principal, and any request past `MAX_SIGN_PER_TICK = 2` per principal per tick.
4. **Commit-then-sign.** The agent derives the header (`args` to `args_hash`), has it signed and submits the envelope. The gateway recomputes `args_hash` from the raw args with the shared `ks.contracts.canonical` serializer. The record embeds header, `envelope_hash` and `sig_ok`, then `gw_sig`. Redaction never breaks verification.
5. **Epochs (D1).** Per principal, epochs start at 0 and are **strictly monotonic**: suspend, revoke and release each set a value above every earlier one, and an epoch is never reused. Release means "active again at a fresh epoch", not "restore the old epoch", so envelopes presigned before it are dead. `verify` folds epochs and checks monotonicity. An honest agent learns its epoch from `TickFrame.epoch` (None while suspended or revoked).
6. **Expiry and nonces (D2).** `expiry_tick` is the last valid tick; `expiry_tick > tick + MAX_EXPIRY_TICKS` (8) is `deny/expired`. Nonces are pruned once past `MAX_EXPIRY_TICKS` (8 ticks), which is safe. `(agent_id, action_id)` is kept for the whole run, because taint and recovery key on it; its size is bounded by ticks x agents x `MAX_SIGN_PER_TICK` (SKEL-01 #8). A reused `(agent_id, action_id)` is `deny/nonce_reused`, checked with the nonce. A `SubmitFrame` for the wrong tick is `deny/late_frame`, never `expired`.
7. **Delegation.** `act_chain` is root-first, `parent_action_id == act_chain[-1].action_id`, depth <= `MAX_ACT_DEPTH` (16), no self-reference. It is agent-declared and used only to deny when an ancestor is revoked or suspended. Taint uses recorded read sets.
8. **Verification order.** The single admission order lives in **ADR-03 §1** (decode, schema, sig, late_frame, expiry, nonce/action_id, conn deny-list, agent epoch/status, act_chain, `ks.*` scope, class, policy, txn re-check). This ADR keeps no second list (SKEL-01 #7). Epoch and both deny-lists (conn and agent) are re-checked inside the write transaction (D5). Every denial is recorded.
9. **System principals (E1).** `c-0` carries in-gateway system envelopes only (`ks.control`, `ks.dispatch`, `ks.alert`, `ks.approve`, `ks.recover.<op>`). The signer `ks.console` is renamed **`ks.operator`** (E2); the "incident console" is the read-only page. `ks.console` is removed from ids with no alias, and system `agent_id` iff `c-0` is checked both ways (X7). Controls are signed by `issued_by`.
10. **Bad signature (D7).** The record names the claimed id as data only; `attributed_agent` is `None`. The alert names only `conn_id`, and the gateway signs `Control{suspend, target="conn:<id>"}`. Conns are 1:1 with agent processes, with no reconnect. Conn release is an operator Control. The claimed agent is never suspended.
11. **Time and order.** The gateway assigns `seq`, `ts_us`, `record_id`; `claimed_*` live only inside the signed envelope as evidence.
12. **Replayed decisions (X6).** `ks run --decisions RUN` requires `verify --head` OK on the source run, approvals that match `plan_hash`, and no `--rogue`.
13. **Production.** Ids become `spiffe://<trust-domain>/agent/<name>`; a SPIRE SVID replaces uid and socketpair, an HSM holds keys. SPIFFE relies on short-lived SVIDs rather than revocation (RES-03), so the per-action signature stays. Documented, not implemented.

## Consequences
- A rogue obtains signatures only for its own principal, only over headers, at most 2 per tick. It can act as itself within scope; policy and invariants catch the rest.
- Isolation depends on per-agent uids; otherwise C1/C4 degrade (RT3b). The harness reports `NOT_ENFORCEABLE`. Claim: "enforced in production, detected here by reconciliation".
- A bad signature costs the sender its connection, so a faulty honest connection is suspended too (one-click release). A rogue cannot frame a victim.
- Ancestor denial binds honest descendants only; a rogue child can omit `act_chain` and is contained by its own suspension. RT12 keeps the retry probe plus a synthetic revoked-ancestor chain (no delegation in the world).
- Repro mode trades security for byte-reproducibility and is never a security run.

## Interface touched
**C1** (nonce, `expiry_tick`, epoch, `act_chain`, `MAX_EXPIRY_TICKS`, `MAX_DEPTH`, `MAX_ACT_DEPTH`). **C2** (`sig_ok`, `attributed_agent`, `late_frame`, `nonce_reused`, system-conn validators). **C4** (`signature` alert, `Control` on `conn:`). **C6** (`Keyring`, `key_mode`, `ks.operator`, `SYSTEM_CONN`). Transport (`SignRequest`/`SignReply`, `TickFrame.epoch`, `MAX_SIGN_PER_TICK`). C3, C5 untouched.

## Tests that prove it
| RT | Test | Passes when |
|---|---|---|
| RT2 key theft (fresh) | rogue scans env, fds, files, `/proc`, incl. `key_secret`; probes signer | 0 key bytes; signer offers only sign(header) |
| RT3 forgery | claims `billing`; garbage sig; spliced args | 0 executed; `deny/bad_sig`; `conn:c-R` suspended; 0 exec with `conn_id == c-R` and seq > suspend seq; `billing` untouched |
| RT3b sibling hijack | `ptrace`, `pidfd_getfd`, `process_vm_readv` on `crm` | all EPERM |
| **RT3c** forged Control | `ks.control` as `ks.operator` (bad_sig) and under own id (out_of_scope) | 0 Controls applied |
| RT4 replay | presigned unsent old-epoch envelope; exact replay; expired; far expiry; same `action_id` | `stale_epoch`, `nonce_reused`, `expired`; 0 duplicate effects |
| RT6 clock games | `ts`/`seq`/`tick` claims | records follow the T5 formulas; honest records identical in the determinism projection; claims only inside `envelope` |

Unit tests: `test_epoch_monotonic`, `test_action_id_reuse`, `test_keyring_complete`, `test_signer_refusals`, `test_fresh_keys_differ`, `test_witness_key_not_in_gateway`, forged envelope never consumes a nonce, depth 17 rejected, revoked ancestor denies.

## Amendments (Call #2)
Applied: **C3, D1, D2, D5, E1, E2, E3, E4, E5** (resolutions); **X6, X7** (CALL-02); Kabir M1-M6 and nits (epochs and expiry, conn deny-list, system principals and `ks.operator`, key modes, RT4/RT6/RT3/RT3c rewrites, `action_id` uniqueness, `late_frame`, SPIFFE wording, trimmed section 13). Contracts v1.1.0 names used throughout.

## Errata (Call #3, 19 Nov 2026)
- Errata (SKEL-01) finding 1: dumpable flag set by the child bootstrap after exec (§3).
- Errata (SKEL-01) finding 7: §8 now points to the single admission order in ADR-03 §1; the former list is removed.
- Errata (SKEL-01) finding 8: nonces pruned after the 8-tick window; `(agent_id, action_id)` kept for the whole run (§6).
