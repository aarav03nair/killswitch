# CALL-03 · maya: Sprint 3 build plan

**19 Nov 2026** · Maya (Eng Lead) · Inputs: SKEL-01 (12 ADR findings), CON-02 Kabir sign-off (open fix-before-S4), ADR-00..07 + ADR-06-metrics (frozen), THREAT-MODEL v4, tests/redteam/SPEC v2, CALL-01/zoya §4, CALL-02/vikram §7.
**Rule:** contracts win over ADR text. Where they disagree, the ADR gets an erratum block. A meaning change goes to contracts 1.2. Nothing below changes a CALL-02 resolution.

## 1. The 12 SKEL-01 findings

| # | Finding | Decision | Kind | Issue |
|---|---|---|---|---|
| 1 | `PR_SET_DUMPABLE=0` set before exec is undone by execve/setuid | The child bootstrap sets it as its first statement after exec. Gateway and witness set it at start. Tested by a cross-uid ptrace EPERM check | ADR-00/01 erratum | B3-02, B3-10 |
| 2 | Gateway↔witness messages are ad hoc (`witness/protocol.py`) | `WitnessInit/Pub/Files/Ready/Head/Close` become transport types | contracts 1.2 | B3-01, B3-08 |
| 3 | A signer refusal gets no reply, so the agent waits out the deadline | New `SignRefusal{reason}` frame (closed vocabulary = `signer_refusal` + `schema`). A refusal is not a record (there is no envelope); the console counts refusals | contracts 1.2 | B3-01 |
| 4 | Degraded isolation is printed but `verify` cannot see it | `RunConfig.isolation ∈ {per_agent_uid, degraded}`, fixed before spawn and covered by `config_hash`. The runtime aborts if the /proc readback contradicts it. `VerifyReport.isolation` is echoed, and when degraded verify prints "per-agent attribution VOID" | contracts 1.2 | B3-01, B3-10, B3-15 |
| 5 | ADR says the witness creates `witness.jsonl`; the skeleton's gateway creates it | The gateway creates it in `RunDir.create`, fchowns it to the witness uid with mode 0600, and hands over O_APPEND + heads-dir fds by SCM_RIGHTS, then closes its copies. The witness never opens a run-dir path. Owner = witness uid (Kabir) | ADR-02 erratum | B3-02, B3-08 |
| 6 | In repro mode the gateway derives and sends the witness key | Document it: repro = the gateway holds every key, including the witness's, which is *why* repro is never anchored. No code | ADR-02 §3 + THREAT-MODEL repro row | B3-02 |
| 7 | ADR-01 §8, ADR-03 §1 and the stub order admission differently (late_frame, conn deny-list, out_of_scope) | One order, owned by ADR-03 §1: decode → schema → sig → late_frame → expiry → nonce/action_id → conn deny-list → agent epoch/status → act_chain → `ks.*` scope → class → policy → txn re-check. ADR-01 §8 points to it | ADR-01/03 erratum | B3-02, B3-11 |
| 8 | Nonce window (8) vs `(agent, action_id)` uniqueness | Nonces are pruned past `MAX_EXPIRY_TICKS`. `(agent_id, action_id)` is kept for the whole run, because taint and recovery key on it. Size ≤ ticks × agents × `MAX_SIGN_PER_TICK` | ADR-01 §6 erratum | B3-02, B3-11 |
| 9 | `no_state`: ADR-02 says ok=true, contract maps it to RECONCILE | Contract wins. If there is no state file and `fold(record)` has no state writes, reconcile is trivially OK. If the record has writes but the state file is missing: RECONCILE `no_state` | ADR-02 erratum | B3-02, B3-15 |
| 10 | Tail truncation: ADR-02 test expects `head_mismatch`, contract gives `truncated` | Contract wins. Anchor `count` > last line's count → `truncated`, first_bad n+1. Same count, different tuple → `head_mismatch`, first_bad min(anchor.seq, n)+1. SPEC RT7(d) already accepts both | ADR-02 erratum | B3-02 |
| 11 | "One checkpoint per tick" + "final checkpoint" vs "ticks strictly increase" | At most one checkpoint per tick. A stalled tick has none (`timing.jsonl` witness_ack=false plus a `witness_stall` alert). The final checkpoint is the last tick's checkpoint. Teardown writes no records. The witness is idempotent per tick: a repeated push returns the existing line | ADR-00 T5 / ADR-02 §3 erratum | B3-02, B3-08 |
| 12 | `run_id` is in config.json, so a free-form id breaks byte-identity | Default `<scenario>-s<seed>` (deterministic). `--run-id` is allowed, but byte-identity only holds between runs with the same id. The operator socket dir `/run/ks/<run_id>` refuses to start if it already exists | code-only (ADR-00 note) | B3-10 |

Also code-only: there is no readiness handshake, so the tick-0 grace (`STARTUP_GRACE_S`) stays.

## 2. Contracts 1.2 (small, owner maya, reviewer kabir, D1)

The 1.2 bump is additive only. Nothing is renamed or removed, and golden hashes are re-pinned with changelog lines:
1. Witness link frames (finding 2).
2. `SignRefusal` frame (finding 3).
3. `RunConfig.isolation` + `VerifyReport.isolation` (finding 4).
4. `RunConfig.decisions_from: Hash | None`, the anchored source run for `--decisions`. Refused with `fault="rogue"` and with repro keys (R3).
5. Verify reason `reexec_invalid` → TAMPER (F9).

Everything else on Kabir's list is validator, gateway or verify code and needs no contract change.

## 3. Build order to the hero path (F2+ end to end)

```
contracts 1.2 (01) ─┬─ witness (08) ─ recorder txn (09) ─┐
                    └─ runtime/isolation (10) ─ CLI (12) │
STATE store (03) ═> READ RULE/digest (04) ═╦═> adapters (06) ─ F7 (16)
   └─ world agents + view (05) ────────────╫─> inject F2+ (17) ─ oracle (22) ─ score (26)
gateway pipeline (11) ─ c-0/operator (13) ─╫─ policy+R2 (14) ─ containment (19) ─ outbox/holds/dispatch (23)
monitor detectors (07, fixtures) ──────────╫──────────────────────────────────────────┐
                                  TAINT (18) ═> PLANNER (21) ═> RE-RUN SIM (24) ═> HERO E2E (27)
                                                               ═> APPLY (30) ═> BENCH (33) ═> RT wiring (35) / console (34) ═> FREEZE
```

**Critical path (═>):** B3-03 state → B3-04 read rule → B3-18 taint → B3-21 planner → B3-24 re-run simulation (also needs adapters 06 + view 05) → **B3-27 hero e2e** → B3-30 apply → B3-33 bench → B3-35 red-team wiring → freeze. Vikram's 9.5 days do not fit in 8. Three changes make them fit. Helpers (0.5) already landed in CON-02. Apply (1.5) moves to maya as runtime/c-0 work. Tests (1.5) are folded into each issue's acceptance criteria. Vikram keeps six issue-days, D1–D6. The rest of the graph has ≥1 day of float, except gateway → containment → outbox (nisha), which also lands on D5.

## 4. Day plan

D1 = Fri 20 Nov. We start five days ahead of the 25 Nov window. Abstract day (22 Nov) is Aarav's; eng does not touch abstract text.

| Day | Date | Lands | Milestone |
|---|---|---|---|
| D1 | 20 Nov | 01 contracts 1.2, 02 errata, 03 state store, 05 world agents, 07 detectors (fixtures), 08 witness | contracts 1.2 signed by Kabir EOD |
| D2 | 21 Nov | 04 read rule, 06 adapters, 09 recorder txn, 10 runtime, 11 gateway pipeline, 12 CLI | 10 agents tick through the real gateway with state |
| D3 | 22 Nov | 13 c-0/operator, 14 policy+R2, 15 verify, 16 F7, 17 inject, 18 taint | F2+ injects, detector fires, alert chained |
| D4 | 23 Nov | 19 containment, 20 R3, 21 planner, 22 oracle | beats 1–3 (break, identify, contain) green |
| D5 | 24 Nov | 23 outbox/holds, 24 re-run sim, 25 F9, 26 score, 27 hero e2e, 28 console live | **HERO PATH GREEN**: F2+ beats 1–4 (dry-run incl. re-run), scored, verify OK |
| D6 | 25 Nov | 29 conflict/replan, 30 apply, 31 verify F4/F6, 32 F8, 33 bench | applied recovery scored; bench runs 3 seeds |
| D7 | 26 Nov | 34 console recover/audit, 35 red-team wiring | **CODE FREEZE 18:00 IST**: features stop; only fixes with an issue id |
| D8 | 27 Nov | buffer, slip absorption, S4 hand-off | S4 (28 Nov–2 Dec): ≥20-seed bench, RT1–RT13, Panel dry-run, 5-beat demo |

**Slip rule.** If B3-24 is not green by D5 18:00, maya pairs on it on D6 and B3-29 (F2+x) drops to S4. The hero is F2+, so F2+x is a Q&A backup only. Kabir reviews are batched twice a day (13:00, 19:00).

## 5. Fix-before-S4 → issues

F9 → B3-25 (verify) + B3-19 (gateway refuses a second unhold re-exec). R2 → B3-14 (+ B3-04 store side). R3 → B3-20 (+ field in B3-01). R5 → B3-13. F4 → B3-23 (dispatch record) + B3-31 (window check). F6 → B3-07 (`ks.alert` envelopes) + B3-31 (cross-check, FROZEN from records). F7 → B3-16. F8 → B3-32. witness.jsonl owner → B3-08. Kabir's weak `test_epoch_monotonic` line → B3-19.

## 6. Issues

35 issues, B3-01..B3-35, each ≤1 day with 2–4 testable criteria: maya 7, arjun 6, nisha 6, vikram 6, tara 7, ishaan 3. Models: vikram and maya opus, the others sonnet. Reviewers: kabir for security-relevant work, maya for the rest, anaya for oracle/score. `python3 -m pytest -q` stays green on every merge.
