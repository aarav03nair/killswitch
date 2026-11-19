# THREAT-MODEL: Project Kill Switch, for the jury

Owner: kabir · SEC-01 v4 · Binding source: org/meetings/CALL-01.md and CALL-02.md · Read before the D11 live attacks.

**System:** agents are separate subprocesses that reach shared state only through the **gateway**, which owns workspace, record and keys. A separate **witness** process signs `(seq, head, tick, count)` every tick. `verify` checks chain, signatures, witness heads, seq gaps and reconciliation (state = fold(record)). **Anchored** verification, `ks verify RUN --head ANCHOR`, also checks the **run anchor** `{seq, head, tick, count, keyring_hash, config_hash}` that the console prints at run end, off the file system.

**Live setup (fixed day 1).** The container runs as uid 0. Gateway: uid 0; witness: its own uid; **each agent: its own numeric uid** (60001 + index); the child bootstrap sets `PR_SET_DUMPABLE=0` as its first statement after exec (execve and setuid reset it; the gateway and witness set it at start), before any agent code runs (SKEL-01 #1). Cross-uid `ptrace`/`pidfd_getfd` → EPERM (checked 19 Nov). Keys are random per run (**fresh** mode), held in memory, never on disk; the witness makes its own key and the gateway never holds it. Each agent gets a path-less `socketpair`, a clean env and `close_fds`. The operator channel is a socket in a root-only (0700, uid 0) directory, and the gateway accepts it only if `SO_PEERCRED` uid is 0. **Repro mode** (deterministic keys from a secret file; the gateway holds every key, including the witness's, which is why repro is never anchored, SKEL-01 #6) is **not a security run**: it is labelled so, forces `anchored=false`, is refused with `--rogue`, and is banned for D11, RT2 and RT8. **If the gateway uid cannot be separated, C1 and C4 degrade** (a key read by the rogue is the admitted gap, RT2). **If per-agent uids fail, per-agent attribution is void for that run** (RT3b).

## 1. Assets

| Asset | What it is | Why an attacker wants it |
|---|---|---|
| Workspace state | `state.db`, row-versioned SQLite. Sensitive fields (e.g. a supplier IBAN) are **their own versioned objects** `table:pk.field`, so taint, holds and restores act on the field, not the whole row | Corrupt data other agents read |
| Outbox | Held irreversible effects (payments, email) | Get a tainted effect out first |
| Record + witness heads | Hash-chained, signed records; heads kept by the witness in its own 0700 dir and echoed in the run anchor | Erase or rewrite who did what |
| Keys | **agent** keys, **gateway**, **witness**, and the system principals **`ks.monitor`** (alerts, auto-suspends), **`ks.operator`** (Controls incl. revoke, approvals) and **`ks.recovery`** (approved plan steps) | Forge actions, records, Controls or a repair |
| Containment state | Deny-list (agent and connection), credential epochs (strictly monotonic) | Escape suspension, or suspend an honest agent |
| Side store | Values (e.g. IBANs); the record holds hashes (rule 9). Tested by the F3 pytest | Read customer data via the evidence |

## 2. Trust boundaries

| # | Boundary | Trust |
|---|---|---|
| B1 | agent → gateway IPC | **Untrusted.** All input checked; agent-declared lineage, `ts`, `seq` never trusted. `c-0` is **reserved for in-gateway system envelopes**: a system agent_id on any other connection is `bad_sig` unverified, and an agent-signed `ks.*` tool is `out_of_scope` |
| B2 | gateway → workspace | **TCB.** The gateway is the reference monitor |
| B3 | gateway → witness | Separate process, uid, own key and head store |
| B4 | record file ↔ operator | **Editable.** We detect, not prevent |
| B5 | operator socket → gateway | Root-only dir plus `SO_PEERCRED` uid 0; the only path for `ks contain` and `ks recover --apply` |

The person using `ks.operator` (approves recovery plans, revokes) is **trusted**. "Incident console" is the read-only page; it cannot revoke.

## 3. Adversaries

**In scope:** **Buggy agent** (F1/F2/F4/F7: wrong but well-formed, in-scope writes; hero: crm swaps a supplier IBAN) · **Rogue agent** (arbitrary code in its own process; **the jury may run arbitrary Python inside it**, D11) · **Colluding agents** (laundering via tickets, splitting under thresholds; we name **root candidates**, no prevention claim) · **Insider record tamper** (edits record files; no witness key; cannot alter the anchor printed at run end).

**Out of scope**, with the production mitigation: gateway/witness host or root compromise (keys in an **HSM**, record on **WORM**) · one insider holding both gateway and witness keys (split custody, **WORM** witness store) · shared uid (separate **container** per agent) · exhaustion beyond per-agent rlimits (container limits) · covert channels between agents (no claim) · semantic influence (taint tracks data exposure, not meaning; we **over-taint**) · preventing prompt injection (we contain and recover its effects).

## 4. Claims we make and claims we refuse

Wording is CALL-01's and CALL-02's. Say nothing stronger.

| # | We claim | We refuse |
|---|---|---|
| C1 | The record is **"tamper-evident up to the last witnessed head"** (D6); keyring-swap and truncation guarantees need **anchored** `ks verify --head` | "Tamper-proof". Records after the last witnessed head; a stalled head raises an alert. Unanchored verify is "consistent, not anchored". No Merkle proofs |
| C2 | Key isolation: **"enforced in production (uid/container), detected here by reconciliation"** | "Keys are unreachable in this container". RT2 measures what is reachable here (fresh keys) |
| C3 | Colluding agents: backward taint names **root candidates**; **no prevention claim** | Preventing collusion. Naming the true originator of a laundered write |
| C4 | A **bad signature suspends the submitting connection, never the claimed agent** (D7, anti-framing) | That a valid signature proves intent: it proves which key signed through which handle |
| C5 | The gateway holds writes and outbox items whose **recorded** read set touches tainted versions (D8) | Lineage the agent declares. Effects released before the alert: at hold window 0 they are scored as residual damage (D10) |
| C6 | Containment **holds, never cancels**. **Release restores the agent's permissions (fresh epoch)**; it lifts only suspension holds, and lineage and sensitive holds survive. Recovery appends compensating records; a held outbox item is cancelled only by an approved plan step after the dry-run diff | Undoing released external effects. Any comparison with Airlock: it is forward containment, complementary (D3) |

## 5. Adversary → attack → control

Controls: **D6** chain + signatures + witness + `verify --head`; **D7** auto-suspend on hard evidence only (scope breach, I-class invariant breach); a reconciliation mismatch names nobody and suspends nobody; bad sig suspends the connection; tamper alert freezes recovery, suspends nobody; revoke only by `ks.operator`; **D8** per-action hold from recorded read sets. Rules 1-11 are in §6.

| Adversary | RT# | Attack | Control | Pass target |
|---|---|---|---|---|
| Buggy | RT10 | Honest consumer pays the bad IBAN | D8 lineage hold; early hold on `sensitive` fields; rule 5 | 0 irreversible tainted effects released |
| Buggy | RT11 | False-positive suspend of an honest agent | D7; rule 10; release at a fresh epoch | tainted items stay held; FP cost scored |
| Rogue | RT1 | Direct `state.db` bypass | Rule 1; D6 reconciliation (class-U alert) | Blocked; else flagged in ≤1 tick |
| Rogue | RT2 | Key theft (fs, env, fds, `/proc`) | Rules 1, 2; Live setup; fresh keys | 0 key bytes reachable |
| Rogue | RT3, RT3b, RT6 | Forgery; sibling `ptrace`/`pidfd_getfd`; own `ts`/`seq` | Rules 3, 4; D7 connection suspend; per-agent uid, non-dumpable | 0 executed; X not suspended; EPERM; gateway ordering |
| Rogue | RT3c | Forged Control: system id, `ks.*` tool, operator socket | `c-0` reserved; scope; root-only socket + `SO_PEERCRED` | 0 forged Controls applied |
| Rogue | RT4 | Replay (valid, expired, presigned across a release) | Rule 4 (nonce, expiry, epoch) | 0 duplicate effects |
| Rogue | RT5 | Write flood during suspension (TOCTOU) | Rule 5 (epoch + deny-list in the write txn) | 0 culprit writes after suspension `seq` |
| Rogue | RT12 | Suspended agent retries or acts through a revoked ancestor | Rules 4, 10; deny-list | 0 effects from probe |
| Rogue | none | Sleep, loop, fork or memory bomb | Per-tick deadline (miss = no-op, EOF after 3); rlimits | Other agents keep ticking |
| Rogue | RT13 | Replays recorded operator decisions, or runs a rogue in repro mode | Source must pass `verify --head`, plan_hash match; both refused with `--rogue`; repro = gateway holds the witness key, never anchored (SKEL-01 #6) | 0 Controls replayed; repro refused |
| Rogue | F3 (pytest) | Emails PII (rogue comms) | `inv.pii_egress`; rule 9 | 0 values reachable |
| Colluding | RT9 | Laundering: A plants ticket, B writes IBAN | D8 + rule 7; backward taint | A in top-3 root candidates; payment held |
| Colluding | none | Splitting under thresholds | I-class invariants do not depend on rate. **No RT, no claim** | none |
| Insider | RT7 | Edit one record or side entry | D6 chain + sigs; `verify` prints first bad seq | `verify` non-zero |
| Insider | RT8 | Recompute the chain; swap the keyring; truncate | Witness heads; **run anchor checked by `ks verify --head`** (keyring and config hashes, head, count) | Detected against the anchor |

RT7 boundary: marking a side-store entry `redacted` passes `verify` by design. RT8(g): a rewrite after the last witnessed head passes unanchored and is caught by the anchor. All pass values are **targets, not results** (D13); measured values appear only in the Sprint 4 red-team report.

## 6. Day-one interface rules (binding, CALL-01)

1 One subprocess per agent, holding only a gateway handle; gateway owns workspace, record, keys. · 2 Keys never enter the agent process; it signs via a signer handle. · 3 Gateway assigns `seq`, `ts`, `record_id`. · 4 Envelope: nonce, expiry, epoch, full `act` chain; one canonical serializer. · 5 Epoch and deny-list checked in the write transaction; dispatcher re-checks holds. · 6 Fail closed: unknown action → U → deny. · 7 Adapters emit read/write sets; aggregates record coarse reads. · 8 Only the gateway writes the record; alert if the witness head stalls. · 9 The record holds hashes; values go in the side store. · 10 Suspend, release, revoke, recover are signed (by `issued_by`), recorded actions. · 11 Denials are recorded.

## 7. Rules of engagement for the jury

**Live (F5/F6):** `ks run --fault F2+`; arbitrary Python in the rogue template (`ks run --rogue FILE --slot AGENT`); direct `state.db` bypass; a record edit; a full chain rewrite, then `ks verify RUN --head ANCHOR`. **Pytest:** F3. A host shell as the gateway's or witness's user is host compromise (§3), not a break of C1-C6.

## Errata (Call #3, 19 Nov 2026)
- Errata (SKEL-01) finding 1: dumpable flag set after exec (Live setup).
- Errata (SKEL-01) finding 6: repro = gateway holds the witness key, never anchored (Live setup, RT13 row). No claim changes.
- Known limit (B3-16, interface rule 7 "coarse reads"): aggregate and scan reads list only rows live at scan time. A scan that finds nothing records no read (absence reads deferred to 2.0), and `Store.read_table` skips deleted rows, so a row deleted before a scan goes unrecorded and its output is never repaired. A point read of a deleted row does record it. No v1 adapter calls `read_table`, so no F-scenario hits this. No claim changes.
- Known limit (B3-45 option C, B3-46, ADR-05 §4): the t0 walk follows the suspect's reads of its own writes only through `source = tool` read entries. A rogue can choose to compute a later write from its view instead of a tool read, so the earlier write it built on is reached only via a `source = view` entry, which the walk skips. Those earlier suspect writes then fall outside the seed and are not reverted. This is reported, not hidden: the dry-run prints `t0_seq_est_literal` and a non-zero `t0_delta` and asks the operator to review the suspect writes from the literal t0. We do not claim the seed contains every bad write of the suspect. No claim changes.
- Known limit (B3-41, interface rule 7 "adapters emit read/write sets"): the gateway checks only that each reported read exists in the store at the reported version; it cannot see a read that is not reported. An adapter that reads through raw SQL on `txn.store.conn` and does not report it executes with that object missing from its read set, so its output is under-tainted (C5 holds only on the **recorded** read set). Mitigation is rule 7 plus the AST check over `src/ks/world` (`tests/world/test_world.py::test_world_adapters_touch_state_only_through_ctx`); a rogue agent cannot add adapters, since adapters run in the gateway. No claim changes.
