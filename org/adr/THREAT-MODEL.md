# THREAT-MODEL: Project Kill Switch, for the jury

Owner: kabir · SEC-01 v3 · Binding source: org/meetings/CALL-01.md · Read before the D11 live attacks.

**System:** agents are separate subprocesses that reach shared state only through the **gateway**, which owns workspace, record and keys. A separate **witness** process signs `(seq, head, tick, count)` every tick; `count` is its own monotonic counter. `verify` checks chain, signatures, witness heads, seq gaps and reconciliation (state = fold(record)).

**Live setup (fixed day 1).** The container runs as uid 0. Gateway: uid 0; witness: its own uid; **each agent: its own numeric uid** (60001 + index, no passwd entry needed); the agent template sets `PR_SET_DUMPABLE=0` before agent code runs; rlimits are per uid. Checked here 19 Nov: cross-uid `ptrace`/`pidfd_getfd` → EPERM. Keys are generated in memory, never on disk; gateway, witness and signer set `PR_SET_DUMPABLE=0`; each agent gets a path-less `socketpair`, a clean env and `close_fds`. The console prints the mode at start. **If an environment cannot separate the gateway uid, C1 and C4 degrade:** a key read from the rogue subprocess is the admitted gap and voids C1/C4 for that run; reconciliation does not see it (RT2). **If per-agent uids fail, per-agent attribution is void for that run:** a sibling may act through an honest agent's handle (RT3b).

## 1. Assets

| Asset | What it is | Why an attacker wants it |
|---|---|---|
| Workspace state | `state.db`, row-versioned SQLite | Corrupt data other agents read |
| Outbox | Held irreversible effects (payments, email) | Get a tainted effect out first |
| Record + witness heads | Hash-chained, signed records. Heads: kept by the witness process in its own file (dir owned by the witness uid, 0700), echoed to console and run summary | Erase or rewrite who did what |
| Keys (4 classes) | **agent**, **gateway**, **witness**, **recovery** | Forge actions, forge records, or forge a repair |
| Containment state | Deny-list, credential epochs | Escape suspension, or suspend an honest agent |
| Side store | Values (e.g. IBANs); the record holds hashes (rule 9). Tested by the F3 pytest | Read customer data via the evidence |

## 2. Trust boundaries

| # | Boundary | Trust |
|---|---|---|
| B1 | agent → gateway IPC | **Untrusted.** All input checked; agent-declared lineage, `ts`, `seq` never trusted |
| B2 | gateway → workspace | **TCB.** The gateway is the reference monitor |
| B3 | gateway → witness | Separate process and uid, own key and head store; anchors the record |
| B4 | record file ↔ operator | **Editable.** We detect, not prevent |

The console operator who approves recovery plans and revokes is **trusted**.

## 3. Adversaries

**In scope**

| Adversary | Capability |
|---|---|
| **Buggy agent** (F1/F2/F4/F7) | Non-adaptive. Wrong but well-formed, in-scope writes (hero: crm swaps a supplier IBAN) |
| **Rogue agent** | Arbitrary code in its own process. **The jury may run arbitrary Python inside the rogue subprocess** (D11): bypass, replay, forge, flood, stall |
| **Colluding agents** | Laundering via tickets, splitting under thresholds. We name **root candidates**; no prevention claim |
| **Insider record tamper** | Edits record files; holds no witness key; cannot alter the head printed at run end (the head store is defence in depth) |

**Out of scope**, with the production mitigation we would use:

| Out of scope | Why | Production mitigation |
|---|---|---|
| Gateway/witness host or root compromise | A reference monitor falls with its host (Airlock also trusts its TCB, App. A.6) | Keys in an **HSM**; record on **WORM** storage |
| One insider holding both gateway and witness keys | Can re-sign and re-witness a rewritten chain | Split key custody (HSM) + **WORM** witness store |
| Shared uid (agent = gateway user, or agents share one uid) | Only where setuid fails; voids C1/C4, or per-agent attribution (Live setup) | Separate **container** per agent; C2 |
| Exhaustion beyond per-agent rlimits | One shared host | Container limits (pids, memory, CPU) |
| Covert channels between agents | Not in any read set | Network isolation narrows them; no claim |
| Semantic influence | Taint tracks data exposure, not meaning | None; we **over-taint** (conservative) |
| Preventing prompt injection | Not our layer | We contain and recover its effects |

## 4. Claims we make and claims we refuse

Wording is CALL-01's, verbatim. Say nothing stronger.

| # | We claim | We refuse |
|---|---|---|
| C1 | The record is **"tamper-evident up to the last witnessed head"** (D6) | "Tamper-proof". No protection for records after the last witnessed head; a stalled head raises an alert (rule 8). No Merkle proofs |
| C2 | Key isolation: **"enforced in production (uid/container), detected here by reconciliation"** | "Keys are unreachable in this container". Reconciliation detects unmediated writes, not a key read; RT2 measures what is reachable here |
| C3 | Colluding agents: backward taint names **root candidates**; **no prevention claim** | Preventing collusion. Naming the true originator of a laundered write (it carries the launderer's signature) |
| C4 | A **bad signature suspends the submitting connection, never the claimed agent** (D7, anti-framing) | That a valid signature proves intent. It proves which key signed through which handle |
| C5 | The gateway holds writes and outbox items whose **recorded** read set touches tainted versions (D8) | Lineage the agent declares. Holds on effects released before the alert: at hold window 0 they are scored as residual damage (D10) |
| C6 | Containment **holds, never cancels** (release = un-hold + restore epoch). Recovery appends compensating records; a held outbox item is cancelled only by an approved recovery-plan step (`cancel_outbox`) after the dry-run diff | Undoing released external effects. Any comparison with Airlock: it is forward containment, complementary (D3) |

## 5. Adversary → attack → control

Controls: **D6** chain + agent sig + gateway sig + witness + `verify`; **D7** auto-suspend on hard evidence only (scope breach, I-class invariant breach, reconciliation mismatch = class U), bad sig suspends the connection, tamper alert freezes recovery and suspends nobody, revoke only after confirmation; **D8** per-action hold from recorded read sets. Rules 1-11 are in §6.

| Adversary | RT# | Attack | Control that answers it | Pass target |
|---|---|---|---|---|
| Buggy | RT10 | Honest consumer pays the bad IBAN | D8 lineage hold; early hold on `sensitive` fields; rule 5 (holds re-checked at dispatch) | 0 irreversible tainted released |
| Buggy | RT11 | False-positive suspend of an honest agent | D7 suspend before revoke; rule 10 | `release` restores work; FP cost scored |
| Rogue | RT1 | Direct `state.db` bypass | Rule 1 (gateway owns workspace, 0600, separate uid); D6 reconciliation → D7 class-U suspend | Blocked; else flagged in ≤1 tick |
| Rogue | RT2 | Key theft (fs, env, fds, `/proc` memory) | Rules 1, 2; Live setup (uid, in-memory keys, non-dumpable, socketpair, clean env) | 0 key bytes reachable |
| Rogue | RT3 | Forgery: claims X, signed by Y | Rule 4 (canonical serializer); D7 connection suspend | 0 executed; X not suspended |
| Rogue | RT3b | Sibling hijack: `ptrace`/`pidfd_getfd` on another agent to use its socket and signer handle | Per-agent uid + non-dumpable agent processes; rule 2 | Attach gets EPERM; 0 actions attributed to the victim |
| Rogue | RT4 | Replay of valid or expired envelope | Rule 4 (nonce, expiry) | 0 duplicate effects |
| Rogue | RT5 | Write flood during suspension (TOCTOU) | Rule 5 (epoch + deny-list checked in the write transaction); rule 11 | 0 culprit writes after suspension `seq` |
| Rogue | RT6 | Supplies its own `ts`/`seq` | Rule 3 (gateway assigns `seq`, `ts`, `record_id`) | Ordering uses gateway values |
| Rogue | RT11 | Tricks auto-suspend of an honest agent | D7 (anti-framing, hard evidence only); rule 10 | As RT11 above |
| Rogue | RT12 | Suspended agent delegates or retries | Rule 4 (full `act` chain); rule 10; rule 6 (unknown → U → deny) | 0 effects from probe |
| Rogue | none (live) | Sleep, loop, fork or memory bomb stalls the tick barrier | Per-tick deadline (config): missing envelope = no-op + anomaly (D7, one click); per-agent rlimits | Other agents keep ticking |
| Rogue | none | Forges suspend, release, revoke, recover | Rules 2, 10: gateway signs Control actions; recovery key gateway-held, used only on console approval of the dry-run diff, never in an agent process | 0 forged Control actions applied |
| Rogue | F3 (pytest) | Reads side-store values via records or evidence | Rule 9 (hashes only); side store gateway-owned, 0600 | 0 values reachable |
| Colluding | RT9 | Laundering: A plants ticket, B writes IBAN | D8 + rule 7 (tickets are objects in read sets); backward taint | A in top-3 root candidates; payment held |
| Colluding | RT10 | Laundered value reaches payments | D8 lineage hold | As RT10 above |
| Colluding | none | Splitting under thresholds | Data invariants (I-class) do not depend on rate; rate rules do. **No RT, no claim** | none |
| Insider | RT7 | Edit one record (one IBAN hash) | D6 chain + sigs; rule 9; `verify` prints first bad index | `verify` non-zero |
| Insider | RT8 | Recompute the whole chain | D6 witness heads (insider holds no witness key) | Detected |
| Insider | RT8 (variant) | Truncate the tail | D6 seq gaps + witness head; rule 8 | Detected up to last witnessed head |
| Insider | RT8 (variant) | Truncate record **and** witness heads to an older valid prefix | Witness `count` is monotonic; `verify` checks against the final signed head + count printed at run end (off the file system). A run with no printed head is out of scope (production: **WORM** witness store) | Detected against the printed head |
| Insider | RT7/8 | Any tamper during recovery | D7: tamper alert freezes recovery, suspends nobody | Recovery frozen |

All pass values are **targets, not results** (D13); measured values appear only in the Sprint 4 red-team report.

## 6. Day-one interface rules (binding, CALL-01)

1 One subprocess per agent, holding only a gateway handle; gateway owns workspace, record, keys (0600; separate uid where possible). · 2 Keys never enter the agent process; it signs via a signer handle. · 3 Gateway assigns `seq`, `ts`, `record_id`. · 4 Envelope: nonce, expiry, epoch, full `act` chain; one canonical serializer. · 5 Epoch and deny-list checked in the write transaction; dispatcher re-checks holds. · 6 Fail closed: unknown action → U → deny. · 7 Adapters emit read/write sets; aggregates record coarse reads. · 8 Only the gateway writes the record; alert if the witness head stalls. · 9 The record holds hashes; values go in the side store. · 10 Suspend, release, revoke, recover are signed, recorded actions. · 11 Denials are recorded.

## 7. Rules of engagement for the jury

**Live (F5/F6):** `ks inject`; arbitrary Python in the rogue-agent template (including stalls, resource bombs and attaching to sibling agents); direct `state.db` bypass; a record edit; a full chain rewrite, then `verify`. **Pytest:** F3 (exfiltration). A host shell as the gateway's or witness's user is host compromise (§3), not a break of C1-C6.
