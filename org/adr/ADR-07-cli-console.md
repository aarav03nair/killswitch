# ADR-07: `ks` CLI and incident console

Owner: ishaan · Reviewer: zoya · 19 Nov 2026 · Depends on: CON-01

## Context
The finale and the jury drive the system through one CLI and read the incident through one console. Both work from a run dir (C6) alone. Control stays signed and recorded (rule 10), and only `ks.console` may revoke. The demo has five beats: break, identify, contain, recover, audit (zoya.md §4).

## Decision

### 1. Commands
Exit codes are `ks.verify.Exit` names; the CLI adds none. `RUN` is a run dir.

| Command | Args | Exits |
|---|---|---|
| `ks run` | `[--seed N] [--fault F2+] [--hold TICKS] [--rogue FILE --slot AGENT] [--ticks N] [--out RUN]` | OK, IO, USAGE |
| `ks inject` | `F2+ [--seed N] [--hold TICKS] [--out RUN]` (sugar for `run --fault`) | OK, IO, USAGE |
| `ks verify` | `RUN [--json]` | OK, IO, TAMPER, WITNESS, RECONCILE, USAGE |
| `ks blame` | `RUN [--alert ID]` | OK, IO, USAGE |
| `ks contain` | `suspend\|release\|revoke TARGET RUN [--alert ID] [--confirm]` | OK, IO, USAGE |
| `ks recover` | `RUN (--dry-run \| --apply PLAN_ID [--approve ITEM...])` | OK, IO, FROZEN, USAGE |
| `ks score` | `RUN [--json]` | OK, IO, USAGE |
| `ks bench` | `[--seeds 0,1,2] [--faults ...] [--hold ...]` | OK, IO, USAGE |
| `ks console` | `RUN (--html OUT \| --live [--once])` | OK, IO, USAGE |

- **`--rogue`/`--slot`:** runs jury Python (SEC-02 §3 template) in place of the named agent; default slot `docs`, an independent agent. Same seed and file give byte-identical records.
- **`verify`:** last stdout line is a canonical `VerifyReport`; `--json` prints only that line.
- **`blame`:** prints ranked `root_candidates` and the first bad action's seq. A `signature` alert names the `conn_id` only (D7).
- **`contain`:** TARGET is `agent:ID` or `conn:ID`. It needs a live gateway; a finished run gives IO. The `ks.console` signer handle signs a `ks.control` envelope (`auto=false`), which the gateway records. Agent suspend sends the recorded epoch+1; release sets the epoch the gateway reports. `revoke` without `--confirm` is USAGE. Lineage `hold`/`unhold` stay with monitor and recovery.
- **`recover`:** `--dry-run` writes `plans/<plan_id>.json` and prints the dry-run diff; it exits FROZEN while a tamper alert is unresolved (D7). `--apply` issues controls as `ks.recovery`, runs `restore`, `rerun` and `cancel_outbox` steps, keeps each `replan` item queued until `--approve ITEM`, and never applies a `flag` (write-write conflict).
- **`score`:** writes `score.json` (ADR-06 keys). No pass/fail exit.

### 2. Incident console
`ks console RUN --html OUT` writes **one static HTML file**: inline CSS and JS, run data embedded as JSON, no server, CDN or network call. It opens `record.jsonl`, `witness.jsonl`, `alerts.jsonl`, `plans/`, `score.json`, `oracle/` and `config.json` read-only and never imports gateway or signer code. It embeds a build-time `verify` result. No wall-clock time, so the same run dir gives the same bytes.

The timeline shows the F2+ hero path in the five beats, in TERMS wording:
1. **Break:** "crm changed a supplier's bank account"; billing, payments and comms read it. Inventory and docs are independent lanes.
2. **Identify:** the IBAN invariant alert, ranked root candidates, first bad action.
3. **Contain:** crm suspended (auto, hard alert); lineage hold on the payment and email; independents still running; crm writes after the suspend seq (target 0).
4. **Recover:** the dry-run diff (`restore` crm row, `flag` triage conflict, `rerun` billing, `cancel_outbox` payment); the approval, with the `replan` queue shown as "awaiting approval" until a recorded approval exists; then residual damage R and collateral loss C against both baselines. A hold=0 run shows the escaped payment as residual damage.
5. **Audit:** `verify` result, first bad seq, last witnessed seq.

Values come from the side store by hash (hash prefix if redacted). Banking labels sit in one table keyed by tool and `table.field`.

`ks console RUN --live` is a read-only terminal view that tails the record and alerts: a line per agent, recent records, held items. `--once` prints one frame, for tests.

Approval is a CLI act (`ks recover --apply --approve`). The console only shows what the record says happened, so it cannot fake an approval.

## Consequences
- Every attack and demo beat is scriptable from the shell.
- The page outlives the run and shows only what the record proves; a tampered record turns the audit beat red.
- Open: release-epoch reply field (maya); `bench` flags follow ADR-06; pass/fail exit for `score` (tara).

## Interface touched
- **C4:** issues `Control` as `ks.console` and `ks.recovery`; reads `Alert`.
- **C5:** writes and applies `RecoveryPlan`.
- **C6:** `RunDir`, `Exit`, `VerifyReport`; no new field.
- **C2:** read only. **C1:** `ks.control` envelopes only. C3 is untouched except side-store reads by hash.

## Tests that prove it
1. Each command's exit codes match the table by `Exit` name, including USAGE for bad args and `revoke` without `--confirm`.
2. `contain suspend` yields a recorded `ks.control` whose `args_hash` binds the clear Control and verifies under the `ks.console` key. Revoke from another issuer is rejected.
3. `recover --dry-run` with an unresolved tamper alert gives FROZEN; `--apply` leaves a `replan` item unapplied until approved.
4. Console build is deterministic, has no external resource references, leaves the run dir byte-identical, and shows a failed audit beat for an edited record line.
5. Golden: the F2+ HTML lists the five beats in order and includes alert, suspend, held items, dry-run diff and approval.
6. `ks run --rogue` twice with one seed gives byte-identical records.
