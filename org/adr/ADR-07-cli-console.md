# ADR-07: `ks` CLI and incident console

Owner: ishaan · Reviewer: zoya · 19 Nov 2026 · Depends on: CON-01

## Context
The finale and the jury drive the system through one CLI and read the incident through one console. Both work from a run dir (C6) alone. Control stays signed and recorded (rule 10), and only `ks.operator` may revoke. The demo has five beats: break, identify, contain, recover, audit (zoya.md §4).

## Decision

### 1. Commands
Exit codes are `ks.verify.Exit` names; the CLI adds none. `RUN` is a run dir.

| Command | Args | Exits |
|---|---|---|
| `ks run` | `[--seed N] [--fault F2+] [--hold TICKS] [--rogue FILE --slot AGENT] [--ticks N] [--pause-at TICK,… \| --step] [--decisions RUN] [--tick-deadline-ms N] [--out RUN]` | OK, IO, USAGE |
| `ks inject` | `(F2+ \| --rogue FILE --slot AGENT) [--seed N] [--hold TICKS] [--with-baselines] [--pause-at TICK,… \| --step] [--out RUN]` (sugar for `run --fault` / `run --rogue`) | OK, IO, USAGE |
| `ks verify` | `RUN [--head ANCHOR] [--json]` | OK, IO, TAMPER, WITNESS, RECONCILE, USAGE |
| `ks blame` (alias) | `RUN [--alert ID]` | OK, IO, USAGE |
| `ks contain` | `suspend\|release\|revoke TARGET RUN [--alert ID] [--confirm]` | OK, IO, USAGE |
| `ks recover` | `RUN (--dry-run \| --apply PLAN_ID [--approve ITEM...])` | OK, IO, FROZEN, USAGE |
| `ks score` | `RUN [--json]` | OK, IO, USAGE |
| `ks repro` | `RUN_A RUN_B` | OK, IO, DIVERGED, USAGE |
| `ks bench` | `[--seeds 0,1,2] [--faults ...] [--hold ...]` | OK, IO, USAGE |
| `ks console` | `RUN (--html OUT \| --live [--once])` | OK, IO, USAGE |

- **`--rogue`/`--slot`:** runs jury Python (SEC-02 §3 template) in place of the named agent; default slot `docs`, an independent agent. Flags match TERMS "inject" and SEC-02 §3. Fresh keys are forced with `--rogue`, so two runs with one seed and file are identical under `determinism_view()`, not byte-identical.
- **`verify`:** last stdout line is a canonical `VerifyReport`; `--json` prints only that line. The `RunAnchor` line is printed in the console banner at run end and in the run summary; the presenter copies it into `ks verify --head` (F1). `--head` takes the `RunAnchor` line; `VerifyReport.anchored` says whether C1 holds. A TAMPER names the first bad **seq** (one word everywhere; never "index").
- **`blame`:** a command alias only. Screen and narration say "root candidates": ranked `root_candidates` and the first bad action's seq.
- **`contain`:** TARGET is `agent:ID` or `conn:ID`. It needs a live gateway; a finished run gives IO. It talks to the operator socket (J1). The `ks.operator` signer signs a `ks.control` envelope (`auto=false`), which the gateway records. Agent suspend sends the next fresh epoch (strictly monotonic, D1); release sets a new maximum. `revoke` without `--confirm` is USAGE.
- **`recover`:** `--dry-run` writes `plans/<plan_id>.json` and prints the dry-run diff, then the exact `ks recover RUN --apply PLAN_ID [--approve ITEM...]` line, ids filled in, ready to paste. It runs `verify` first and exits FROZEN on a non-OK result or unresolved tamper alert (F5). `--apply` issues controls as `ks.recovery`, runs `restore`, `rerun` and `cancel_outbox` steps, keeps each `replan` item queued until `--approve ITEM`, and never applies a `flag` (write-write conflict).
- **`repro A B`:** diffs `determinism_view()` of two run dirs (C6); OK, or `Exit.DIVERGED`.
- **`score`:** writes `score.json` (ADR-06 keys). No pass/fail exit.

### 2. Pacing (L1)
`ks run`/`inject --pause-at TICK,…` or `--step` stops the gateway between ticks, keeps the operator socket open, and resumes on a keypress or on the next `contain`/`recover` command. A paused run is live, so `ks contain` works. The 5-beat demo runs against a live paused run (`ks run --fault F2+ --pause-at ... --step`); the gateway stays live through beat 4's `ks recover --dry-run`/`--apply` via the operator socket. `ks recover` on a finished run is read-only dry-run only. A paused and an unpaused run with one seed give identical records under `determinism_view()` (byte-identical only in repro mode).

### 3. Operator socket (J1)
`ks contain` and `recover --apply` reach the gateway only over `/run/ks/<run_id>/operator.sock`, in a 0700 uid-0 dir, checked by `SO_PEERCRED` uid 0. Agents cannot connect; the page never opens it.

### 4. Incident console
"Incident console" means the read-only page and nothing else; the signer is `ks.operator`, so the console cannot revoke. `ks console RUN --html OUT` writes **one static HTML file**: inline CSS and JS, run data embedded as JSON, no server, CDN or network call. It opens `record.jsonl`, `witness.jsonl`, `alerts.jsonl`, `plans/`, `score.json`, `oracle/`, `baselines/` and `config.json` read-only and never imports gateway or signer code. It embeds a build-time `verify` result. No wall-clock time: same run dir, same bytes.

Baselines (L2): `ks inject --with-baselines` also runs the snapshot baseline and the revert-culprit-only baseline on the same seed and writes `RUN/baselines/<name>/score.json`. The console embeds these and shows residual damage R and collateral loss C against them. Without the flag the panel reads "not run".

The timeline shows the F2+ hero path in the five beats, in TERMS wording:
1. **Break:** "crm changed a supplier's bank account" (the IBAN field, plus the ×10 price); billing, payments and comms read it. Inventory and docs are independent agents.
2. **Identify:** the IBAN invariant alert and the ranked root candidates (crm first), with the first bad action.
3. **Contain:** crm suspended (auto, hard alert); lineage hold on the payment and email; independent agents still running; crm writes after the suspend seq (target 0).
4. **Recover (B3):** the dry-run diff in four lanes: restore (IBAN, price) · re-run (billing, payments, comms) · **kept** (triage's risk note on the same supplier) · independent (inventory, docs). Line: "triage edited the same supplier; we kept its edit and restored only the bank account". Zero `flag` items. The `replan` queue reads "awaiting approval" until a recorded approval exists; then residual damage R and collateral loss C against both baselines. A hold=0 run shows the released payment as residual damage.
5. **Audit (L3):** the page shows the build-time result and says it is stale until rebuilt. The live proof is `ks verify RUN --head` (exit TAMPER, first bad seq). Edits after the last witnessed seq go undetected; rehearse before it.

Values come from the side store by hash (prefix if redacted); banking labels sit in one table.

`ks console RUN --live` is a read-only terminal view that tails the record and alerts: a line per agent, recent records, held items. `--once` prints one frame, for tests.

Approval is a CLI act (`--approve`); the page only shows what the record says, so it cannot fake one.

## Consequences
- Every demo beat is scriptable, and beats 1-3 can be held live.
- The page outlives the run and shows only what the record proves.
- Open: `bench` flags follow ADR-06; pass/fail exit for `score` (tara).

## Interface touched
- **C4:** issues `Control` as `ks.operator` and `ks.recovery`; reads `Alert`.
- **C5:** writes and applies `RecoveryPlan`.
- **C6:** `RunDir` (incl. `baselines/`), `Exit` (incl. `DIVERGED`), `RunAnchor`, `VerifyReport`, `determinism_view()`.
- **C2:** read only. **C1:** `ks.control` envelopes only. C3 is untouched except side-store reads by hash.

## Tests that prove it
1. Each command's exit codes match the table by `Exit` name, including USAGE for bad args and `revoke` without `--confirm`.
2. `contain suspend` yields a recorded `ks.control` whose `args_hash` binds the clear Control and verifies under the `ks.operator` key. Revoke from another issuer is rejected.
3. `recover --dry-run` with an unresolved tamper alert gives FROZEN; `--apply` leaves a `replan` item unapplied until approved.
4. Console build is deterministic, has no external resource references, leaves the run dir byte-identical, and shows a failed audit beat for an edited record line.
5. Golden: the F2+ HTML lists the five beats in order and includes alert, suspend, held items, dry-run diff with kept lane and 0 flags, baselines and approval (console golden).
6. `ks run --rogue` twice with one seed gives identical `determinism_view()` (not byte-identical: fresh keys).
7. `test_pause_identical_record`, `test_ks_repro_fresh_pair` (OK; changed seed gives DIVERGED), `test_operator_sock_rejects_agent`, `test_dryrun_prints_apply`.
8. `verify --head` with a swapped keyring gives WITNESS; grep test: no `ks.console` signer id remains.

## Amendments (Call #2)
- B3 kept lane, no flag on the hero. C6 `ks repro`, `DIVERGED`. E2 signer is `ks.operator`; console is the page only.
- F1 `verify --head`; seq, not index. J1 operator socket. L1 `--pause-at`/`--step`. L2 `--with-baselines`, `baselines/`. L3 live verify is the audit proof; `--dry-run` prints the apply command; `blame` is an alias.
- Zoya: pacing, flag alignment with TERMS and SEC-02 §3, baselines in the run dir, terms fixed.
- Integration pass: demo runs on live paused run, recover on finished run is dry-run only; RunAnchor location; `--rogue` runs identical under `determinism_view()`.

## Amendments (B3-28 review, maya, 20 Nov)
- `ks console RUN --live --pace` is accepted: it holds the read-only view at each of the five beat boundaries until Enter. It paces the presenter, not the run (that stays `ks run --pause-at`/`--step`, L1), writes nothing and never opens the operator socket.
