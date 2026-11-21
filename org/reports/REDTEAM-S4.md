# REDTEAM-S4: mutation gate for every defence (S4-21)

Owner: kabir (Security) · 21 Nov · Reviewer: panel · Inputs: S4-01 (panel's review: recovery-apply recheck had only a unit test), THREAT-MODEL §5/§6, `tests/redteam/SPEC.md` §5

**Result: 12 of 12 mutants killed.** In the first run (before this issue's tests), 11 of 12 were killed. Two defences were gaps, and each now has a new red-team test that kills it:
- **SO_PEERCRED (M11)** survived the whole red team. RT3c leg (d) is refused earlier, by the 0700 directory, so the peer-uid check never ran. New test: **RT3d**, `tests/redteam/test_rt03d_peercred.py`.
- **Recovery-apply staleness re-check (M12)**: only `tests/runtime/test_recover.py` caught it, which is not a red-team test. New test: **RT15**, `tests/redteam/test_rt15_stale_apply.py` (in the first run, RT15 was already in the overlay).

## How to run

```
make mutation-gate                                   # = IMAGE=killswitch:kabir python3 tests/redteam/mutation_gate.py
python3 tests/redteam/mutation_gate.py --list        # the mutants
python3 tests/redteam/mutation_gate.py --only M11 --keep
```

- **Never touches the main tree.** The gate snapshots `pyproject.toml`, `Dockerfile`, `src/` and `tests/` into a fresh temp dir and builds the image from that snapshot. Each mutant is a copy of the snapshot with one switched-off defence. `--head` snapshots `git archive HEAD` instead and overlays the working tree's `tests/redteam/` (see finding 1).
- **Container:** `docker run --rm --network none`, as root. The mutant's `src/` and `tests/` are mounted read-only over `/app` with `PYTHONPATH=/app/src`. Running as root means the per-agent uid tests (`NEEDS_UIDS`) run and do not skip: 0 skipped in every run below.
- **Baseline first.** The unmutated snapshot must pass `tests/redteam`, or the gate stops. A red baseline would kill every mutant for free. With `--allow-red-baseline`, only tests that pass in the baseline count as kills.
- **Kill rule:** a mutant is killed only if at least one red-team test that passed in the baseline now fails. A timeout or crash with no failing test does not count. The old text must occur the stated number of times and the mutant file must compile, so a stale mutation fails loudly and is never silently skipped.
- **Exit code:** 0 if every mutant is killed; 1 if any survive; 2 if the build or the baseline fails. The run also writes `mutation-gate.json` in the scratch dir.
- **Scope limit [Our view]:** agent subprocesses start with a clean environment, so they import `ks` from the image's installed (unmutated) copy. No mutant is in agent-side code. Every mutant is in a process that does get `PYTHONPATH`: the gateway/runtime, monitor, witness link, operator socket, or `ks verify`.

## Table (container run, worktree snapshot, 21 Nov; baseline 97 passed, 0 failed, 0 skipped)

| ID | Defence switched off (mutation) | File | Verdict | Red-team tests that fail |
|---|---|---|---|---|
| M01 | **Epoch fence, live:** gateway step 8 `env.epoch != current` -> `deny/stale_epoch` (`if False`) | `src/ks/gateway/stub.py` | killed (3) | `test_rt04_replay::test_rt4_each_replay_leg_denied_with_its_reason`, `::test_rt4_global`, `test_rt05_toctou::test_rt5_hook_suspend_between_check_and_txn[epoch-stale_epoch]` |
| M02 | **Epoch fence, audit:** verify B3-49, admitted at a non-current epoch -> `epoch_regression` | `src/ks/verify/core.py` | killed (9) | `test_rt12_epoch_fence::test_same_tick_after_suspend[old_epoch, new_epoch]`, `::test_release_then_resuspend[*]`, `::test_after_revoke[*]`, `::test_future_epoch_*` (2), `::test_hold_decision_is_fenced` |
| M03 | **Epoch fence, audit:** verify B3-35, suspended/revoked `act_chain` ancestor -> `epoch_regression` | `src/ks/verify/core.py` | killed (2) | `test_rt12_epoch_fence::test_admitted_with_dead_act_chain_ancestor[suspend, revoke]` |
| M04 | **`inv.pii_egress`** (the hard alert on PII in a queued email payload never fires) | `src/ks/monitor/detectors.py` | killed (7) | `test_rt10_irreversible::test_f3b_pii_egress_fires_in_a_run_and_nothing_leaves`, `::test_extra_recipient_fails_closed[extra0..5]` |
| M05 | **Dispatcher re-check** (the release phase dispatches a suspended/revoked author's due item) | `src/ks/gateway/stub.py` | killed (6) | `test_rt05_toctou::test_rt5_nothing_executes_or_dispatches_after_suspend`, `::test_rt5_global`, `test_rt10_irreversible::test_f3_pii_egress_held`, `::test_f3b_*`, `test_rt12_persistence::test_rt12_nothing_as_or_through_comms_after_suspend`, `::test_rt12_global` |
| M06 | **Outbox provenance** (`unrecorded_item` hold off) | `src/ks/gateway/outbox.py` | killed (1) | `test_rt10b_outbox_provenance::test_rt10b_offlog_outbox_item_is_held_never_dispatched` |
| M07 | **Witness ack signature check** (`WitnessLink._ingest`) | `src/ks/witness/link.py` | killed (4) | `test_rt08b_witness_ack::test_rt8b_ack_signed_by_another_key_is_a_stall`, `::…_edited_after_signing_…`, `::…_unsigned_or_garbage_…`, `::test_rt8b_forged_ack_drained_at_close_is_not_the_anchor` |
| M08 | **Witness ack pushed-head check** (`(seq, head)` must be what the link pushed for that tick) | `src/ks/witness/link.py` | killed (2) | `test_rt08b_witness_ack::test_rt8b_validly_signed_but_mismatched_ack_does_not_move_the_anchor`, `::test_rt8b_forged_ack_drained_at_close_is_not_the_anchor` |
| M09 | **Deny-list re-read inside the write txn** (step 13, rule 5: `why = None` after `BEGIN IMMEDIATE`) | `src/ks/gateway/stub.py` | killed (4) | `test_rt05_toctou::test_rt5_hook_suspend_between_check_and_txn[suspend-suspended, epoch-stale_epoch, conn-revoked, ancestor-revoked_ancestor]` |
| M10 | **Connection deny-list** (`conn:<id>` suspended/revoked is ignored at steps 7 and 13) | `src/ks/gateway/stub.py` | killed (2) | `test_rt03_forgery::test_rt3_connection_suspended_billing_untouched`, `test_rt05_toctou::…[conn-revoked]` |
| M11 | **SO_PEERCRED** peer-uid check on the operator socket (J1, B5) | `src/ks/runtime/operator.py` | killed (1); **survived before RT3d** | `test_rt03d_peercred::test_rt3d_agent_uid_refused_by_peercred_when_dir_is_open` |
| M12 | **Recovery-apply staleness re-check** (M8): every `ks.recovery.recheck` in `runtime/recover.py` returns None (restore, cancel, rerun and resolve paths) | `src/ks/runtime/recover.py` | killed (2) | `test_rt15_stale_apply::test_rt15a_honest_write_after_dry_run_holds_the_apply`, `::test_rt15b_approval_is_not_a_blank_cheque` |

Counts in brackets are the number of red-team tests that failed. Run times on this Mac, 4 containers in parallel: baseline 147–256 s, each mutant 151–380 s. Gate run: 12/12 killed, exit 0. The full gate takes about 20 min.

## New tests

**RT3d: `test_rt03d_peercred.py` (container only, `NEEDS_UIDS`).** THREAT-MODEL B5 is two layers: "Root-only dir plus `SO_PEERCRED` uid 0". RT3c (d) only ever exercises the first layer. With the run paused at tick 4, the root harness opens `operator/` to 0711 and the socket to 0666, which is what a mis-deployed socket directory would look like. A process running as the `docs` agent's uid (`agent_uid(4)`) then connects and asks for `suspend agent:billing`. Asserted:
- the connect succeeds, so layer 1 really was down;
- the peer gets no reply bytes;
- 0 `ks.operator` Controls are applied, and billing is still active;
- the run summary shows refused peers ≥ 1;
- `assert_global` passes (verify OK and anchored).

Permissions are restored before the run resumes. With M11 the request is served and the test fails.

**RT15: `test_rt15_stale_apply.py`.** Attack: an honest write through the real gateway (billing re-drafts `invoices:INV-0031`) lands after the dry-run on an object that a planned re-run writes. Two legs: (a) before the approval, (b) after the recorded `ks.approve` (the approval is not a blank cheque). Asserted:
- that step is `hold/stale_plan` with no writes;
- nothing after it is recorded (the apply halts);
- the honest version is still the head (same version, same hash, author billing);
- `verify` is OK.

The claim defended is C6. RT15 runs **in process** (`tests/recovery/world.py`: real Gateway, Recorder, RecoveryService, signer and witness, no sockets or uids). [Fact, measured here] The world scenario never schedules this write. On seed 2 F2+ with `ks run --step`, I delayed the apply 0, 3 and 8 ticks after the dry-run, and every step executed with no stale step. So a live `ks run` cannot reach this race without a racing agent that has write scope on a re-run object. Rogue and fault are mutually exclusive (`RunOptions`), so no single run can contain both a culprit and a racing writer.

## Findings

1. **HEAD is red for `ks score` (blocker for anyone running from a clone, including panel's jury dry run).** [Fact] At `752e971`, `src/ks/score/score.py:413` calls `_resolver(run)`, which reads `RunConfig.resolver`. That field exists only in the *uncommitted* S4-13 contracts. Result: the HEAD snapshot's baseline in the container gives 92 tests with **11 failed**. Re-run natively on a HEAD copy, the same 11 fail, and all 11 carry `AttributeError: 'RunConfig' object has no attribute 'resolver'` raised from `ks score`. Affected: `test_noop_rogue_score` ×2, RT9 ×2, RT10 ×4 (`hold_saves_the_payment`, `hold_zero_damage_is_scored`, `f3_pii_egress_held`, `contrast_label_travels_with_score`) and RT11 ×3. The working tree is green (97/97 in the container; full native suite 1131 passed, 13 skipped). Fix: commit S4-13's contracts with score.py, or revert the score.py hunk. Owner: vikram (S4-13), or pmo for the S4-01 commit. Until that lands, the gate defaults to a working-tree snapshot.
2. **Restore staleness is guarded three times, so switching off one guard is an equivalent mutant (not in the gate).** The restore path checks staleness in `recheck` (`conflict.py`), in `apply_restore`'s expect check (`planner.py`), and in `store.restore(expect=)`. Turning off only the restore `recheck` survives by construction. M12 turns off every `recheck`, and RT15 kills it through the re-run path, which has only the one guard.
3. **SO_PEERCRED was untested defence in depth (M11, fixed by RT3d).** [Our view] There is no claim change. B5 already names both layers. RT3d is the first test showing the second layer holds by itself.

## Acceptance (S4-21)

| Criterion | Evidence |
|---|---|
| Script disables each listed defence: epoch fence (M01–M03), pii_egress (M04), dispatcher re-check (M05), outbox provenance (M06), witness ack sig (M07; head check M08), deny-list in txn (M09; conn deny-list M10), SO_PEERCRED (M11), recovery-apply recheck (M12) | `tests/redteam/mutation_gate.py`, `make mutation-gate` |
| Each kills ≥1 `tests/redteam` test in the container | table above: 12/12 killed, 0 skipped |
| A survivor gets an RT test that kills it | RT3d (M11), RT15 (M12) |
| Main tree never mutated; image tag `killswitch:kabir` | snapshot in a temp dir; `IMAGE` default |

---

# S4-23: claim audit of README, demo-sim, console and the Kit number files

Owner: kabir · 21 Nov · HEAD `1b9a743` (+ working tree) · Reviewer: panel (jury dry run #2 runs concurrently from a clone; nothing here depends on it)

**Scope.** `README.md`, `board/demo-sim.html`, the incident console (`ks console --html`, rendered from two real container runs: hero `runs/finale-hero-s2-20261121-064305` and F2+x `runs/finale-f2x-s2-20261121-064305`, both `ks run --resolver ww_rebase/1`, T=40 in config.json, verify OK, `per_agent_uid`), `abstract/ALLOWED-NUMBERS.md`, `abstract/FACT-CARD.md` (own-number rows O1–O6), `abstract/JURY-QA.md`. Not re-run: a new `make demo` (a demo container was live during the audit; one `ks run` per machine, K2).

**Method.** Every number of ours was matched against a cell in `org/reports/BENCH-S3.md` or a named score.json. Then I checked each one for: T=40 stated, container stated, D-17 clause next to every R = 0, and the resolver label (opt-in `ww_rebase/1`) on every after-row value. I grepped for `never|proof|prove|provable|first|guarantee|tamper-proof|impossible|unforgeable|immutable` in all six files and in the rendered console strings.

## Result

**[Fact]** Every number traces to a BENCH-S3 cell or a named score.json except FACT-CARD seed 0 (finding K4). No unrefuted overclaim word was found. Fixed in place (one word each): "container" added to the README bench sentence and to the demo-sim banner. Open: 8 findings, listed below. None changes a value. Four of them need an owner other than me (Kit files and console code).

## Trace table

| Surface | Numbers checked | Source matched | T=40 | Container | D-17 at R = 0 | Resolver label |
|---|---|---|---|---|---|---|
| README "Expected end of output" (seed 2) | verify seq 223; tti 2/0, ttc 1; R 0/9, C 0/265, kept 263/265; 0 post-alert, 0 irreversible, 0 reemitted | `runs/bench-b3-33/F2p/h6/system/s2/score.json`; `runs/hero-s2-20261120-092934.verify.txt`; same in finale-hero score.json | yes (step 3) | yes (step 2) | R shown as raw score.json output; release counts in the beat table ("2 re-held + 7") | **no** (K2) |
| README beat table (seed 2) | tti 2, ttc 1, 2 + 7 releases, R n=0, C n=0 | same score.json (`operator_unholds` 9 = 7 honest + 2 tainted) | via section | yes | the "score.json" row says R n=0 with the releases one row up (K3, minor) | no (K2) |
| README bench paragraph | R 0 after 5 [..9] releases (3 honest, 2 tainted), C 0, reemitted 0, tti 2, ttc 1; F2+x R 1/5, 29 held, RCO 27 | BENCH-S3 §F2+ H=6 system; §F2+x H=6 system and RCO | yes | **fixed** (added "container") | yes | **no**: F2+x has no "before resolver" label, no after-row, no C (K1) |
| README setup times 47 s / 15 s | not a system claim | S4-02 log (ishaan run, OrbStack arm64) | n/a | n/a | n/a | n/a |
| demo-sim banner, beats, terminal, scorecard | t_inject 11, t_alert 13, seqs 45/52/53/59/60/63/64/65/66, tti 2/0, ttc 1, 7 held, 9 releases (7 + 2), R 0/9, C 0/265, kept 263/265, verify seq 223; bench 1 [1..1], 5 [1..9] (3, 2), R 3/5 [0..7/9], C 34/263, post-alert 1 [0..1]; contrast 12 [6..18], 0 [0..0] | HTML `SRC` comments, all checked: bench-b3-33 s2 score.json, hero-s2-20261120-092934 record/dry/apply/verify, BENCH-S3 §F2+ H=6, §CONTRAST F2+ H=0. `ks blame` lines re-run by me on finale-hero: identical | yes | **fixed** (banner); terminal says per-agent uids | yes: terminal, scorecard row, narration | blame beat says "(resolver on)"; hero results are identical off/on (BENCH-S3 §S4-13) |
| Console, hero run | tti 2/0, ttc 1, R 0/9, C 0/265, irreversible 0; releases 9 (7 honest, 2 tainted); held honest 7 | finale-hero score.json = bench-b3-33 s2 cell for cell | **no** (K5) | implicit: `isolation=per_agent_uid` validity line | yes: release line printed under the scorecard | yes: banner `resolver: ww_rebase/1 (on)` |
| Console, F2+x run | same values; plan step 1 `resolve suppliers:S-22 (ww_rebase/1) … undo: ks recover RUN --unresolve p-000066.1` | finale-f2x score.json = `runs/bench-s4-13-ctr/F2px/h6/system+resolver/s2/score.json` cell for cell | **no** (K5) | implicit, as above | yes | yes |
| ALLOWED-NUMBERS N1–N18 | every cell | BENCH-S3 §F2+, §F2+x, §F2+ H=0, §CONTRAST, §S4-13: all match | yes (G1) | yes (G9; N18 (c)) | yes (N4, N18 (b), N16 states its 2 releases) | yes (3b (a)) |
| FACT-CARD O1–O4 | seeds 1 and 2: R 0/5, 0/9; releases 2+3, 2+7; held 3/7; stall 0/382, 0/381; tti 2, ttc 1 | bench-b3-33 s1 and s2 score.json: match | **no** in the O header (K4) | yes ("real container runs") | yes (O1) | n/a (pre-resolver runs) |
| FACT-CARD O5/O6 | before and after rows | BENCH-S3 §S4-13: match | yes | yes | yes | yes |
| JURY-QA Q8, Q10, Q13 | Q8 3 [0..7] held, 5 releases, H=0 R 0, contrast 12 [6..18]; Q10 both F2+x rows; Q13 5 [1..9] = 3 + 2 | BENCH-S3: match | yes (standing rule; Q10 inline) | yes (Q10 inline) | **Q8 no** (K6); Q10, Q13 yes | Q10 yes |

## Word grep

**[Fact]** Every hit is one of four kinds:
- a refutation or trap ("Tamper-proof" X15, "Impossible" Q5, "Guarantees" Q1, "first" X1/X5, "never a bare R = 0");
- a usage rule ("never seconds", "never quote");
- a narrower claim ("detects, never prevents", "never cancel");
- ordinary English ("read first", "first bad seq", "the approver never resolves flags", "repro … never anchored").

Two hits need a note:
- **Console `live proof: ks verify RUN --head ANCHOR`** (`src/ks/console/model.py:459`, shown in every console audit beat). "Proof" overclaims an anchored verify. THREAT-MODEL C1 calls it a check of tamper evidence up to the last witnessed head. Finding K7.
- **demo-sim "A juror edits any line; verify with --head … catches it"**. This is true for the seed-2 run: the last witnessed seq is 223 and so is the last record, so 0 records are unwitnessed. The same sentence also states the boundary in THREAT-MODEL wording. [Our view] It is acceptable on stage only for a run whose console shows no "[unwitnessed]" records. Do not repeat it for a run that has them.

The THREAT-MODEL phrase "tamper-evident up to the last witnessed head" appears verbatim in the README, demo-sim and the console audit beat.

## Findings (open; none changes a value)

| # | Where | Finding | Fix (proposed) | Owner |
|---|---|---|---|---|
| K1 | README.md line 98–100 | The F2+x sentence gives only the **before** row: R 1/5 and 29 held. It has no "before resolver" label, no C (21/254), and no after-row (R 0, C 0, 3 held, after 5 releases; resolver ww_rebase/1 on, opt-in). This breaks D-18 (both rows), ALLOWED §3 (R, C and held together) and D-19 (label). A juror reading only the README sees F2+x as unsolved, or, if told otherwise orally, sees a hidden row | Replace with the two O5/O6 rows from FACT-CARD, each with its label, and add "medians over 20 seeds" | ishaan (README, S4-02) |
| K2 | README.md "What each demo beat means" | `make demo` runs with `--resolver ww_rebase/1` by default (`scripts/demo.sh` line 15). The README never says so, and never says the resolver is opt-in. The values are unaffected: hero F2+ score.json is identical off and on (BENCH-S3 §S4-13 "Hero F2+"). But the console banner reads `resolver: ww_rebase/1 (on)` and the README does not explain it | Add one line: resolver on by default in the demo (`RESOLVER=off` to compare); hero results identical off/on | ishaan |
| K3 | README.md beat table, row "score.json" | "R n=0, C n=0" does not repeat the D-17 clause. The release count is one row up. Minor | Add "(after the 9 releases above)" | ishaan |
| K4 | abstract/FACT-CARD.md O1–O4 header | No T is stated. Seed 0 values (R 0/1, releases 1+0, stall 0/389, tti 0) trace to no BENCH-S3 row: bench seeds are 1..20. No seed-0 score.json exists in `runs/` at HEAD, so I could not re-check them. Seeds 1 and 2 match bench-b3-33 | Add "T=40" to the header. Name the seed-0 run dir, or mark seed 0 "B3-27 run, not in BENCH-S3" | anaya (Kit) |
| K5 | Console (`src/ks/console/html.py`) | Fault, seed, T (ticks) and H are in the model (`M.config`) but are never rendered, and the scorecard has no T. The page alone does not state T=40. The container is implicit (`isolation=per_agent_uid`) | Render one config line above the scorecard: fault, seed, `T=<ticks>`, `H=<hold_window_ticks>`, isolation | ishaan (console, S4-19) |
| K6 | abstract/JURY-QA.md Q8 "Evidence (us tuning it)" | "BENCH-S3 F2+ H=0 system: R 0, irreversible released 0" has no D-17 clause. N16 carries it: after operator releases 2 [1..2] (0 honest) | Append N16's release clause | anaya (Kit) |
| K7 | Console audit beat (`src/ks/console/model.py:459`) | "live proof: ks verify RUN --head ANCHOR": wrong word ("proof") | "live check:" (one word) | ishaan (console, S4-19) |
| K8 | abstract/JURY-QA.md Q13 last trap | Stale: "The console scorecard does not yet show release counts (S4-19)". It does now: "operator released 9 held item(s): 7 honest, 2 tainted (recovery re-holds); honest actions held: 7", seen on both rendered runs | Delete the trap, or point to the console line | anaya (Kit) |

Minor, no action required [Our view]:
- **ALLOWED header.** It says the source of every value is `runs/bench-b3-33/`. N18 comes from `runs/bench-s4-13-ctr/`, and §3b says so.
- **demo-sim scorecard.** Baseline cells give the median without the range (e.g. snapshot C "34/263"), while the note says "Medians [min..max]". The ranges are in the SRC comment and in BENCH-S3.
- **Console lanes, F2+x run.** Triage is listed as "independent" and "kept: none", although step 1 rebased its S-22 edit. The resolve step is shown with its undo command, so nothing is hidden. The lane wording could mislead.

## Acceptance (S4-23)

| Criterion | Status |
|---|---|
| Every number traces to a BENCH-S3 row (or a cited score.json) with T=40 and container stated | All values trace, except FACT-CARD seed 0 (K4). T or container is missing in the console (K5) and in the FACT-CARD O header (K4). README and demo-sim container wording fixed in place |
| Every R = 0 has the D-17 operator-release clause | Yes in demo-sim, console, ALLOWED, FACT-CARD, Q10 and Q13. Missing in JURY-QA Q8 (K6); README beat row is minor (K3) |
| Resolver numbers say opt-in ww_rebase/1 | Yes in ALLOWED, FACT-CARD, JURY-QA and the console banner. README omits both the after-row and the demo's resolver default (K1, K2) |
| Overclaim grep finds no unrefuted use | Yes. One wrong word in the console ("live proof", K7) |
| Report in REDTEAM-S4.md | This section |
