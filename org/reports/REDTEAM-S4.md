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
