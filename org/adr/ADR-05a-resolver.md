# ADR-05a: Auditable, reversible resolver for write-write conflicts (D-18)

**Owner:** maya · **Builder:** vikram (S4-13) · **Reviewer:** kabir · **Status:** in review (rev 2, kabir's S4-12 changes 1–5 applied) · **Amends:** ADR-05 §6.2, §6.1 (held items), §8; CALL-02 B5, B6 (see CALL-02 amendment note in `org/meetings/CALL-02/resolutions.md`) · **Inputs:** CALL-04 decision 2 (D-18), ADR-05 §6.1/§6.4/M14/B3-30, `src/ks/recovery/{planner,conflict,dryrun}.py`, `src/ks/runtime/recover.py`, `src/ks/world/{agents,tools}.py`

## Context

Aarav decided D-18 on 20 Nov: a resolver for flagged write-write conflicts that is "a proper auditable and stable resolver with traceback of what was resolved", so that a bad resolution can be found and fixed.

What exists now ([Fact], from the code):
- The planner gives `flag(write_write_conflict, obj, action)` when the head of an object the suspect wrote is a later **tainted** version by someone else (`planner.py`, restore loop). It does not restore that object. The readers of that head ride with the flag, and their outbox items stay held (`Planned.held`, ADR-05 §6.1 amended).
- F2+x (`world/agents.py` `_triage`, `world/tools.py` `_supplier_set_risk_note`): at h+2 triage runs `supplier.set_risk_note` on `S-22`. The tool reads the `suppliers:S-22` row (tool read, plain projection) at crm's tainted v2 (price x10), then writes the whole row back with `risk_note` set. Triage is deterministic. It writes one object and creates no outbox item. Billing's S-22 invoice at h+3 reads triage's version, so it rides with the flag.
- CALL-02 B2 rejected "restore + re-run triage" **for the hero** because it needed a new `expect` semantic (M13), restored over a tainted head, and was critical-path code. Field objects (B1) fixed the hero. B5 kept F2+x as the honest unresolved flag. D-18 now asks for a resolver for exactly that residue. The hero F2+ plan does not change, because it has no flag.

[Our view] The literal guard "resolve only when the honest write's read set contains no tainted version" can never fire. A head is a conflict only *because* its writer read something tainted (§4 forward taint). Below, the guard becomes: the only tainted versions the honest writer read are the suspect's own seed versions, and the plan reverts all of them.

## Decision

### 1. One rule, versioned: `ww_rebase` v1

A resolution **rebases** the honest write. It restores the object to its last clean version, re-runs the honest action on that clean state, and lands the result as **one** new version, in one gateway transaction. The honest edit is kept, recomputed on clean inputs. The suspect's edit is gone. Nothing is merged by hand and no value is invented.

The resolver is a pure pass inside the planner. It is on only when `RunConfig.resolver == "ww_rebase/1"`, which `ks run --resolver ww_rebase/1` sets. The contract default is `"off"`, so old run dirs, goldens and the F2+x "before" row stay byte-identical (§7). **The demo and the bench after-row run with it on and say so** (§7 label).

### 2. What the rule may resolve, and what always waits for a person

The rule looks only at `flag(write_write_conflict)` steps. For flag `(obj O, action H)` with suspect seed version `vC` (the highest seed version on O) and head `vH`, it resolves **only if every check passes**. Each check id goes into the resolution record as its rationale.

| id | Check (all from the record, plan-time) |
|---|---|
| `row_object` | O is a row object: `split_obj_id(O).field is None`. A conflict on a sensitive field object (e.g. `suppliers:S-17.iban`) always goes to a person |
| `single_honest_write` | `vH == vC + 1`: exactly one write after the suspect's, by H. Two or more later writers go to a person |
| `honest_deterministic` | H's agent is not in `llm_agents`, not the suspect, not in `root_candidates`, and not suspended at `as_of_seq` |
| `single_object` | H's record is `exec`. Its write set is exactly `{O}` (no other object, no `outbox:*`), it has no `outbox_ids`, and its args are in the side store and not redacted |
| `no_tainted_view_reads` | H's read set has **no** `source = view` entry of any tainted version (seed or not). Reason (kabir, S4-12 review): the re-run replays H's **original args**. A deterministic agent can copy a value from its view into its args (crm does this with price), and that would carry the suspect's value into the rebased write while every other check passes. Only tool reads are re-done on clean state, so only tool reads of seed versions may be tolerated |
| `seed_reads_only` | Every tainted `(obj, ver)` in H's read set (tool reads only, after `no_tainted_view_reads`) is a **seed** version on an object this plan restores, or on O itself. A read of any version derived from another agent's tainted work goes to a person |
| `clean_base` | The restore target exists and is not redacted: the last untainted version `vT < vC`. If the suspect created O (`to = None`), it goes to a person |
| `not_undone` | No executed `ks.recover.unresolve` names an earlier resolution of the same `(O, H)` (no ping-pong after a person undid it, §5) |
| `sim_clean` (dry-run) | In the rolled-back savepoint, with every plan restore applied and O set to value(`vT`), re-running H's tool and args (`ToolRerunner`, M14) has no error, writes exactly `{O}`, requests no outbox item, and reads no tainted version. Its after-hash becomes `rebased_hash` |

**Always a person, never the resolver:** every `flag` with another reason (`redacted_restore_source`, `no_compensator`, `tainted_i2`, `dispatched_tainted`, and any later reason); every `write_write_conflict` that fails any check above; every `replan` (LLM step); every `compensate`; every held item whose blocker is still a flag or replan after the pass; every blocked undo (`flag(unresolve_blocked)`, §5).

F2+x is expected to pass all checks. [Our view, from the code paths above; S4-13 must confirm it on the landed record]: O = `suppliers:S-22` (row), triage is the only writer after crm, triage is deterministic and outside root candidates, and `set_risk_note` writes only S-22. Its args come from the seed and the scenario (`_triage`: target and `review-NN` note), not from its view. Its only tainted read should be crm's seed v2 on S-22 through the **tool**. Triage's view scope is tickets only (`scenario.py`), so it should have no tainted view read. **Vikram must assert this in `test_f2x_resolved` (no view-source tainted read in triage's h+2 record).** If the assertion fails, F2+x stays flagged and we say so.

### 3. Plan shape (contracts 1.7.0, additive)

`src/ks/contracts/recovery.py`:
- `StepOp` adds `RESOLVE = "resolve"` and `UNRESOLVE = "unresolve"`. `Step` union adds `ResolveStep` and `UnresolveStep`. `ENVELOPE_OPS` (runtime) adds both. Plans without them parse and hash as before.
- **`ResolveStep(_Step)`**: `op: Literal["resolve"]`, `reason = "write_write_conflict"`, `rule: Token` (`"ww_rebase"`), `rule_version: int >= 1`, `obj: ObjId`, `culprit_ver: VersionRef` (vC), `expect: VersionRef` (vH, which must still be the head), `to: VersionRef` (vT), `rebased: ActionRef` (H's record), `rebased_hash: Hash` (from `sim_clean`), `unblocked: tuple[ob-id]` (sorted: held items whose only blocker was this flag and which now get a `rerun` step, so they go back on hold as `rerun_reheld`. **The resolution never releases an item itself.** Release stays approval-only, X4), `rationale: tuple[Token]` (the check ids that passed, in table order). It is a step of the same plan and the same `plan_hash`, so the `ks.approve` that lists its `n` is the approval it extends.
- **`RevertEntry(Value)`**: `obj`, `expect: VersionRef`, `to: VersionRef`.
- **`UnresolveStep(_Step)`**: `op: Literal["unresolve"]`, `reason = "resolution_reverted"`, `resolution: ActionRef` (the executed `ks.recover.resolve` record: seq, `ks.recovery`, action id `<plan_id>.<n>`), `resolution_plan_hash: Hash`, `reverts: tuple[RevertEntry]` (sorted by obj; the first is O back to `vH`), `reheld: tuple[ob-id]`, `rationale: tuple[Token]`.
- `rundir.py`: `RunConfig.resolver: Literal["off", "ww_rebase/1"] = additive("off")`, passed through `tcb_view()`. Verify reason `resolution_invalid -> Exit.TAMPER` in the reason/exit map. Hold reason token `resolution_reverted`.
- ADR-03 catalogue: `ks.recover.resolve` and `ks.recover.unresolve`, for `ks.recovery` on c-0 only. They are never class U.
- `CONTRACTS_VERSION = "1.7.0"`, schema regenerated, README rows, contract tests.

Step order becomes: cancel_outbox, restore, **resolve (by obj)**, rerun, compensate, replan, flag. `RecoveryPlan.needs_approval` is unchanged. `resolve` is in the default approval set (`approved_steps`), like `restore`. The person who approves the plan approves the resolution, and the dry-run shows it on its own line first.

### 4. Apply: one signed c-0 record per resolution

`ks.recover.resolve` runs through the B3-30 path (args, freeze, binding, `BEGIN IMMEDIATE`). In that one transaction:
1. M8 re-check (`conflict.recheck`): O's head must still be `expect` (vH). Otherwise `hold/stale_plan` and the apply halts, as for a restore.
2. A savepoint sets O to value(`vT`). `ToolRerunner` re-runs H's original tool and args (M14). The savepoint is then released into a **single** new version of O: author `ks.recovery`, action id `<plan_id>.<n>`, value = the re-run's value. If its hash is not `rebased_hash`, the step denies with `tool_error` and the apply halts. Nothing lands.
3. The record's read set = the re-run's tool reads, with O listed at `vT` (`source = tool`). That is the value it actually read. Its write set = `{O: before vH, after new}`.

There is one record and one version, so an apply can never halt halfway between "suspect edit removed" and "honest edit re-applied". After that, the planner treats O as repaired, so H's readers (F2+x: billing's S-22 invoice) get ordinary `rerun` steps and their items are re-held `rerun_reheld`. H itself gets no `rerun` step, because the resolve covers it.

`conflict.recheck` for later reruns already accepts this plan's own `ks.recovery` `<plan_id>.<n>` writes (B3-30), so it needs no change there.

### 5. Undo: `ks recover RUN --unresolve <plan_id>.<n>`

This builds a new plan `p-<seq>` (same `alert_id`, culprit and `taint_set` as the resolving plan, `as_of_seq` = now). It holds either one `UnresolveStep` or one `flag(unresolve_blocked)`. The operator approves it (`ks.approve`), and the gateway executes `ks.recover.unresolve` as a signed c-0 record. So the undo is itself recorded, approved and verifiable.

- **Reverts:** O goes back to `vH`'s value. So do the objects written by this plan's later `rerun` steps whose landed re-run record read O's rebased version, transitively through other such reruns. Each of those goes back to the version that rerun replaced. Each revert writes a new version (author `ks.recovery`, action id `<new plan_id>.0`), and its read entry lists the version it copied (`source = tool`). Taint therefore flows exactly as before the resolution.
- **Re-hold:** each item in `reheld` (the reverted reruns' items) gets a `ks.control` hold by `ks.recovery` with reason `resolution_reverted`. `bench_releasable` now looks at the **latest** hold Control of an item and releases only `rerun_reheld`, so a reverted item waits for a person.
- **Blocked** (gives `flag(unresolve_blocked)`, no envelope, counted in R): a record that is not a step of the resolving plan has read or written O or any revert object since the resolution; or any `reheld` item is released or dispatched. Our view: at that point an undo would have to chase effects that have already left. That is a person's call.
- After an undo, the flag is back. Any new plan for that alert keeps it as a flag (`not_undone`). **Undoing an undo is a person's job.** The rule never resolves that `(O, H)` again, and a person fixes it by hand, by a replan, or by accepting the flag in R.
- **Bench runs:** the bench approver releases `rerun_reheld` items at T (X4). After that, an unresolve almost always finds a released or dispatched `reheld` item and gives `flag(unresolve_blocked)`. That is by design. The full undo is a live or demo operation before release. Test: `test_unresolve_blocked_after_bench_release`.

### 6. Verify: `resolution_invalid` (TAMPER), new `verify/recovery.py::resolution_pass`

It runs after `recovery_pass`, so the binding to the approval and the plan file is already proven. Record edits, side-store edits and plan-file edits are already caught by the chain, `args_hash` and `recovery_unbound`. This pass catches a validly signed resolution that the rule does not support. That is the traceback Aarav asked for: verify names the failing check.

For each executed `ks.recover.resolve` record r with args a in plan P:
1. `(a.step.rule, a.step.rule_version)` is in `ks.recovery.resolver.RULES`.
2. Recompute: `resolver.eligible(records <= P.as_of_seq, P.taint_set, P.culprit, flag(O, H))` re-derives the record-only checks (every row of §2 except `sim_clean`) and the fields `culprit_ver`, `expect`, `to`, `rebased`, `unblocked`, `rationale`. Any mismatch fails with the first failing check id in the detail.
3. The landed record matches: exactly one write, on O, `before == expect`, `after.hash == rebased_hash`, author `ks.recovery`. Its read set contains `(O, to.ver)` and no version in `P.taint_set`. This is `sim_clean` proven on the record.
4. Order and replay: r.seq > P.as_of_seq. **At most one executed resolve per (`plan_id`, `n`)**, checked here as well as by `recovery_pass`. **No resolve of `(O, H)` after an executed unresolve of `(O, H)`** (in any plan: a replayed or re-planned resolution after an undo fails). Every restore step of P on an object named by `seed_reads_only` was executed **before** r. Every `rerun` step of P whose action is a reader of `vH` was executed **after** r. Otherwise it fails (out of order).

For each executed `ks.recover.unresolve` record u:
5. `resolution` names an executed resolve record with seq < u.seq and the same plan hash, and no earlier unresolve names it (one undo per resolution). `reverts[0] == (O, current-at-u, vH)`. Each other revert's `to` is the version the matching rerun replaced. Every `reheld` id has a `ks.control` hold by `ks.recovery` with reason `resolution_reverted` after u. Otherwise it fails.

**What verify does not do (TCB residual):** verify does not re-run H's tool. It checks that the landed write's hash equals the plan's `rebased_hash` and that the read set is clean, but it trusts that `ks.recovery`'s re-run computed that value from those reads. Reason: verify stays record-only and offline (ADR-02). `ToolRerunner` needs the world adapters and the side store at the right versions, and that is new verify surface three days before freeze. If the gateway's recovery code is wrong or compromised, it can sign a rebased value that a correct re-run would not produce, and verify would pass it. Proposed THREAT-MODEL row for kabir (S4-01/S4-23): "Resolver output: verify checks a resolution's rule, order, binding and clean inputs, not the re-computed value; the value is trusted to `ks.recovery` (TCB)." Post-finale: `ks verify --reexec-resolutions` re-runs it.

Tests: a forged rule id, a replayed resolve (same `plan_id`, `n`), a resolve after an unresolve of the same `(O, H)`, a re-signed resolve whose step claims a check that fails (e.g. H read a non-seed tainted version), a changed `rebased_hash`, a resolve before its restore, and an unresolve with no resolve or a second unresolve each give `resolution_invalid`.

### 7. Console, score, before/after

- **Dry-run / console plan lines** (`dryrun.render`, `console/model.py` plan step op): `resolve suppliers:S-22 (ww_rebase/1): crm v2 reverted, triage edit rebased on v1 -> <hash8>; unblocked ob-...; checks row_object,...; undo: ks recover RUN --unresolve p-....N`. When the rule refuses a flag, the flag line names the first failed check, e.g. `flag write_write_conflict suppliers:S-22 (resolver: single_honest_write failed)`, so a person sees why it waits. Unresolve shows `unresolve p-....N: S-22 back to v3, flag raised again; re-held ob-...`. The record lane shows the resolve and unresolve records by seq.
- **Label:** whenever `resolver != off`, the console header, dry-run header, `ks verify` summary and score.json print `resolver: ww_rebase/1 (on)`. With it off they print `resolver: off`. Abstract and Kit numbers from an after-row say "with resolver on" (D-19).
- **score.json** (`score/score.py`, additive keys): `resolver` (the RunConfig value), `resolver_label`, `ww_flags_before` (write-write flags before the pass = resolves + remaining ww flags), `ww_flags_after`, `resolutions: [{plan_id, n, seq, rule, obj, rebased_agent, unblocked, undone_by_seq | null}]`.
- **Bench:** run F2+x twice, with `resolver=off` (the B5 before-row, unchanged) and with `resolver=ww_rebase/1` (after-row). Both rows are reported (CALL-04: F2+x before and after). Under D-19 the abstract may use only the measured after-row numbers. Our view: we expect R to drop on F2+x, but that is not measured and not claimed until S4-13 runs.

### 8. Determinism

The rule is a pure function of (records <= `as_of_seq`, plan `taint_set`, `RunConfig.tcb_view()`, side-store values). It never reads `fault`, `culprit` or `fault_tick` (A3 AST guard covers `ks.recovery.resolver`). Flags are visited by obj order. `sim_clean` runs in the existing rolled-back savepoint. If `sim_clean` fails for any flag, the dry-run re-plans **once** with `no_resolve = {those objs}` and keeps them as flags. Same seed gives byte-identical `plans/**` and `score.json` (C4, T1/T1b).

## Build list for vikram (S4-13, <= 2 days)

Day 1
- `src/ks/contracts/recovery.py`: `StepOp`, `ResolveStep`, `RevertEntry`, `UnresolveStep`, `Step` union. `src/ks/contracts/rundir.py`: `RunConfig.resolver`, `resolution_invalid` exit map. `__init__.py` 1.7.0, `schema_gen.py` regen, `README.md`. Tests in `tests/contracts/`.
- `src/ks/recovery/resolver.py` (new): `RULE = ("ww_rebase", 1)`, `RULES`, `CHECKS` (table order), `eligible(ix, taint, culprit, root_candidates, llm_agents, flag, *, state) -> Eligibility(ok, passed, failed)`, `resolve_pass(flags, ix, taint, state, ...) -> (resolves, kept_flags, repaired_objs, covered_seqs)`.
- `src/ks/recovery/planner.py::plan_recovery`: new kwargs `resolver: str = "off"`, `no_resolve: frozenset = frozenset()`. Call `resolve_pass` right after the restore loop, before the rerun scan. Add resolved O to `repaired_objs` and `(O, vH)` to the repaired set, and drop H from riders/reruns. `Planned` gains `resolves` and `refused: dict[obj, check_id]`.
- `src/ks/recovery/dryrun.py`: simulate each resolve (`sim_clean`), fill `rebased_hash`, re-plan once on failure, render the resolve and refused-flag lines.

Day 2
- `ks run --resolver off|ww_rebase/1` in `src/ks/cli/__init__.py` and `src/ks/runtime/options.py`, which sets `RunConfig.resolver`. The demo script, the `make`/reproducer demo target, and `src/ks/bench/runner.py` (F2+x after-row) pass `ww_rebase/1`.
- `src/ks/recovery/conflict.py::recheck`: `ResolveStep` (head == `expect`) and `UnresolveStep` (each revert's `expect` is the head, no foreign read/write since the resolution).
- `src/ks/runtime/recover.py`: `ENVELOPE_OPS`, `approved_steps` (+resolve), `RecoveryService._resolve`, `_unresolve`, `_hold(..., reason)`, `bench_releasable` (latest hold decides), `cli_unresolve(run, ref)`. CLI flag `--unresolve` in `src/ks/cli/__init__.py`. Catalogue rows where `ks.recover.*` is admitted (`src/ks/gateway/system.py`, policy catalogue).
- `src/ks/verify/recovery.py::resolution_pass`, wired in `src/ks/verify/core.py`.
- `src/ks/score/score.py` keys; `src/ks/console/model.py` (+ `html.py` one line); `src/ks/bench/runner.py` F2+x with resolver on.
- Tests `tests/recovery/test_resolver.py`: `test_f2x_resolved` (one resolve, S-22 rebased hash == S\* S-22 hash, billing reruns, 0 ww flags), `test_f2x_resolver_off_unchanged` (B5 golden), one refusal test per check (including `test_refuse_view_copied_arg`: a deterministic writer whose args came from a tainted view value is refused by `no_tainted_view_reads`), `test_resolve_stale`, `test_unresolve_roundtrip` (state back to flagged, items `resolution_reverted`, bench approver leaves them held), `test_unresolve_blocked`, `test_unresolve_blocked_after_bench_release`, `test_no_reresolve_after_undo`, `test_resolver_deterministic`, `test_resolver_tcb_blind`. Verify tests in §6.

**Cut line if late:** ship resolve + verify 1–4 + score/console first. The undo can ship with only the blocked path (`flag(unresolve_blocked)` when any rerun read the rebased version), which still restores the flagged state for F2+x.

**Check before building:** confirm that no verify pass rejects a read entry at a non-head version (`(O, vT)` in step 4.3). If one does, list O at `vT` in the args instead and say so here.

## Consequences
- The honest edit is recomputed, not kept byte-for-byte. Its version is authored by `ks.recovery`, and the record names H as `rebased`. A person sees both.
- Conservative scope: only one-object, one-writer, deterministic, seed-only conflicts on rows. Everything else still counts in R, and the score shows it per check.
- New TCB code: the resolver and `resolution_pass`. The rebased value is trusted to `ks.recovery` (§6 residual). Kabir adds an RT row (forged resolution, S4-01).
