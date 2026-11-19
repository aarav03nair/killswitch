# ADR-05: Versioned state, taint, write-write conflict rule, deduped re-run

**Owner:** vikram · **Reviewer:** maya · **Status:** in review (Call #2 freeze applied) · **Inputs:** CALL-01, CALL-02 (+ resolutions), maya review, CON-02, RES-01/02/06

## Context
Snapshots clobber honest work; revert and sagas cannot see readers (RES-06, RES-02). Recovery restores only what it can prove, re-runs deterministic readers without re-firing effects, hands LLM steps to a person (RES-01), and never edits history.

## Decision
**1. Store (`ks.state`, own SQLite, D5).** `workspace/state.db`, 0700, gateway-owned.
- `objects(obj PK, head_ver, head_hash, head_value)`; append-only `versions(obj, ver, hash, author, seq, action_id)`, old values in the side store. `put` runs in the gateway's execution txn; `heads()` feeds `state_digest`.
- **Objects (B1, X1).** Row `table:pk`; each `RunConfig.sensitive_fields` entry is its own object `table:pk.field` (field `[a-z][a-z0-9_]{0,63}`). OBJ_ID_RE unchanged. `make_obj_id` rejects `.` in a pk; C3 adds `field_obj_id`, `row_obj_id`, and `split_obj_id → (table, pk, field|None)`.
- `put` raises if a row value carries a sensitive key, so each datum lives in one object. Row create/delete writes/tombstones its field objects; a null field is a tombstone. **Actions write only changed objects; a field-only edit does not bump the row.**

**2. Conventions.** `ver` from 1, +1 per write; `seq` global and gap-free; one write per object per action. (a) Delete writes a tombstone; a re-create continues the counter. (b) Restore writes a **new** version (`author=ks.recovery`); taint keys on `(obj, ver)`, never hash. (c) A version written at seq *s* is visible only to seq > *s* (M2: view snapshotted after the control phase), so one forward pass is exact.

**3. Read rule (I1, X2).** A record's read set is everything it delivered:
- its recorded reads **plus every `TickFrame.view` entry of that tick** (gateway-captured), so crm's `crm.update_supplier` record carries `tickets:T-3`;
- a whole-row read (`<table>.read`, aggregate, view row) records the row **and its existing field objects**; aggregates enumerate rows;
- a projection without the field records the row only; any read returning a sensitive value lists its field object. Triage's view scope lists `suppliers:S-17`, not `.iban`.

**4. Forward taint.**
- **Seed (A8, X3).** Every after-version written by `root_candidates[0]` with `t0_seq_est ≤ seq ≤ suspend_seq`. `t0_seq_est` is that agent's earliest write in the bounded backward closure (§5) of all alerts' `evidence_versions`. The planner reads only `RunConfig.tcb_view()`; `fault`, `culprit` and `fault_tick` are never read (A3, AST guard). No suspended suspect gives no seed and no plan.
- Scan in seq order: a record whose read set hits a tainted `(obj, ver)` is tainted, and its after-versions and `outbox_ids` join the set (D8).
- **Conservative by default.** Whole-row and aggregate reads over-taint; an LLM agent stays tainted for its later actions. `--optimistic` drops stickiness and reports the difference.

**5. Backward taint and ranking (H1, matches ADR-04/M9).**
- `root_candidates[0]` = the attributed agent of the record(s) that wrote `evidence_versions` (write_set lookup). Two or more distinct writers, or none, means no suspect.
- Then a backward walk through read sets to earlier writers, **bounded** to `MAX_HOPS = 3` and stopping at tick-0 seed data. Candidates rank by hop distance, then latest causal write, then tainted descendants, then `agent_id`. Old seed ancestors cannot rank first. A laundered write names writer and planter; agents reached only via reads are never auto-suspended (ADR-04).

**6. Plan builder (`ks.recovery`, C5), per object.**
1. `cancel_outbox` for tainted `queued`/`held` items whose creating action is not re-run.
2. `restore` per object with `expect` = the culprit's after-version (B6); `to` = last untainted version. A head written by someone else's tainted action gives **`flag(write_write_conflict)`** and no restore; there is no restore over a tainted head (M13 dropped). An untainted head (honest blind write) is kept. A redacted `to` gives `flag`.
3. `rerun`, in seq order, for tainted honest deterministic actions whose reads are clean by then; otherwise the action rides with the flag. **Mechanics (M14):** re-execute the original tool and args (side store, ARGS) for `action.agent_id/action_id`; idempotency keys derive from those, not the recovery envelope; `OutboxItem.author` stays the original agent; redacted args give `flag`. The outbox dedupes on key:
   - held/queued item: v+1 of the **same** `outbox:<id>`, status `queued`, `release_tick = tick + hold_window_ticks`, `lineage` = the rerun's recorded read set;
   - dispatched item: nothing emitted; if the simulated payload hash differs, `flag(dispatched_tainted)`, scored in R.
4. `compensate` for landed tainted class C effects (approval).
5. `replan` for tainted LLM actions, for console approval (D4).
6. Tainted I2 or dispatched I1 effects become `flag` report entries.

Untainted writes on a restored row (triage's `risk_note`) get no step; the diff marks them **kept** (B3).

**7. Dry-run.** `ks recover --dry-run` restores and simulates every re-run in a **rolled-back savepoint**, in seq order. It writes `plans/<id>.json` with `as_of_seq`, `plan_hash` and a hash-only diff from the simulation. `replan` gets no DiffEntry. Same seed gives a byte-identical plan.

**8. Apply.**
- `ks recover` (dry-run or apply) runs `verify` first. **FROZEN if verify ≠ OK or a tamper/witness-stall alert is open in the chained `ks.alert` records**; the freeze lasts for the rest of the run (M12, F5).
- Apply requires a `ks.approve{plan_id, plan_hash, steps}` record (G6). Each step is a signed `ks.recover.<op>` envelope from `ks.recovery` on `c-0`, carrying `{plan_hash, n}`, for `op ∈ {cancel_outbox, restore, rerun, compensate}`. These ops are in the ADR-03 catalogue for `ks.recovery` only, so they are never class U. `flag` and `replan` create no envelope.
- The gateway re-checks in the same txn: freeze gives `deny/recovery_frozen` and `Exit.FROZEN`; no matching approval gives deny; `expect` no longer the head gives **`hold/stale_plan`** (M8).
- **Apply halts at the first stale step.** Applied steps stay (append-only); the console gets a new plan with `as_of_seq` = now.

## Consequences
- Over-taint costs re-runs and replans (`replan_cost`).
- **The culprit's own post-fault writes are reverted by design.** Their readers re-run and are re-held, counted in C (`c_culprit_window`), never as released effects. Hero C = 0 holds only under the X3b precondition (crm writes nothing in (t_inject+1, suspend]); F2+c reports C > 0. In S\* the culprit stops from its suspension tick (X3a).
- Conflicts on non-sensitive rows go to a person and count in R (F2+x). No field merge beyond sensitive fields.
- Re-run items held at T are released by the bench approver; the ledger compares values (X4).
- Snapshot and revert-culprit-only baselines are **oracle-assisted** (given t0). Revert-culprit-only runs per object: it spares triage and fails with R > 0 (X5).
- A read missed by adapters and the view under-taints.

## Interface touched
- **C3:** id helpers, pk validator, sensitive-key invariant, M11. **C5:** `t0_seq_est`, B6 `expect`, M14, approval binding. **C2:** view in read sets, `STALE_PLAN`. **C4:** M9. **C6:** `tcb_view()`, `Exit.FROZEN`, `plans/`. **Transport:** `TickFrame.view`. **ADR-03:** `ks.recover.<op>` rows.

## Tests that prove it
- **`test_hero_f2plus_golden` (F2+, X3b precondition guarded by `test_hero_no_culprit_write_in_window`):** seed = {`S-17.iban` v2, `S-22` v2}. Plan restores both; re-runs billing, payments (same `outbox:<id>`, v+1, back on hold), comms and reporter; **triage's `risk_note` edit is kept with no step and 0 flags**. R = 0, C = 0, both tainted-effect metrics 0, `reemitted == 0`.
- **`test_triage_conflict` (F2+x):** triage edits `S-22`. No restore of S-22, exactly one `flag(write_write_conflict, S-22, triage)`, R > 0; the IBAN is still restored. An honest write between dry-run and apply gives `hold/stale_plan`, apply halts, and a new plan has a later `as_of_seq`.
- **`test_culprit_honest_write_in_C` (F2+c):** crm's honest window write is reverted; readers re-run and stay held; counted in C and `c_culprit_window`; 0 released.
- **`test_no_double_payment`:** hold > 0: one payment per key, S\* payload, author payments; hold = 0: `flag(dispatched_tainted)` in R; double apply adds 0.
- **`test_root_candidates` (RT9):** intake plants `tickets:T-3`, crm writes the IBAN: `[crm, intake]`, inventory and docs absent. **`test_root_candidates_bounded`:** crm's read set also holds an older supplier version by a third agent; intake stays top 3.
- **`test_t0_est_tcb_blind`:** changing `fault_tick`/`culprit` leaves the plan byte-identical; AST guard.
- Also: `test_crm_record_reads_T3`, `test_row_read_includes_field_objects`, `test_triage_view_excludes_iban`, `test_field_obj_id_roundtrip`, `test_pk_dot_rejected`, `test_sensitive_field_object`, `test_field_only_update_keeps_row_ver`, `test_same_tick_visibility`, `test_restore_expect_head`, `test_rerun_original_keys`, `test_dryrun_savepoint`, `test_recover_bound_to_approval`, `test_recover_catalogue`, `test_baseline_revert_culprit_per_object`, `test_conservative_taint`, `test_append_only`, `test_plan_golden`.
- **`test_frozen`:** an open tamper alert or a dead-dir edit (verify ≠ OK) gives FROZEN until run end.

## Amendments (Call #2)
- **X1/B1:** field-level objects for sensitive fields end to end: ids, store, taint, planner, baseline (§1, §6).
- **X2/I1:** read rule; view entries join the read set (§3; maya 1).
- **X3/A8/A2:** seed = culprit writes in [`t0_seq_est`, suspend]; `t0_seq_est` from the bounded walk, never RunConfig (§4; maya 10). F2+c and `c_culprit_window` added.
- **H1:** rank 0 = evidence writer; bounded walk (§5; maya 2). RT9 → `[crm, intake]` (maya 3).
- **B2/B6:** hero has no flag, triage kept; restore only over the culprit's head; M13 dropped. Supersedes maya 4 (B).
- **B5:** honest conflict moved to F2+x. **M14:** re-run mechanics (maya 5). Dry-run savepoint simulation (maya 6). Halt at first stale step, `hold/stale_plan` (maya 7, M8).
- **G6:** `ks.recover.<op>` catalogue and approval binding (maya 8). Freeze on verify ≠ OK, run-long (maya 9, M12).
- **X4/X5:** held-at-T release; oracle-assisted per-object baselines.
- **B3-16/F7 (tara):** aggregate and scan reads list every live row read plus its existing field objects (`Store.read_table`, `docs.write`; `tests/world/test_aggregate_reads.py`). A scan that finds nothing records **no read**: absence reads are deferred to 2.0 (v1 limitation, `test_scan_that_finds_nothing_records_no_read`). Also `Store.read_table` skips deleted rows (tombstones): a row deleted before a scan goes unrecorded and is never repaired. A point read of a deleted row does record it. No v1 adapter calls `read_table`, so no F-scenario hits this.
