# ADR-05: Versioned state, taint, write-write conflict rule, deduped re-run

**Owner:** vikram · **Reviewer:** maya · **Status:** in review · **Inputs:** CALL-01 (D4, D5, D8), PANEL-ENG-00 §1.3, CON-01, RES-01/02/06, SYNTHESIS §4.8–9, §6

## Context
Snapshots clobber honest work; Dolt/Git revert and sagas cannot see readers (RES-06, RES-02). Recovery must restore only what it can prove, re-run deterministic readers without re-firing effects, hand LLM steps to a person (RES-01), and never edit history.

## Decision
**1. Store (`ks.state`, own SQLite, D5).** `workspace/state.db`, 0700, gateway-owned:
- `objects(obj PK, head_ver, head_hash, head_value)`: live state.
- `versions(obj, ver, hash, author, seq, action_id, PK(obj,ver), UNIQUE(obj,seq))`: history, hashes only. Old values live in the redactable side store (rule 9). Triggers abort UPDATE/DELETE.
- `put` runs inside the gateway's execution transaction. `heads()` feeds `state_digest`, which reconciliation compares with fold(record).

**2. Conventions.** Maya's are confirmed: `ver` starts at 1 and goes +1 per write; `seq` is global and gap-free, covering every record kind; an action writes an object at most once. Three amendments:
- (a) Delete writes a tombstone. A re-create continues the counter, so `before=None` means the object never existed.
- (b) Restore writes a **new** version (`author=ks.recovery`). Taint keys on `(obj, ver)`, never on hash.
- (c) A version written at seq *s* is visible only to records with seq > *s*, so one forward pass is exact.

**3. Forward taint.** The seed is every after-version written by records where `attributed_agent == culprit` and `seq ≥ t0_seq`. t0 defaults to the culprit's first action reaching `evidence_versions`.
- Scan records in seq order. A record is tainted if its recorded `read_set` hits a tainted `(obj, ver)`; its after-versions and `outbox_ids` then join the set. Lineage comes from recorded reads only (D8).
- **Conservative by default (Taser).** Aggregate and `SELECT *` reads record every row scanned. An LLM agent stays tainted for all its later actions, because its context carries what it read. `--optimistic` drops that stickiness and reports the difference.

**4. Backward taint (used by ADR-04 `attribute()`).** From `evidence_versions`, walk back through writing records and their read sets to earlier writers. Root candidates are the attributed agents reached. They are ranked by earliest causal write, then by tainted descendants. A laundered write names both the planter and the writer; we claim nothing stronger.

**5. Plan builder (`ks.recovery`, C5).** Steps run in this order:
1. `cancel_outbox` for tainted `queued`/`held` items whose creating action is not re-run.
2. `restore` only if the head is still the culprit's after-version (`expect`); `to` is the last untainted version. If someone else's tainted write is the head, emit **`flag(write_write_conflict)`** and do not restore. A redacted `to` value also gives `flag`.
3. `rerun`, in seq order, for tainted honest actions of deterministic tools, provided every object they read is clean by then. Otherwise the action rides with the flag. The outbox dedupes on `idempotency_key`:
   - A held item gets v+1 of the **same** `outbox:<id>` and re-enters the hold, so there is one item per key.
   - For a dispatched item nothing is emitted. If the payload differs, emit `flag(dispatched_tainted)`, scored as residual.
4. `compensate` for landed tainted class C effects. Needs approval.
5. `replan` for tainted LLM actions, queued for console approval (D4).
6. Tainted I2 or dispatched I1 effects become `flag` entries in the report.

The determinism flag and the compensators come from the scenario tool registry.

**6. Execution.** `ks recover --dry-run` writes `plans/<id>.json` with `as_of_seq` and a hash-only diff. The console approves it by `content_hash`. `--apply` submits each step as a signed, recorded `ks.recover.<op>` envelope from `ks.recovery`, carrying `{plan_hash, n}` (rule 10). In the same transaction the gateway re-checks two things:
- A tamper alert is open: `deny/recovery_frozen`, `Exit.FROZEN`.
- `expect` is no longer the head: `hold/needs_approval`, then recompute.

Recovery only appends.

## Consequences
- Over-taint costs re-runs and replans; it is reported as `replan_cost`.
- Conflicts and escaped I-class effects go to people and count in R. There is no field merge.
- An honest blind write leaves a clean head, which is kept without redo.
- A read that adapters miss means under-taint.

## Interface touched
- **C3:** implements `StateView`/`StateWriter`; amendments (a)–(c), no field change.
- **C5:** produces `RecoveryPlan`/`TaintSet`.
- **C2:** reads read/write sets, `outbox_ids`, `attributed_agent`.
- **C4:** reads `evidence_versions` and tamper state; feeds `root_candidates`.
- **C6:** `Exit.FROZEN`, `plans/`.
- Optional ask: a `stale_plan` hold reason.

## Tests that prove it
- **`test_triage_conflict` (F2+):** crm writes `suppliers:S-17` v2; triage reads v2 and writes v3.
  - The plan has no restore of S-17, and exactly one `flag(write_write_conflict, S-17, triage)`.
  - After apply, v3 is kept and crm's other objects are restored as new versions.
  - An honest write between dry-run and apply makes that restore `hold/needs_approval`.
- **`test_no_double_payment`:**
  - Hold > 0: billing and payments are re-run, `effects.jsonl` holds one payment per key with the S\* payload, and `reemitted == 0`.
  - Hold = 0: the re-run emits nothing, `flag(dispatched_tainted)` counts in R, and `reemitted == 0`.
  - Applying twice adds 0 effects.
- **`test_root_candidates` (RT9):** crm plants `tickets:T-3` and comms writes the IBAN from it. Result: `[crm, comms]`, with inventory and docs absent.
- **`test_conservative_taint`:** the aggregate reporter is tainted, and so is an LLM agent's later unrelated action; `--optimistic` lists the difference.
- **`test_append_only`:** UPDATE on `versions` aborts. After apply, `state_digest(heads) == fold(record)`, and a restored version has `ver = n+1` and `hash == to.hash`.
- **`test_frozen`:** an open tamper alert gives FROZEN and `recovery_frozen`.
- **`test_plan_golden`:** same seed, byte-identical plan.
