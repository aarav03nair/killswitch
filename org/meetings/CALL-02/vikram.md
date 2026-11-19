# CALL-02 · vikram (ADR-05)

**B(3) is clean.** Store, taint and planner are object-generic and unchanged. New: id helpers, one store invariant, one read rule (+0.5 day).

## 1. Ids (C3)
- Forms: row `table:pk`; field `table:pk.field`, with field `[a-z][a-z0-9_]{0,63}`. OBJ_ID_RE is unchanged.
- `make_obj_id` rejects `.` in pk, so the split is unambiguous. World pks are dot-free.
- New `field_obj_id(table, pk, field)` and `row_obj_id(obj)`.
- `split_obj_id` returns `(table, pk, field|None)`.

## 2. Store
- `put` raises if a row value carries a sensitive key, so each datum lives in exactly one object.
- Row create/delete writes/tombstones its field objects; a null field is a tombstone.
- **Writes touch only changed objects, with no row metadata bump on a field edit.** Otherwise crm's swap bumps `suppliers:S-17` and taints triage again.

## 3. Row vs field reads
A read records every object it delivered.
- **Whole-row reads** record the row **plus every existing field object of that row**: `<table>.read`, aggregates, view rows. Conservative.
- **A projection without the field** records the row only. Examples: triage's `set_risk_note` and triage's view.
- Triage's view scope lists `suppliers:S-17`, not `.iban` (tara, nisha).

## 4. Taint and planner
- Hero seed: {`S-17.iban` v2, `S-22` v2}. Triage read only the clean row, so it is kept with no step.
- Restore is per object, with expect = crm's after-version. F2+x still conflicts on `S-22`.
- The *revert-culprit-only* baseline must also run on objects. It then spares triage; its failure is R>0.

## 5. Culprit's honest writes (A8)
**The record cannot tell them apart.**
- The fault lives in the agent. Tool, args, reads and timing are all rogue-chosen, so any "looks honest" filter can be mimicked to keep a bad write alive (R).
- A "bad value" seed needs an oracle, and detectors are partial: price ×10 trips only a soft detector, so an evidence-only seed drops `S-22`.
- Injected ids break A3.

**Rule:**
- seed = every write by `root_candidates[0]` with `t0_seq_est ≤ seq ≤ suspend_seq`
- `t0_seq_est` = that agent's earliest write in the bounded backward closure of all alerts' `evidence_versions`
- never reads RunConfig

Consequences:
- Readers of a reverted honest write rerun, and the changed payloads are re-held. They count in C, never as released effects.
- **B2's C=0 needs crm to write nothing in (t_inject+1, suspend].** crm applies bank-update tickets, so this is not automatic. Tara's guard `test_hero_no_culprit_write_in_window` enforces it, and `test_culprit_honest_write_in_C` covers a variant.
- The scorer reports `c_culprit_window` from the ledger.
- ⚑ D13 must add: "the culprit's own post-fault writes are reverted by design".

## 6. Tests
New: `test_field_obj_id_roundtrip`, `test_pk_dot_rejected`, `test_sensitive_field_object`, `test_field_only_update_keeps_row_ver`, `test_row_read_includes_field_objects`, `test_triage_view_excludes_iban`. `test_triage_conflict` → F2+x; `test_root_candidates` → [crm, intake].

## 7. Build days
| Module | Days |
|---|---|
| state | 1.5 |
| helpers | 0.5 |
| taint | 1.5 |
| planner, including savepoint rerun simulation | 3 |
| apply | 1.5 |
| tests | 1.5 |
| **Total** | **9.5** |

Critical path: rerun simulation, needing ADR-03 adapters and the I1 view.
