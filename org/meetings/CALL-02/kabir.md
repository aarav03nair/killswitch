# CALL-02 · kabir (Security) · freeze check

## Blockers
- **B1 resolved:** F1, F2, checklist C2/C6.
- **B2 resolved:** C3, C4, C5, E4, with condition R4.
- **B3 resolved:** D1, D2, D3, D4.
- **B4 resolved:** checklist C1, G7.

## Fix-before-S4
- **F1 partial:** it appears only as "RunDir K7" in checklist C6, with no owner or test. Give maya `test_rundir_perms_agent_eacces`.
- **F2 resolved:** E1, E3, checklist C2, RT3c.
- **F3 resolved:** checklist C2, D1.
- **F4 partial:** G4 defines the record. Verify's window check (no hold, seed or suspend in (created_seq, dispatched_seq) without an unhold) is unowned; give it to arjun.
- **F5 resolved:** G6. See R3.
- **F6 partial:** under F5 the freeze comes from records, but TTI still reads the unsigned alerts.jsonl. Score should take alert ticks from records, and verify should add `alert_mismatch`.
- **F7 resolved** (doc option), via checklist C3. Needs `test_aggregate_enumerates_rows`, field objects included.
- **F8 resolved:** I accept the deferral if the gateway reads at most one frame (≤ MAX_FRAME_BYTES+1) per connection per tick and keeps no read-ahead queue. Test: `test_flood_backpressure`.

**ADR-01 M1–M6, ADR-02 M1–M8, ADR-03 M1–M8:** all resolved, except that G2 scopes writes only (R2).

## Holes the freeze opens
- **R1, field objects:** `OBJ_ID_RE` still allows `.` in pks, and nothing enforces "no `.`". An agent-chosen pk `C-1.email` (`crm.upsert_customer`) would collide with a field object. *Fix (C3, v1.1):* a validator rejects `.` in pks, and a `.suffix` must name a `sensitive_fields` entry for that table.
- **R2, field objects:** the row object's value hash must exclude sensitive fields. Any read that returns one (`<table>.read`, a view entry, an aggregate) must list the field object. Otherwise payments' lineage shows only `suppliers:S-17` and both holds miss the IBAN (RT10). Test: `test_row_read_lists_field_obj`. G2 has no read scope, so any role can read IBANs and PII. *Fix:* read scope equals the I1 view scope; anything else is `out_of_scope`.
- **R3, replayed decisions (C1):** `--decisions RUN` re-signs Controls from an editable run dir as `ks.operator`, so approvals, releases and revokes happen without the operator. *Fix:* the source must pass anchored `verify --head`. Replay only operator-signed Controls. An approval with a `plan_hash` mismatch is `STALE_PLAN`. Put `decisions_from` in config, refuse it with `--rogue`.
- **R4, repro mode (C3):** the gateway derives the witness key, so C1 does not hold. *Fix:* `key_mode=repro` ⇒ `VerifyReport.anchored=false` (`repro_keys`). Enforce the ban in code: repro plus `--rogue` gives `Exit.USAGE`, and the RT2/RT8 fixtures assert fresh mode.
- **R5, ks.operator and c-0:** remove `ks.console` from `SYSTEM_PRINCIPALS` with no alias (ids.py still has it), including the revoke issuer. c-0 envelopes are still signature-verified, and system agent_id ⇔ c-0, checked both ways. Operator frames reach c-0 only through J1's peercred socket.

## Sign-off
**I will sign CON-01/v1.1** once the checklist lands with the B1–B4 tests (`test_count_chain`, RT8(h), `test_fresh_keys_differ`, `test_epoch_monotonic`, RT4, `test_depth_6kb_denied`) plus R1 and R4, which are contract-level. R2, R3, R5, F1, F4, F6 and F8 are fix-before-S4 and do not block signing.
