# Call #2: Design freeze

**Date:** 19 Nov 2026 (IST) · **Chair:** Claude (PMO) · **Attendees:** Maya (architect, drafted resolutions), Kabir, Anaya, Vikram, The Panel (via reviews) · **Product Owner:** Aarav (⚑ = needs his confirmation)
**Inputs:** all 8 ADR reviews, org/reports/SEC-03.md, org/reports/CON-02-requests.md, CALL-02/{resolutions,kabir,anaya,vikram}.md

## Outcome
**`CALL-02/resolutions.md` is adopted as the binding design, with the amendments below.** Every ADR owner applies their items (assignment table in resolutions.md). Contracts move to **v1.1.0 (CON-02)**. Kabir signs once his checklist tests land.

## Amendments agreed on the call

| # | Topic | Raised by | Amendment |
|---|---|---|---|
| X1 | Field objects: pk collision | Kabir R1 | C3 validator rejects `.` in a pk; new `field_obj_id`/`row_obj_id`; `split_obj_id` → (table, pk, field\|None) |
| X2 | Field objects: reads | Kabir R2, Vikram | A whole-row read (row read, aggregate, row in the view) reads that row's field objects too. A read that omits the field reads only the row. Any read returning a sensitive value lists its field object. Field-only edits do not bump the row. Triage's view scope lists `suppliers:S-17`, not `.iban` |
| X3 | Culprit's honest writes (the C = 0 question) | Anaya, Vikram | The record cannot tell them apart, and the TCB must not learn `fault_tick`. Adopted: **(a)** in S\*, the culprit also stops acting from the tick it was suspended in the faulty run; collateral stall is reported separately. **(b)** Per-seed hero precondition, enforced by a guard test: crm writes nothing else in (t_inject+1, suspend]. **(c)** New bench variant **F2+c**, where crm does honest work in that window: golden C > 0, reported honestly. **(d)** Scorer splits out `c_culprit_window`. Taint seed stays A8, with `t0_seq_est` from the bounded backward walk over alert evidence; RunConfig is never read |
| X4 | Re-run items still held at T | Anaya | The bench approver releases re-run items before T, and the effect ledger compares values (not statuses). Otherwise a correctly re-held payment would count as residual damage |
| X5 | Baselines | Anaya | Snapshot and revert-culprit-only baselines are labelled **oracle-assisted** (they are given t0). Revert-culprit-only works per object |
| X6 | Replayed decisions | Kabir R3 | `--decisions RUN` requires the source run to pass `verify --head`, approvals must match `plan_hash`, and it is refused with `--rogue` |
| X7 | Repro mode | Kabir R4 | Repro forces `anchored=false`. Repro + `--rogue` is refused in code and the run is labelled "not a security run". `ks.console` is removed from ids.py with no alias; system agent_id ⇔ c-0 is checked in both directions |
| X8 | Open SEC-03 items | Kabir | F1 (RunDir file modes 0600/0700, agents cannot read record or side store) → **maya** in CON-02. F4 (verify window check) → **arjun**. F6: TTI is computed from chained `ks.alert` records, never from unsigned alerts.jsonl → **tara/arjun** |
| X9 | Estimate | Vikram | ks.state/taint/recovery: 9.5 build days. The critical path is re-run simulation, which waits on ADR-03 adapters + I1 view. We start the build now (ahead of the 25 Nov prototyping window) to absorb this |

## Hero result (resolution B, option 3): field-level objects for sensitive fields ⚑
- Each `RunConfig.sensitive_fields` entry is its own versioned object `table:pk.field`; generic, no IBAN-specific code.
- The demo shows the plan restoring the IBAN and the ×10 price, and re-running billing, payments (same outbox item, held again), comms and reporter. Triage's edit to the same supplier is in a "kept" lane, with no flags.
- An honest flagged conflict lives in bench variant **F2+x** (triage edits the non-sensitive row crm wrote → write-write flag → R > 0, shown in Jury Q&A).

## Revised D13 target wording for the abstract ⚑
> Targets, to be measured: on the hero scenario, residual damage R = 0 and collateral loss C = 0, with zero post-alert tainted effects and zero irreversible tainted effects released. If an honest agent later changed the same data, a person decides and it counts in residual damage; the culprit's own work between fault and suspension is reverted and counts in collateral loss.

(This is the *meaning* Aarav's abstract must stay within. He words it himself.)

## Follow-ups
- **CON-02** contracts v1.1.0 (maya), the critical path. Then SKEL-01.
- **ADR revisions** (all 8 owners) per the assignment table + X1–X9, as amendment sections. Each reviewer re-checks only their must-fixes.
- **Kit updates** (zoya, anaya, ishaan): TERMS, GUARDRAILS (W1, W6, F3, F9, §1.5, D13 row), SKELETON (1a, 2b, 3b), SYNTHESIS §6, JURY-QA conflict line, how-it-works 3c (triage now *kept*, not flagged).
- **Sprint 3 (build)** opens as soon as CON-02 lands.

## Dissent recorded
- None blocking. Anaya notes that C = 0 on the hero depends on the precondition in X3b; F2+c exists so we never hide that.
