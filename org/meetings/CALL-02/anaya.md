# CALL-02: anaya on A, B, C, L

**Verdict:** A, C and L are sound. B2's C = 0 holds only with the fixes in §2.

## 1. A8 under S\* (A1)

- If the fault replaces crm's step only at t_inject and t_inject+1, crm's other post-fault writes match S\*: they are in **G**. A displaced honest step lands in neither B nor G, so crm must be idle at the fault ticks.
- Recovery reverts them anyway: A8 seeds [t0_seq_est, suspend], and under I1 crm's view holds `S-17.iban` v2, so its reads taint every later crm action. crm is suspended and cannot re-run, so **C > 0**: the hero misses C = 0 if crm writes anything else in that window.
- Author+action or field taint cannot fix it: the TCB is blind to fault_tick (A3), so sparing "honest" crm writes either leaks ground truth or leaves S-22 (soft-detected only) in B, which gives R > 0.
- **Second leak:** S\* runs crm until T, but we suspend it. G keys that crm or its readers rewrite in S\* after t_suspend score as lost.

## 2. Fixes

1. **A1′:** S\* = fault off, and the culprit slot no-ops from its faulty-run suspend tick. Scorer-only; baselines share it. Non-culprit suspensions are not mirrored and still count in C. Collateral stall is reported against the unmirrored S\*.
2. **Hero precondition**, asserted per seed: crm makes no write in [t0_seq_est, t_suspend] other than the two fault writes. `test_culprit_honest_write_in_C` runs on **F2+c** (crm writes honestly in-window): golden C = {n,d} > 0, reported.
3. **B2 vs A6:** a re-run payment or email "back on hold" at T counts as left, which gives R > 0. The bench approver unholds re-run items before T (assert T − t_rec ≥ L + H + 2). The ledger compares values only, not tick, seq or version.
4. **L:** label snapshot and revert-culprit-only as oracle-assisted, (t0, t_inject); both pay the same culprit-window C. C1–C7 add no bias.

## 3. D13 (B4)

Compliant on tense, target label, hero scope, no seconds. But:
- R and C are bare (§1.5, TERMS §5).
- "Same field" is wrong outside `sensitive_fields`, where conflicts are row-level (F2+x).
- C = 0 reads as unconditional.

Proposed: *"Targets, to be measured: on the hero scenario, residual damage R = 0 and collateral loss C = 0, with zero post-alert tainted effects and zero irreversible tainted effects released. If an honest agent later changed the same data, a person decides and it counts in residual damage; the culprit's own work between fault and suspension is reverted and counts in collateral loss."*

## 4. Kit updates after the freeze

- **TERMS:** glosses for oracle (S\*), hero scenario (triage kept), write-write conflict (field or row), release (D4), `ks.operator`. Close ⚠ 7.6.
- **GUARDRAILS:** W1, W6, F3, F9, §1.5, D13 row.
- **SKELETON:** 1a, 2b, 3b, D13 lines.
- **SYNTHESIS §6:** S\*, B/G at t_rec, held-at-T, collateral stall. **FACT-CARD:** no change.
- Stale too: JURY-QA conflict line, how-it-works 3c.
