# Call #4 input: kabir (Security & Red-Team Lead)

Sources: HANDOFF.md, org/adr/THREAT-MODEL.md (SEC-01 v4 + errata), tests/redteam/SPEC.md, B3-35 review, org/reports/BENCH-S3.md, S4-01, README.md, board/demo-sim.html, src/ks/score/score.py.

## 1. Open security items, ranked by jury risk (what a hostile juror tries first)
| # | Juror move | What breaks | State |
|---|---|---|---|
| 1 | Runs the rogue template on a laptop (native macOS) or in repro mode | Attribution is VOID natively; repro is "not a security run". If the finale box is not the container, every RT3/RT3b claim falls | Guarded in code (repro refused with `--rogue`); no finale preflight gate yet |
| 2 | Rogue computes its 2nd bad write from its **view** of its 1st (not a tool read) | 1st write falls outside the t0 seed and is not reverted (errata B3-45). Dry-run prints `t0_delta`, but no RT asserts that warning | Known limit, untested |
| 3 | Rewrites the whole chain, runs `ks verify` **without** `--head` | Passes as "consistent, not anchored" (RT8 g). Only a break if we demo unanchored or keep the anchor in the run dir | Covered by RT8; a demo-discipline risk |
| 4 | "Who released those 5 held items?" | R=0 depends on operator releases (median 5: 3 honest, 2 tainted). F2+x: R 1/5, 29 honest items held | D-17 wording; demo-sim omits it (§3) |
| 5 | Toggles hold 0 and compares with our slide | Demo-sim shows 1 tainted payment; bench D10 shows median 12 (6-18, 20/20 seeds). Mismatch reads as fabrication | Fix in demo polish |
| 6 | Pytest F3 (PII email) | `inv.pii_egress` never fires in a run: scope suspends first. Only cc/bcc unit tests prove the detector | S4-01 |
| 7 | Reads `score.json` with no containment | `ttc` is `null` (score.py:219), not `{unavailable: reason}` | S4-01 |
| 8 | Asks "which test fails if you delete X?" | Witness ack sig check off: **0 tests fail**. Outbox provenance off: only gateway unit tests fail, no RT | S4-01. Agent can't reach the witness link (path-less socketpair, witness uid) |
| 9 | Splits payments under thresholds / colludes | No RT, no claim (C3) | Say so up front |

## 2. Known limits we state up front (exact THREAT-MODEL wording, nothing stronger)
- C1: "tamper-evident up to the last witnessed head"; Unanchored verify is "consistent, not anchored". No Merkle proofs.
- C2: "enforced in production (uid/container), detected here by reconciliation".
- "If per-agent uids fail, per-agent attribution is void for that run". Repro mode "is **not a security run**".
- C3: backward taint names **root candidates**; **no prevention claim**.
- C5: holds act on the **recorded** read set; "Effects released before the alert: at hold window 0 they are scored as residual damage (D10)". Errata B3-41: "C5 holds only on the **recorded** read set".
- C6 refuses "Undoing released external effects".
- Errata B3-45: "We do not claim the seed contains every bad write of the suspect."
- Semantic influence: "taint tracks data exposure, not meaning; we **over-taint**".
- D13: "All pass values are **targets, not results**"; measured values only in the Sprint 4 red-team report.
- D-17: every R=0 states the operator releases.

## 3. Overclaims in README / demo
- **demo-sim.html** b:4/score: "R 0/6" with no operator-release clause (breaks D-17); denominator 6 vs bench /5; hold-0 shows "released 1 · R 1/6" vs measured median 12 tainted payments. Replace with BENCH-S3 values, labelled measured, with seeds.
- demo-sim b:3 "an outbox that never sends twice": say "re-emitted 0 in 20/20 seeds".
- demo-sim b:5 "rewrites the whole file; verify ... catches it": true only with `--head` and the anchor kept off the run dir. Say both.
- README: stale note says `scripts/demo.sh` runs the skeleton (it runs the hero path). No link to THREAT-MODEL known limits. No R=0 operator-release wording.

## 4. Sprint 4 security issues I want
| Id | Title | Owner / reviewer | Acceptance (testable) |
|---|---|---|---|
| S4-01 | Red-team gaps: forged witness ack, outbox provenance RT, ttc unavailable | kabir / panel | As filed, plus: a bad-sig or mismatched ack makes `WitnessLink.push` return None and leaves `newest` unchanged; disabling link.py:103 fails it |
| S4-a | RT14: view-sourced seed gap is surfaced | tara / kabir | Rogue crm builds write 2 from its view of write 1; dry-run prints `t0_seq_est_literal` and `t0_delta != 0`; deleting the warning fails the test |
| S4-b | Mutation gate for every defence | kabir / panel | Script disables each listed defence (epoch fence, pii_egress, dispatcher re-check, outbox provenance, witness ack sig, deny-list in txn, SO_PEERCRED); each kills >=1 `tests/redteam` test in the container; table in report |
| S4-c | Red-team report with measured values (D13) | kabir / panel | `org/reports/REDTEAM-S4.md`: every RT row has measured value, commit, seeds, raw path; no number without a raw file |
| S4-d | Finale preflight: refuse a non-security live run | maya / kabir | Finale script aborts unless `make smoke` gives `isolation=per_agent_uid`, `anchored=true`, `key_mode=fresh`; test: native run puts VOID in console banner and `score.json` |
| S4-e | Claim audit of README, demo-sim, console | pmo (assign) / kabir | Every number traces to a BENCH-S3 row; every R=0 has the operator-release clause; grep for "never", "proof", "first", "guarantee" finds no unrefused use |
| S4-f | Panel hostile-juror dry run | panel / kabir | Each §7 move (F2+, TEMPLATE rogue, state.db bypass, line edit, rewrite + `--head`, F3) logged with outcome and THREAT-MODEL row; any break opens an issue the same day |

Order: S4-d and S4-e first (cheap, highest jury risk), then S4-01, S4-a, S4-b, S4-c last (needs the rest). All before code freeze 26 Nov 18:00 IST.
