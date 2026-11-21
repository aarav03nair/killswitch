# PANEL-JURY-02: jury dry run #2, re-attack of the fixed build (S4-09)

panel · 21 Nov 2026 · Reviewer: maya · Target: HEAD `1b9a743` (pushed), fresh `git clone` into a scratch dir, image `killswitch:panel` built from that clone (OrbStack, arm64, 11 CPUs). One ks run at a time; `docker ps` was empty before each run (no tara bench). Host 1-min load was 2.4–6.1 during the session; the finale preflight saw 2.39–2.65 (0.22–0.24 per CPU) and passed its own host check.

Note: while this ran, other agents had uncommitted edits in the main tree (README, demo-sim, console, JURY-QA, FACT-CARD, REDTEAM-S4). They are not in this review; every result is on committed `1b9a743`. (S4-30 was taken by anaya during the run, so new issues are S4-31..34.)

Method: as in #1. Start from `README.md`, then re-try every #1 attack, then attack what is new since #1: the D-18 resolver, `make finale`, `ks blame`, the console scorecard, and every number in README, `board/demo-sim.html` and `abstract/ALLOWED-NUMBERS.md` checked against `org/reports/BENCH-S3.md`. Everything below is [Fact], observed on this clone, unless marked [Our view]. Scratch tools (rogue, F2+x driver) stayed outside the repo.

Severity as in #1: **Must** = a juror sees it break, or a claim is false as shipped; fix before code freeze (26 Nov 18:00 IST). **Should** = a juror can use it against us. **Nit** = polish.

## 1. #1 Musts: closed?

| #1 | Re-test | Verdict |
|---|---|---|
| M1 (S4-26) HEAD red, `make demo` fails at `ks score` | `KS_IMAGE=killswitch:panel make demo`: 15.4 s, verify `OK; last witnessed seq 223; anchored`, score block identical to README step 3 (tti_detect 2, tti_attribute 0, ttc 1, R 0/9, C 0/265, post-alert 0, irreversible 0, reemitted 0, kept 263/265, false accusations 0), `demo OK (anchored, isolation=per_agent_uid)`, console page written. Container suite: **1152 passed, 3 skipped**, 856 s | **Closed.** (S4-26 is still `in_review` on the board; this re-test is evidence for its reviewer.) |
| M2 (S4-27) bind mount ignores per-agent perms | Rogue (`docs`, uid 60005) on the demo path `/work/runs/r1`, with a second run `/work/runs/other` in the same container: `glob('/work/runs/*')` returns `[]` (cannot even list), so no state.db, record, heads or side-store access; run anchored. RT16 covers it | **Closed** on the README path. Known limit stays as written in README Troubleshooting: a hand-run `ks run --out /app/runs/...` (bind mount) is still open to every agent uid (re-shown: the same rogue read the side store of every run dir under `./runs`, opened record and heads for append, and edited state.db in other copied-out runs) |
| M3 (S4-28) mid-run off-gateway state edit crashes the gateway | Same rogue on the bind mount (writable state, the only way to reach it now) changed the `suppliers:S-17.iban` head value at tick 4: chained `ks.alert` seq 13 tick 4, detector `reconcile`, hard, `root_candidates []`, nobody suspended, run exit 0 with a RunAnchor; post-run verify `RECONCILE reconcile_mismatch` (value does not hash to 751189fd…) | **Closed.** |
| M4 (S4-29) `ks blame` not built | `ks blame RUN` on the hero: alert a-000001, root candidates 1. crm 2. intake 3. triage, suspect crm t0 45 suspended 66, taint 6 versions / 6 actions / 2 outbox: **identical** to the demo-sim Identify beat. Unknown alert: exit 1. Tampered record (seq 100 re-attributed): refuses, `UNVERIFIED RECORD`, exit 2 | **Closed** as built. New Must M5 below on what blame says about VOID and unanchored runs |

## 2. New Must list (issues opened)

| # | Finding | Issue |
|---|---|---|
| M5 | **`ks blame` names a culprit on a VOID run and never says "not anchored".** Native macOS run (`ks run --scenario world --fault F2+ --seed 2`, isolation degraded): `ks verify` prints `isolation degraded: per-agent attribution VOID for this run`, but `ks blame` prints `1. crm 2. intake 3. triage` and `suspect crm`, exit 0, with no VOID line. THREAT-MODEL Live setup: "If per-agent uids fail, per-agent attribution is void for that run" (RT3b). Blame also only runs unanchored verify (`src/ks/cli/__init__.py:287`, no `--head` flag), so it prints its ranking as fact on a run whose verify result is only "consistent, not anchored" (C1). [Our view, from #1 attack 10 + that line] a full chain rewrite with fresh keys passes unanchored verify, so blame would name whatever the rewritten record says, with no caveat | S4-31 |
| M6 | **Verify still says "consistent" on a failure, and "no_anchor" when an anchor was given.** #1 S-a, unfixed. `ks verify --head ANCHOR` on a record with seq 100 edited: `verify: TAMPER hash_mismatch at seq 100; last witnessed seq 0; consistent, not anchored (no_anchor)`; JSON `unanchored_reason: no_anchor`, `last_witnessed_seq: 0`. Same on RECONCILE with `--head`: `RECONCILE reconcile_mismatch; last witnessed seq 38; consistent, not anchored (no_anchor)`. Escalated to Must: this is the finale Audit beat (juror edits a line), the line contradicts C1 wording ("consistent" on a TAMPER), and demo-sim shows a cleaned-up line that the real tool does not print (`src/ks/cli/__init__.py:227`, `src/ks/verify/core.py:54-58`) | S4-32 |
| M7 | **`ks score` reads unverified state.db history, so a run that verifies anchored can be re-scored.** On a copy of the hero run: drop the append-only triggers, `UPDATE versions SET author='payments' WHERE author='crm'` (4 rows), recreate triggers. `ks verify --head ANCHOR`: **OK, anchored**. `ks score`: **R 0/9 → 2/11**, t0 11 → 12, exposure 3 → 2, `clean` unavailable → false. Cause: the real-run effect ledger is built from `store.history(obj)` authors (`src/ks/oracle/realrun.py:50-82`), and verify reconciles only `(obj, ver, hash)` of heads (`state_digest`, `src/ks/contracts/state.py:387-389`). #1 attack 12 found the unreconciled history (Should); this shows it moves the headline number | S4-33 |
| M8 | **"Undoable" is not true on the live F2+x path.** F2+x seed 2, `--resolver ww_rebase/1`, `--pause-on-alert`: dry-run shows `resolve suppliers:S-22 (ww_rebase/1) … undo: ks recover RUN --unresolve p-000066.1`, apply lands it (seq 69). At the very next operator moment (paused before tick 15, nothing released yet) `ks recover --unresolve p-000066.1` gives `unresolve_blocked: seq 76 (billing) touched suppliers:S-22 after the resolution (a person decides)`. Seq 76 is billing's own tick-14 `draft_invoice`, reading S-22 v4 (the rebased version) in the same tick as the apply. ADR-05a §5 expects blocking only after bench release; live, the undo can never be issued. ALLOWED-NUMBERS N18(d), FACT-CARD and JURY-QA call every resolution "undoable", and N18 is on the list Aarav may cite in the abstract due **22 Nov** | S4-34 |

## 3. Attacks this round

| # | Attack | Result | Sev | File / line |
|---|---|---|---|---|
| 1 | README step 2–3 `make demo` | Works (see M1). README's expected block omits two lines the demo now prints: `fault: F2+  resolver: ww_rebase/1 (on)` and `run validity: OK (headline-eligible): …` | pass; **Nit** | README.md:50-66 |
| 2 | Container pytest | 1152 passed, 3 skipped | pass | n/a |
| 3 | Record line edit (seq 100 agent re-attributed), with `--head` | Caught: TAMPER, first_bad 100, exit 2. Wording wrong | pass; **Must M6** | cli/__init__.py:227 |
| 4 | Rogue on the demo path (container fs) | Cannot list `/work/runs` | pass (M2) | n/a |
| 5 | Rogue on a bind-mounted `--out` (by hand, against README advice) | Reads every run's side store, opens record/heads for append, edits other runs' state.db; its own run alerts `reconcile` in the same tick and anchors | M3 pass; bind mount = stated limit | README Troubleshooting |
| 6 | state.db history re-attribution | verify anchored OK, score changes | **Must M7** | oracle/realrun.py:50-82 |
| 7 | `ks blame` on hero, unknown alert, tampered record | Correct; refuses tampered | pass | n/a |
| 8 | `ks blame` on a VOID (native) run | Names crm, exit 0, no VOID | **Must M5** | cli/__init__.py:279-325 |
| 9 | **Resolver, live F2+x:** dry-run, apply | `ww_flags_before 1, ww_flags_after 0`, resolve on S-22 with all 8 check ids, billing/comms/payments re-run, 2 re-held. Finale F2+x run: R 0/9, C 0/265, verify anchored, `resolver: ww_rebase/1 (on)` on verify and score | pass | n/a |
| 10 | **Resolver: replay** the applied plan (`--apply p-000066` again) | Step denied `nonce_reused` (seq 82), apply halts. But a second `ks.approve` (seq 81) is recorded as **exec ok** first | pass; **Nit** (dangling approval record) | runtime/recover.py `cli_apply` |
| 11 | **Resolver: undo** before any release | Blocked at once by an honest read in the apply tick | **Must M8** | ADR-05a §5; recovery/resolver.py `plan_unresolve` |
| 12 | Resolver: applying the blocked undo plan | `applied: 0 steps recorded`; the resolution stays | pass | n/a |
| 13 | **Resolver: get a culprit write kept** | Not reachable from a juror seat: `--rogue` and `--fault` are mutually exclusive (`runtime/options.py:53`), so no rogue can be the rebased writer in F2+x. crm is the suspect and `root_candidates[0]`, both refused. What is left is the stated limit (THREAT-MODEL D-18 entry: colluding agent outside the refused set; verify trusts the rebased value) | stated limit | THREAT-MODEL line 90 |
| 14 | Forge/alter a resolution post-run | Not re-run by hand; the plan file and args are bound by `plan_hash`/`args_hash`, and `resolution_invalid` tests exist (`tests/recovery/test_resolver.py`, `tests/contracts/test_contracts_17.py`) and pass in the container | pass (tests) | n/a |
| 15 | `ks recover` while the run is **not** paused (after the apply resumes) | `FROZEN: verify truncated at seq 87` / `reconcile_mismatch at seq None` with the text "M12: no recovery for the rest of this run". It is a torn read of a live run: final verify is OK, anchored, no tamper alert, and a later `--unresolve` call in the same run built a plan. The message is false and alarming on stage | **Should** | cli/__init__.py:355-367; runtime/recover.py:673 |
| 16 | `make finale` (`IMAGE=killswitch:panel`) | Host check, smoke (anchored, per_agent_uid, fresh, 0 misses), hero F2+ and F2+x (resolver on) all validity OK; `finale preflight OK`, exit 0 | pass | scripts/finale.sh |
| 17 | **Degraded run as headline (1):** `ks run --fault F2+ --tick-deadline-ms 2` | Validity `DEGRADED, NOT THE HEADLINE … deadline misses: 30`, exit 1; finale would stop (exit 3). But `ks verify --head` says `OK; anchored` for it | pass (finale) | ks/validity.py |
| 18 | **Degraded run as headline (2):** same run, set every `missed` to `[]` in `timing.jsonl` | Validity flips to `OK (headline-eligible)`; `ks score` prints the OK line; verify still anchored. `timing.jsonl` is outside the chain and the witness (rundir.py:18 "the ONLY non-deterministic file") | **Should** | ks/validity.py `_misses` |
| 19 | **Degraded run as headline (3):** `make demo` (not finale) on a degraded run | `scripts/demo.sh:78` asserts only `exit == 0 and anchored`, so it prints `demo OK (anchored, …)` whatever the validity verdict; it still does not assert `isolation == per_agent_uid` (#1 Nit). Only `make finale` blocks | **Should** | scripts/demo.sh:78 |
| 20 | Console scorecard on the hero | Shows R 0/9, C 0/265, the D-17 release line ("operator released 9 held item(s): 7 honest, 2 tainted"), `resolver: ww_rebase/1 (on)`, validity OK. But (a) its verify banner reads `not anchored (no_anchor)` on the anchored hero, because `ks console` has no `--head` and demo.sh does not pass one; (b) the row **"clean recovery"** reads `unavailable (invariants_ok not computed (needs the world supplier master))` on every run: `invariants_ok` is never computed (score.py:396-404), so "clean" (ADR-06: R=0, C=0 and invariants_ok) can never be true. "Clean recovery" is one of the three things the jury scores | **Should** (b: needs a maya decision: compute invariants_ok, or drop/relabel the row) | console/html.py:41; score/score.py:396 |
| 21 | Claims: THREAT-MODEL vs README / JURY-QA | README limits use C1/C3 wording; THREAT-MODEL now has the D-18 limits (verify trusts the rebased value; collusion). JURY-QA Q5 still says "prevention needs per-agent uid"; now true on the demo path (M2 closed) | pass | n/a |
| 22 | `abstract/how-it-works.html` | Still shows hero `cancel` (lines 295, 300) and the footer "Design plan; nothing here is measured yet" (#1 S-e). New stale line: footnote "if an honest agent changed the same data (bench case F2+x), it is flagged to a person", which is the resolver-off row only | **Should** | abstract/how-it-works.html:295-313 |
| 23 | `ks recover --dry-run` on a copied-out evidence dir | Writes `plans/p-000223.json` into the evidence copy (verify still OK) | **Nit** | runtime/recover.py |

## 4. Numbers check (README, demo-sim, ALLOWED-NUMBERS vs BENCH-S3)

| Where | Value | BENCH-S3 | Verdict |
|---|---|---|---|
| README:96-99 | R=0 after median 5 releases (3 honest, 2 tainted; max 9), C=0, reemitted 0, TTI 2, TTC 1 | F2+ H=6 system: R 0 [0..0], unholds 5 [1..9], 3 [0..7], 2 [1..2], C 0, reemitted 0, tti 2 [0..2], ttc 1 [1..1] | match |
| README:99-100 | F2+x R 1/5, 29 honest held, baseline 27 | F2+x H=6: R 1/5, held 29 [0..35], revert_culprit_only 27 | values match. **Should** (#1 S-d, unfixed and worse): no C 21/254, no "before resolver" label (ALLOWED N15 requires both), and README never says the demo now runs `resolver: ww_rebase/1 (on)` by default (demo.sh:15) |
| README step 3 | seed-2 score block | my run and both finale runs | match |
| demo-sim | R 0 (seed 2 0/9), C 0 (0/265), snapshot R 3/5 [0..7/9], C 34/263, revert-culprit-only R 3/5 [0..7/9] C 0, post-alert 0 / 1 [0..1] / 0, releases 5 [1..9] (3, 2), seed 2: 9 (7 honest), kept 263/265, D10 12 [6..18] vs 0 | BENCH-S3 F2+ H=6 and CONTRAST; my run | match. Blame layout matches real output exactly. Audit TAMPER line is still a layout the real tool does not print (see M6) |
| ALLOWED N1–N17 | each cell | BENCH-S3 | match (checked every cell) |
| ALLOWED N18 | R 0 [0..0], C 0 [0..0], held 3 [0..7], releases 5 [1..9] (3 [0..7], 2 [1..2]), 1 resolution on 19/20 seeds (s7: 0), verify OK on 40 runs | BENCH-S3 §S4-13 | values match. Condition (d) "undoable" is false live (M8). [Our view] A juror will notice the after-row equals the F2+ hero row cell for cell (R, C, held 3 [0..7], releases 5 [1..9], kept 263/265); the true answer is that with S-22 rebased the F2+x run converges on the F2+ plan, and `ww_flags_before 1` on 19/20 shows the conflict was there. Put that one line in JURY-QA |

## 5. Should list

- S-1 (#1 S-a escalated to M6).
- S-2 Console verify banner "not anchored" on the anchored hero; add `--head` to `ks console` or pass the anchor from demo.sh (#20a).
- S-3 "clean recovery: unavailable" on the console scorecard: maya decision (#20b).
- S-4 `make demo` says `demo OK` regardless of validity and isolation (#19).
- S-5 Validity from unwitnessed `timing.jsonl` (#18): count deadline misses in the record or a witnessed line, or state "self-reported" next to the verdict.
- S-6 Spurious FROZEN on an unpaused live run, with a false "rest of this run" message (#15).
- S-7 README F2+x sentence and resolver default (#1 S-d) (§4).
- S-8 how-it-works.html (#1 S-e plus the F2+x footnote) (#22).
- S-9 README jury section (`--rogue FILE --slot AGENT`, the SPEC §3 template, kabir's six moves); `tests/redteam/rogues/` and `tools/` named in SPEC §1.1 still do not exist (#1 S-c, unfixed).
- S-10 HANDOFF still dated 20 Nov with 820 passed (#1 S-f).

Route S-2, S-4, S-7, S-8, S-9 into kabir's claim audit (S4-23).

## 6. Nits

README expected block missing the resolver and validity lines (#1). Replayed apply records a second executed `ks.approve` (#10). Dry-run on a copied-out run writes into the evidence (#23). demo-sim banner/tamper layout (#1 attack 27, unchanged).
