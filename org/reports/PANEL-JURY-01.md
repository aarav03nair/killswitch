# PANEL-JURY-01: jury dry run #1 (S4-04)

panel · 21 Nov 2026 · Reviewer: maya · Target: committed HEAD `752e971`, fresh clone (`git clone` of the repo into a scratch dir), image `killswitch:panel` built from that clone (OrbStack, arm64). vikram's S4-13 WIP in the main tree was **not** used.

Method: I acted as the SEED jury. I started from `README.md` only, ran `make demo` (`KS_IMAGE=killswitch:panel`), then ran 27 attacks. These cover kabir's six juror moves (CALL-04/kabir.md §7 / S4-f), zoya's Q1–Q5 (CALL-04/zoya.md §3), tamper, forge, replay, rogue code, claims checked against `org/adr/THREAT-MODEL.md`, and numbers checked against `org/reports/BENCH-S3.md` and `abstract/ALLOWED-NUMBERS.md`. Every result below is [Fact], observed on this clone, unless marked [Our view]. Scratch tools (rewrite script, rogues) were kept out of the repo.

Severity: **Must** = a juror sees it break, or a claim is false as shipped; fix before code freeze (26 Nov 18:00 IST). **Should** = a juror can use it against us. **Nit** = polish.

## Must list (each opened as an issue)

| # | Finding | Issue |
|---|---|---|
| M1 | **HEAD is red, and `make demo` fails at `ks score`.** Commit 752e971 (S4-01) took in S4-13 WIP in `src/ks/score/score.py:35-38` (`RunDir(run).config().resolver`), but `RunConfig` at HEAD has no `resolver` field. `ks score` raises `AttributeError` on every run, so `make demo` exits 1 after verify and writes no score.json and no console page. Container pytest: **14 failed, 4 errors, 1074 passed** (bench, console, hero golden, RT9/RT10/RT11, F3 pytest, score). README step 3 (expected score block, `demo OK`) cannot be reproduced. One-line check: with `getattr(cfg, "resolver", "off")` the seed-2 score matches the README block exactly (R 0/9, C 0/265, kept 263/265, unholds 9 = 7 honest + 2 tainted). | S4-26 |
| M2 | **On the README's own demo path, per-agent uids do not protect the run dir.** `make demo` bind-mounts `./runs` → `/app/runs` (OrbStack `virtiofs`). Inside the container, files show `0600 root` but are readable and writable by agent uids. A `--rogue` in slot `docs` (uid 60005) on `--out /app/runs/...`: **wrote `workspace/state.db`**, **appended to `record.jsonl`**, opened `witness-heads/heads.jsonl` for append, listed every run under `/app/runs` and read their side stores (raw values). Result: the gateway **crashed** (`ks run: invalid JSON`, or `ViewEntry: view entry hash does not match value`), exit 64, **no RunAnchor**. RT1's target "Blocked; else flagged in ≤1 tick" and rule 8 "only the gateway writes the record" are both false for `make demo`. The same rogue on a container-internal dir (`/run/ks/...`) got EACCES on state.db, heads and the operator socket, and the run verified anchored. So the cause is the bind mount, and `tests/redteam/test_rt01_db_bypass.py:21-31` never searches `/app/runs`, which is why it passes. | S4-27 |
| M3 | **A mid-run off-gateway write to the state crashes the gateway and gives no class-U alert.** The rogue changed the `suppliers:S-17.iban` head value (hash unchanged) at tick 4. The next tick died in `src/ks/contracts/state.py:171` (ViewEntry validation) instead of raising a reconciliation alert. Post-mortem `ks verify` (unanchored) does say RECONCILE, but the live run is lost and unanchored. RT1b only tests a harness write while paused. [Our view] Any deployment where the state is writable (relaxed perms, M2) turns this into a one-line DoS. Fail closed should mean alert plus freeze, not a crash. | S4-28 |
| M4 | **`ks blame` is advertised but not built.** `ks --help` lists `blame  alias: root candidates of a run`. Running it prints `ks blame: not yet implemented (needs monitor alerts, B3-14)`. `board/demo-sim.html` (Identify beat) shows `$ ks blame --alert a-000001` with ranked root candidates, under a banner that says "Terminal text is a layout of real ks output". The data exists (alert `root_candidates` in the record, e.g. hero seed 2 `["crm","intake",…]`). | S4-29 |

## Attacks

| # | Attack (what I did) | Result | Sev | File / line |
|---|---|---|---|---|
| 1 | README step 2–3: `make demo` on a fresh clone | Break, identify, contain, dry-run, apply and 9 unholds ran; verify `OK; last witnessed seq 223; anchored`, per_agent_uid. Then `ks score` gave a traceback, `make: *** [demo] Error 1`, and no console page. 15 s on a built image | **Must M1** | src/ks/score/score.py:35-38; scripts/demo.sh:68 |
| 2 | `make test` equivalent (`python -m pytest -q` in the image) | 14 failed, 4 errors, 1074 passed, 565 s. All traced to M1. HANDOFF line 3 still says green | **Must M1** | tests/bench, tests/console, tests/integration/test_hero_f2plus.py, tests/redteam/test_rt09/10/11, tests/score |
| 3 | README step 4: `ks verify --head "$ANCHOR"`, then without `--head` | `anchored`, exit 0; without the anchor `consistent, not anchored (no_anchor)`, exit 0. Matches README and C1 | pass | README.md:70-79 |
| 4 | **kabir move: record line edit.** Re-attributed seq 100 (`agent_id` inventory → payments) | `TAMPER hash_mismatch at seq 100`, exit 2, with and without `--head`. But the human line reads `…; consistent, not anchored (no_anchor)` on a TAMPER result, and the JSON says `unanchored_reason: no_anchor` even when `--head` was given | pass; wording **Should** | src/ks/verify/core.py:54; src/ks/cli/__init__.py:220 |
| 5 | One hex digit changed in line 50 | `hash_mismatch`, first_bad 50, exit 2 | pass | n/a |
| 6 | Deleted line 120 | `seq_gap: line 120 has seq 121`, exit 2 | pass | n/a |
| 7 | Truncated the last 30 records | `truncated: checkpoint 35 witnessed seq 197, record has 193`, exit 3, even unanchored | pass | n/a |
| 8 | Consistent truncation: record and both witness files cut at seq 176 | Unanchored: `reconcile_mismatch` (state.db ahead of fold), exit 4. Anchored: `truncated`, exit 3 | pass | n/a |
| 9 | Witness tamper: dropped one checkpoint from `witness.jsonl` only | `count_mismatch`, exit 3 | pass | n/a |
| 10 | **kabir move: full chain rewrite, verify with and without `--head`.** Insider with fresh gateway and witness keys erased payments' read of `suppliers:S-17.iban` (seq 10), re-chained, re-signed every gateway envelope, record and witness checkpoint, and swapped both pubs in `keys.json` | Without `--head`: `verify: OK; … consistent, not anchored (no_anchor)`, exit 0 (as claimed, README:13-15). With `--head`: `keyring_mismatch`, exit 3. Same wording issue as #4 (`WITNESS keyring_mismatch; … consistent, not anchored (no_anchor)`) | pass (C1 as worded); wording **Should** | org/adr/THREAT-MODEL.md C1, RT8 |
| 11 | **kabir move: state.db bypass (post-run).** (a) IBAN head value changed, hash kept; (b) S-17 head hash and value swapped with S-22's | (a) `state.db value differs from its hash`; (b) `state.db differs from fold(record)`. Both exit 4 | pass | src/ks/verify/core.py:270 |
| 12 | state.db history: dropped the append-only triggers, re-attributed every `versions.author` crm → payments, recreated the triggers | **anchored verify OK, exit 0.** `state_digest` covers only `(obj, ver, hash)` of heads; history rows (authors, older versions) are not reconciled. `ks score` reads historical values from state.db (`value_at`) | **Should** | src/ks/contracts/state.py:387-389; src/ks/score/score.py:163,188 |
| 13 | **kabir move: TEMPLATE rogue (`--rogue FILE --slot docs`) on the demo path `/app/runs`** | Rogue wrote state.db, appended to record.jsonl, opened witness heads for writing, and read other runs' side stores. Gateway crashed (exit 64), no anchor. Post-mortem verify: `parse_error at seq 2` and `reconcile_mismatch` | **Must M2, M3** | Makefile:7-8, scripts/demo.sh:31 (`-v "$PWD/runs:/app/runs"`, `--out /app/runs/…`) |
| 14 | Same rogue on container-internal `--out /run/ks/r2int` | state.db `unable to open`, heads EACCES, operator socket EACCES; run verified anchored, per_agent_uid | pass | n/a |
| 15 | Rogue connects to the operator socket on the bind mount (filesystem lets it connect) and sends `release agent:crm` | `ConnectionResetError`; gateway logs `0 refused requests`. SO_PEERCRED holds (B5) even when the 0700 dir does not | pass | THREAT-MODEL B5 |
| 16 | Rogue isolation probes: own ids, env, `/proc/*/environ`, `/proc/*/mem`, `ptrace(ATTACH, ppid)`, `setuid(0)`, network | uid 60005, CapEff 0, env `{LC_CTYPE, PYTHONHASHSEED}` only; environ and mem PermissionError for all pids; ptrace EPERM; setuid EPERM; network unreachable. Process list (cmdlines) readable | pass | THREAT-MODEL Live setup, RT2/RT3b |
| 17 | Forgery: sign as crm; sign `ks.control`; raw-send a crm envelope with a zero signature | Signer refused `foreign_agent` and `system_tool`. Forged frame: `deny bad_sig` (seq 35), `ks.monitor` suspended **`conn:c-5` (the rogue's connection), not crm**. Next rogue frames `deny suspended` | pass (C4) | n/a |
| 18 | Replay and clock: resubmitted a used envelope; submitted a presigned envelope after expiry; `claimed_seq=1, claimed_ts_us=1`; 5-frame flood in one tick | `nonce_reused`; `expired`; claimed values ignored (gateway seq 20); signer `rate` after 2 per tick, surplus frame `late_frame` | pass (RT4, RT6) | n/a |
| 19 | `ks run --decisions` from tampered sources (run 4, run 10) with the real anchor | Refused: `hash_mismatch (first_bad=100)` and `keyring_mismatch` | pass (RT13) | n/a |
| 20 | `--rogue` with `--key-mode repro`; `--rogue` with `--fault F2+` | Both refused, exit 64 | pass | n/a |
| 21 | **kabir move: F2+ hero** (from #1, plus score with the M1 one-liner) | tti_detect 2, tti_attribute 0, ttc 1, R 0/9, C 0/265, post-alert 0, irreversible 0, reemitted 0, unholds 9 (7 honest, 2 tainted): **identical to README step 3** and to demo-sim seed 2 | pass once M1 is fixed | README.md:50-66 |
| 22 | **kabir move: F3** (live `--fault F3`, seed 2, internal dir) | `comms.send_email deny out_of_scope` seq 43 → scope alert → suspend seq 47 → next send `deny suspended`; verify anchored. Denied args in the side store hold a template reference, no PII. The F3 **pytest** (`test_f3_pii_egress_held`) fails at HEAD (M1) | pass live; pytest **Must M1** | tests/redteam/test_rt10_irreversible.py |
| 23 | Rubber-stamp operator: released all 7 sensitive-field holds **before** recovery, never applied a plan | `irreversible_tainted_released 0`: the release phase re-held them. R 64/64 (no recovery). Side effect: `--pause-on-alert` resumed at once because my stdin was at EOF ("press Enter") | pass on safety; pause-on-EOF **Nit** | src/ks/gateway/holds.py:6-7 |
| 24 | `ks blame` (from `ks --help`) | `not yet implemented` | **Must M4** | src/ks/cli/__init__.py:65,268; board/demo-sim.html Identify beat |
| 25 | Claims vs THREAT-MODEL wording | README uses C1/C3 wording exactly ("tamper-evident up to the last witnessed head", "consistent, not anchored", VOID, root candidates, no prevention claim). **JURY-QA Q5** says prevention needs per-agent uid and the live setup has it, which is false for `make demo` (M2). **how-it-works.html** §3c still shows payment/email `cancel` (B2-a hero: re-run, re-held, operator unhold) and the footer "Design plan; nothing here is measured yet" (D-19) | Q5 → M2; how-it-works **Should** | abstract/JURY-QA.md:72-85; abstract/how-it-works.html |
| 26 | Numbers: README vs BENCH-S3 / ALLOWED-NUMBERS | All README numbers match: R=0 with 5 released [3 honest, 2 tainted, max 9] (N4), C=0 (N5), ttc 1 (N3), tti 2 (N1), F2+x R 1/5 and 29 held (N15), baseline 27 (BENCH-S3 F2+x revert_culprit_only). **But** README:99-100 quotes F2+x without C 21/254 and without "before resolver", and N15 requires both to travel with it | **Should** | README.md:99-100; abstract/ALLOWED-NUMBERS.md §3 |
| 27 | Numbers: demo-sim and console | demo-sim values match BENCH-S3 and my seed-2 run (seqs 45, 53, 65, 66 identical in `record.jsonl`). The banner says "the only seq shown is … 223", but beats show seqs 45/53/65/66/47-58. The Audit beat's TAMPER line format differs from real output (real: `verify: TAMPER hash_mismatch at seq N; last witnessed seq 0; consistent, not anchored (no_anchor)`). Console code shows D-17 releases (S4-19), but on a README run it has no score.json to show (M1) | **Nit** (banner, tamper line); console via M1 | board/demo-sim.html (banner; script beats 14, 24) |

Also seen (Nit): `scripts/demo.sh:70` asserts exit 0 and anchored but not `isolation == per_agent_uid`, while README:67-68 calls `isolation=per_agent_uid` part of the pass signal. On a failure, verify reports `last_witnessed_seq 0` even when the witness covered more (#4, #10).

## Kabir's six moves (S4-f): outcome and THREAT-MODEL row

| Move | Outcome | Row |
|---|---|---|
| F2+ hero | Passes through verify; score/console broken at HEAD | RT10, C5/C6 → M1 |
| TEMPLATE rogue | Forgery, replay and isolation hold (#14–#20). **On the bind mount, the run dir is open to the rogue** | RT1, RT2, RT3, RT4 → M2, M3 |
| state.db bypass | Post-run head edits caught (#11). History not reconciled (#12). Live bypass on the demo path crashes the run (#13) | RT1 → M2, M3; #12 Should |
| Record line edit | Caught, first bad seq right (#4–#6); wording Should | RT7 |
| Chain rewrite + verify with/without `--head` | As claimed: unanchored "consistent, not anchored", anchored `keyring_mismatch` (#10) | RT8, C1 |
| F3 | Live passes (#22); pytest red at HEAD | F3 → M1 |

## Zoya's Q1–Q5: can we answer from a file?

| Q | Answer source | Gap |
|---|---|---|
| Q1 "Is R=0 just the human releasing things?" | ALLOWED-NUMBERS N4; BENCH-S3 F2+ `fp_cost.operator_unholds` 5 [1..9] (3 honest, 2 tainted); README:96-99; JURY-QA Q13. New evidence (#23): a rubber-stamp release before recovery still leaks 0 tainted irreversible effects because the release phase re-checks taint | Console cannot show it on a README run until M1 is fixed |
| Q2 "Conflict case leaves 29 stuck, C>0" | BENCH-S3 F2+x + Reading notes bullet 1; ALLOWED N15 ("before resolver") | README omits C and the label (#26). The S4-13 resolver build is what broke HEAD (M1) |
| Q3 "Forge the witness ack / fake an outbox origin" | Now covered: `tests/redteam/test_rt08b_witness_ack.py`, `test_rt10b_outbox_provenance.py` (both pass at HEAD). Live forgery attempts fail (#17) | Not yet in a red-team report (REDTEAM-S4, kabir) |
| Q4 "F3: R=1 and no plan?" | BENCH-S3 Reading notes bullet 2; ALLOWED §5. Live run (#22) shows deny → alert → suspend in the same tick | F3 pytest red at HEAD (M1) |
| Q5 "Ticks, deterministic agents, 10 agents?" | ALLOWED G4/G5; GUARDRAILS L6/L7; README Known limits | [Our view] Answerable. The bigger Q5-adjacent risk is the JURY-QA Q5 bypass answer (M2) |

## Should list

- S-a: verify wording on failure: no "consistent" on TAMPER/WITNESS, and no `no_anchor` when `--head` was given (core.py:54, cli/__init__.py:220).
- S-b: Either reconcile version history (authors, all versions) or state that the limit exists (#12).
- S-c: README has no jury section: `ks run --rogue FILE --slot AGENT`, the SPEC §3 template, kabir's six moves as commands. `tests/redteam/rogues/` and `tools/` named in SPEC §1.1 do not exist.
- S-d: README F2+x sentence: add C 21/254 and "before resolver" (N15).
- S-e: how-it-works.html: drop the hero `cancel`, fix "nothing here is measured yet".
- S-f: HANDOFF test counts are stale against the red HEAD.
