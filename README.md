# Project Kill Switch

Authenticated provenance, containment and taint-scoped revert for multi-agent shared state
(SEED Hackathon 2026, track 3). Agents act through a gateway; every action is recorded and
witnessed, and `ks verify` checks a run directory offline.

## Known limits (read first)

- **Native macOS is degraded isolation.** Outside a container, per-agent uids are unavailable, so
  per-agent attribution is **VOID** for that run. Use the container for the real demo.
- **The record is "tamper-evident up to the last witnessed head".** Records written after the last
  witnessed head are not covered. Keyring-swap and truncation checks need the anchored form,
  `ks verify --head ANCHOR`, with the RunAnchor kept outside the run directory.
- **`ks verify` without `--head` means "consistent, not anchored"**, not "anchored". Only the
  `--head` form reports `anchored=true`.
- **Only one `ks run` at a time per machine.** Runs claim uids 60000 and up; a second concurrent
  run is refused (K2 guard).
- **View-sourced self-read gap.** If a rogue builds its second bad write from its own view of its
  first, the recovery t0 walk does not follow that read. The dry-run shows it as a non-zero
  `t0_delta` ("view-only self-reads not followed: suspect writes from the literal t0 are outside
  the seed, review them"); the operator must review those writes.
- **Collusion and threshold splitting are out of scope.** For colluding agents we name **root
  candidates** only; there is no prevention claim, and no red-team test or claim covers splitting
  under thresholds (C3).
- Repro mode (deterministic keys) is not a security run and is never anchored.

Full claim wording: `org/adr/THREAT-MODEL.md`.

## Fresh Mac: clone to verified in under 10 minutes

Measured on an Apple Silicon Mac with OrbStack, 20 Nov 2026: image build from scratch (no cache,
base image already pulled) 47 s; `make demo` on a built image 15 s. Allow extra time for the first
OrbStack install and the base image pull (network speed dependent; not measured here).

1. Install OrbStack (https://orbstack.dev) and open it once so the daemon starts. Docker Desktop
   also works but is not yet checked (see Troubleshooting). Make sure `docker` is on your PATH
   (OrbStack puts it in `~/.orbstack/bin`):

       docker info

2. Clone and run:

       git clone <repo-url> killswitch && cd killswitch
       make demo

   The first run builds the image (`killswitch:dev`); results land in `./runs` (bind mount).
   The container runs as root so per-agent numeric uids work, with `--network none`.

3. Expected end of the output (seed 2, T=40; run ids and hashes differ per run):

       == audit: verify against the printed RunAnchor
       verify: OK; last witnessed seq 223; anchored
       {"anchored":true,"exit":0,"first_bad":null,"isolation":"per_agent_uid","last_witnessed_seq":223,"ok":true,"reason":"ok","unanchored_reason":null}
       == score.json
       tti_detect                       2
       tti_attribute                    0
       ttc                              1
       R                                {"d":9,"n":0}
       C                                {"d":265,"n":0}
       post_alert_tainted_effects       0
       irreversible_tainted_released    0
       reemitted                        0
       kept_without_redo                {"d":265,"n":263}
       false_accusations                0
       demo OK (anchored, isolation=per_agent_uid)

   `make demo` fails (non-zero) if verify is not exit 0, anchored, so a final
   `demo OK (anchored, isolation=per_agent_uid)` is the pass signal.

4. Re-run the audit yourself. The RunAnchor is printed at the end of the run and saved in
   `runs/<run-id>.log`:

       ID=$(ls -t runs | grep '^hero-.*\.log$' | head -1 | sed 's/\.log$//')
       ANCHOR=$(grep -A1 '^RunAnchor (copy' runs/$ID.log | tail -n 1)
       docker run --rm --network none -v "$PWD/runs:/app/runs" killswitch:dev ks verify --head "$ANCHOR" /app/runs/$ID

   Expected: `verify: OK; last witnessed seq 223; anchored`, exit 0, and in `--json` form
   `"anchored":true` and `"isolation":"per_agent_uid"`. The same command without `--head "$ANCHOR"`
   prints `consistent, not anchored (no_anchor)`.

5. Open the incident console: `open runs/$ID.html`.

## What each demo beat means

`make demo` runs `scripts/demo.sh` (fault F2+, seed 2, 40 ticks, 10 agents, per-agent uids):

| Beat (script heading) | What happened |
|---|---|
| break / identify / contain | A culprit agent (`crm`) writes a bad bank field. The monitor alerts and suspends it; the run pauses before the next tick. Scores: `tti_detect` 2 ticks, `ttc` 1 tick. |
| recover: dry-run plan | `ks recover --dry-run` plans only the culprit's landed writes (`restore`) and re-runs the honest steps that read them (`rerun`); other agents are `independent` or `kept`. Nothing changes yet. |
| recover: operator approves and applies | `ks recover --apply PLAN` records the approval and the steps. Outbound payments built from tainted reads are re-held. |
| release the items the apply listed | The operator releases the held items with `ks contain unhold`, after review. Here: 2 re-held with clean payloads plus 7 held for a changed bank field now restored. |
| audit | `ks verify --head ANCHOR` must be exit 0, `isolation=per_agent_uid`, `anchored=true`. |
| score.json | Oracle-scored: `R` (residual damage) n=0, `C` (collateral) n=0, `reemitted` 0. |

Numbers in the benchmark report (`org/reports/BENCH-S3.md`, T=40, 20 seeds, H=6, fault F2+): R=0
**after the operator released a median 5 held items (3 honest, 2 tainted; max 9)**, C=0,
reemitted 0, time-to-identify 2 ticks, time-to-contain 1 tick. The R=0 claim holds only with those
operator releases (D-17). With fault F2+x (the variant where the plan flags a conflict and the approver never
resolves flags), R is 1/5 and 29 honest items stay held (median 27 in the revert-culprit-only baseline). Do not
compare these T=40 figures with T=120 runs.

## Other commands

    make test     # pytest inside the container
    make shell    # bash inside the container
    make smoke    # 2-agent run, then ks verify --head: asserts exit 0, per_agent_uid, anchored

Env knobs for the demo: `SEED`, `TICKS`, `RUN_ID`, `KS_IMAGE` (default `killswitch:dev`), `REBUILD=1`.

## Troubleshooting

- **`docker daemon not running`** (exit 69): start OrbStack (or Docker Desktop) and retry; check
  with `docker info`. `docker not found`: add `~/.orbstack/bin` to PATH or reopen the terminal.
- **Why the run is not on `./runs` while it runs** (S4-27): OrbStack and Docker Desktop bind mounts (virtiofs)
  ignore file permissions, which would let a rogue agent uid write `state.db`/`record.jsonl` and read the side
  store. So `make demo` and `make smoke` keep the live run dir at `/work/runs/<id>` on the container's own
  filesystem (permissions enforced), and `docker cp` it to `./runs/<id>` only after the run ends. `ks verify`,
  `score` and `console` then read that copy. The copy is evidence for audit, not a live run: `ks recover`/`contain`
  need the container while it is alive (the demo script drives them). Check: `tests/redteam/test_rt16_demo_path_isolation.py`.
  If you run `ks run` by hand in a container, use `--out /work/runs/<id>`, not a bind-mounted path.

- **`processes already run under uids 60000..` (K2) refusal**: another `ks run` or test container is
  still running. `docker ps`, stop it (`docker rm -f <name>`), and run one at a time. Do not run
  `make test` while `make demo` runs.
- **`run dir ... already exists`**: pick a new `RUN_ID` or delete the directory under `./runs`.
- **Stale image after pulling new code**: `REBUILD=1 make demo`.
- **Demo seems stuck**: it pauses by design and is driven by the script; wait. Container logs:
  `docker logs ks-demo-<pid>`.

## Open in IntelliJ / Claude Code

Read `CLAUDE.md` (rules and conventions) and `HANDOFF.md` (current state and next steps) first.
