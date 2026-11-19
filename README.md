# Project Kill Switch

Authenticated provenance, containment and taint-scoped revert for multi-agent shared state
(SEED Hackathon 2026, track 3). Agents act through a gateway; every action is recorded and
witnessed, and `ks verify` checks a run directory offline.

## Quick start

    make demo     # build image if needed, ks run, then ks verify (run dir in ./runs)
    make test     # pytest inside the container
    make shell    # bash inside the container

## Run on macOS

Works on Apple Silicon and Intel (the image is based on multi-arch `python:3.13-slim`).

1. Install Docker Desktop or OrbStack and start it.
2. `git clone` this repo and `cd` into it.
3. `make demo`. The first run builds the image; results land in `./runs` (bind mount).

The container runs as root internally so per-agent numeric uids work, and needs no network
at runtime (the demo uses `--network none`).

**Warning:** running natively on macOS (outside Docker) is degraded isolation. Per-agent uid
separation is unavailable, so per-agent attribution is VOID. Use the container for the real demo.

`make smoke` builds the image, runs and verifies in the container, and asserts exit 0 with
`isolation=per_agent_uid`.

Known risk (untested until `make smoke` has run on Docker/OrbStack): `src/ks/contracts/rundir.py`
chowns `witness.jsonl` and `witness-heads/` to uid 60000, which may fail or behave differently on a
macOS bind mount (virtiofs). If so, use a named volume instead of `./runs`.

Note: `scripts/demo.sh` currently runs the skeleton (`--agents 2 --ticks 10`); it switches to
`--fault F2+ --pause-at ... --step` once the hero path exists (TODO in the script).

## Open in IntelliJ / Claude Code

Read `CLAUDE.md` (rules and conventions) and `HANDOFF.md` (current state and next steps) first.
