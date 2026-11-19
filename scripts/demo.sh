#!/usr/bin/env bash
# One-command demo: build image if needed, ks run (bind-mounted ./runs), then ks verify.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${KS_IMAGE:-killswitch:dev}"
RUN_ID="${RUN_ID:-demo-$(date +%Y%m%d-%H%M%S)}"

command -v docker >/dev/null || { echo "docker not found: install Docker Desktop or OrbStack" >&2; exit 69; }
docker info >/dev/null 2>&1 || { echo "docker daemon not running: start Docker Desktop / OrbStack" >&2; exit 69; }

if [ -n "${REBUILD:-}" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" .
fi

mkdir -p runs
# Root inside the container (per-agent uids); no network needed at runtime.
DRUN=(docker run --rm --network none -v "$PWD/runs:/app/runs" "$IMAGE")

# TODO(B3-39): once the hero path exists, switch to:
#   ks run --fault F2+ --pause-at <POINT> --step --out /app/runs/$RUN_ID
"${DRUN[@]}" ks run --agents 2 --ticks 10 --seed 0 --out "/app/runs/$RUN_ID"
"${DRUN[@]}" ks verify "/app/runs/$RUN_ID"
echo "run dir: ./runs/$RUN_ID"
