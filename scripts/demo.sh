#!/usr/bin/env bash
# One-command demo of the hero path (B3-27, CALL-02 B2), in the container with per-agent uids:
#   ks run --scenario world --fault F2+ --pause-on-alert   -> break, identify (alert), contain (suspend), paused
#   ks recover --dry-run ; ks recover --apply PLAN          -> recover (approve + steps on c-0), paused again
#   ks contain unhold outbox:<id> (what the apply listed)   -> re-held payments leave with clean payloads
#   ks verify --head ANCHOR (anchored) ; ks score ; ks console --html   -> audit, score.json, the page
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${KS_IMAGE:-killswitch:dev}"
SEED="${SEED:-2}"
TICKS="${TICKS:-40}"
RUN_ID="${RUN_ID:-hero-s$SEED-$(date +%Y%m%d-%H%M%S)}"
NAME="ks-demo-$$"
RUN="/app/runs/$RUN_ID"

command -v docker >/dev/null || { echo "docker not found: install Docker Desktop or OrbStack" >&2; exit 69; }
docker info >/dev/null 2>&1 || { echo "docker daemon not running: start Docker Desktop / OrbStack" >&2; exit 69; }

if [ -n "${REBUILD:-}" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" .
fi

mkdir -p runs
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
# Root inside the container (per-agent uids); no network needed at runtime.
docker run -d --name "$NAME" --network none -v "$PWD/runs:/app/runs" "$IMAGE" \
  ks run --scenario world --fault F2+ --seed "$SEED" --ticks "$TICKS" --pause-on-alert --out "$RUN" >/dev/null
EXEC=(docker exec "$NAME")

wait_log() {  # wait until the run's log has $2 lines matching $1
  for _ in $(seq 600); do
    [ "$(docker logs "$NAME" 2>&1 | grep -c "$1" || true)" -ge "$2" ] && return 0
    docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null | grep -q true || break
    sleep 0.2
  done
  [ "$(docker logs "$NAME" 2>&1 | grep -c "$1" || true)" -ge "$2" ] || {
    docker logs "$NAME" >&2; echo "demo: run ended before '$1'" >&2; exit 1; }
}

echo "== break / identify / contain: the monitor alerts and suspends; the run pauses"
wait_log "paused before tick" 1
docker logs "$NAME" 2>&1 | grep -E "^isolation|paused before" | head -2

echo "== recover: dry-run plan"
"${EXEC[@]}" ks recover "$RUN" --dry-run | tee "runs/$RUN_ID.dry.txt"
PLAN=$(grep -o -- '--apply p-[0-9]*' "runs/$RUN_ID.dry.txt" | head -1 | cut -d' ' -f2)

echo "== recover: operator approves and applies $PLAN"
"${EXEC[@]}" ks recover "$RUN" --apply "$PLAN" | tee "runs/$RUN_ID.apply.txt" | grep -v '^{'
wait_log "paused before tick" 2

echo "== release the items the apply listed (re-held payments, clean payloads)"
for OID in $(grep -o 'ks contain unhold outbox:ob-[0-9]*' "runs/$RUN_ID.apply.txt" | cut -d: -f2); do
  "${EXEC[@]}" ks contain unhold "outbox:$OID" "$RUN" >/dev/null && echo "unheld outbox:$OID"
done
"${EXEC[@]}" python -c "from ks.runtime.operator import operator_request as r; r('$RUN', {'op': 'resume'})" >/dev/null

docker wait "$NAME" >/dev/null
docker logs "$NAME" > "runs/$RUN_ID.log" 2>&1
ANCHOR=$(grep -A1 '^RunAnchor (copy' "runs/$RUN_ID.log" | tail -n 1)
test -n "$ANCHOR"

echo "== audit: verify against the printed RunAnchor"
DRUN=(docker run --rm --network none -v "$PWD/runs:/app/runs" "$IMAGE")
"${DRUN[@]}" ks verify --head "$ANCHOR" "$RUN" | tee "runs/$RUN_ID.verify.txt" | head -2
echo "== score.json"
"${DRUN[@]}" ks score "$RUN"
"${DRUN[@]}" ks console "$RUN" --html "$RUN.html"
python3 -c "import json,sys; l=[x for x in open('runs/$RUN_ID.verify.txt') if x.startswith('{')][-1]; j=json.loads(l); assert j['exit']==0 and j['anchored'] is True, j; print('demo OK (anchored, isolation=%s)' % j['isolation'])"
echo "run dir: ./runs/$RUN_ID   console: ./runs/$RUN_ID.html"
