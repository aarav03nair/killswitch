#!/usr/bin/env bash
# Finale preflight + live runs (S4-22). Refuses to present a run that is not a security run:
#   1. host check: 1-min load per CPU <= KS_MAX_LOAD_PER_CPU (default 0.5) and no other container running
#      (panel S4-26: under heavy load agents miss tick deadlines and the hero scores C 3/144 instead of 0/265)
#   2. make smoke: verify exit 0, isolation=per_agent_uid, anchored=true; config key_mode=fresh; 0 deadline misses
#   3. hero  : FAULT=F2+  (scripts/demo.sh, resolver label printed by the demo)            -> must be validity OK
#   4. F2+x  : FAULT=F2+x RESOLVER=ww_rebase/1 (D-18 after-row, labelled resolver on)      -> must be validity OK
#      (FINALE_F2X=0 skips it)
# After each run, `python -m ks.validity RUN` reads config.json + timing.jsonl in a fresh container. Any VOID or
# DEGRADED verdict (or a run_validity key in score.json) prints a DEGRADED banner and exits 3: that run is never the
# headline. Exit codes: 0 all OK, 2 host not ready, 3 a run is VOID/DEGRADED, other = a step failed.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${KS_IMAGE:-killswitch:dev}"
MAX_LOAD="${KS_MAX_LOAD_PER_CPU:-0.5}"
SEED="${SEED:-2}"
STAMP="$(date +%Y%m%d-%H%M%S)"
F2X_RESOLVER="ww_rebase/1"  # D-18 / ADR-05a §7: the F2+x mode runs with the resolver on and says so

die() { echo "finale: $*" >&2; exit "${2:-1}"; }
banner() {  # loud, unmissable
  echo "################################################################################" >&2
  echo "## $*" >&2
  echo "################################################################################" >&2
}

command -v docker >/dev/null || die "docker not found: install Docker Desktop or OrbStack" 69
docker info >/dev/null 2>&1 || die "docker daemon not running: start Docker Desktop / OrbStack" 69

host_check() {  # $1 = when
  local load ncpu
  if [ -r /proc/loadavg ]; then
    load=$(cut -d' ' -f1 /proc/loadavg); ncpu=$(nproc)
  else
    load=$(sysctl -n vm.loadavg | tr -d '{}' | awk '{print $1}'); ncpu=$(sysctl -n hw.ncpu)
  fi
  if ! python3 -c "import sys; sys.exit(0 if float('$load') / int('$ncpu') <= float('$MAX_LOAD') else 1)"; then
    banner "HOST TOO BUSY ($1): load $load on $ncpu CPUs > $MAX_LOAD per CPU. Close other apps and builds, retry."
    exit 2
  fi
  local others
  others=$(docker ps --format '{{.Names}} ({{.Image}})' | grep -v '^ks-smoke ' || true)
  if [ -n "$others" ]; then
    banner "OTHER CONTAINERS RUNNING ($1): one ks run per machine. Stop them first:"
    echo "$others" >&2
    exit 2
  fi
  echo "host ok ($1): load $load on $ncpu CPUs (max $MAX_LOAD per CPU), no other containers"
}

DRUN=(docker run --rm --network none -v "$PWD/runs:/app/runs" "$IMAGE")

check_run() {  # $1 = run id under ./runs, $2 = label. Validity OK and no run_validity key in score.json, or exit 3.
  local out rc=0
  out=$("${DRUN[@]}" python -m ks.validity "/app/runs/$1") || rc=$?
  echo "$out"
  if [ "$rc" -ne 0 ]; then
    banner "DEGRADED: $2 ($1) is NOT the headline. Do not present it. Fix the host, rerun make finale."
    exit 3
  fi
  if [ -f "runs/$1/score.json" ] && "${DRUN[@]}" python -c \
      "import json,sys; sys.exit(0 if 'run_validity' in json.load(open('/app/runs/$1/score.json')) else 1)"; then
    banner "DEGRADED: score.json of $2 ($1) carries run_validity. NOT the headline."
    exit 3
  fi
}

echo "== 1. host check"
host_check "before smoke"

echo "== 2. make smoke ($IMAGE)"
make smoke IMAGE="$IMAGE"
python3 - <<'EOF' || die "smoke did not give isolation=per_agent_uid, anchored=true, exit 0" 3
import json
line = [x for x in open("runs/smoke-verify.json") if x.startswith("{")][-1]
j = json.loads(line)
assert j["exit"] == 0 and j["isolation"] == "per_agent_uid" and j["anchored"] is True, j
EOF
check_run smoke "smoke"  # key_mode=fresh, isolation, 0 deadline misses (config.json + timing.jsonl)
echo "smoke OK: isolation=per_agent_uid anchored=true key_mode=fresh, 0 deadline misses"

echo "== 3. hero: F2+ seed $SEED"
host_check "before hero"
HERO="finale-hero-s$SEED-$STAMP"
KS_IMAGE="$IMAGE" SEED="$SEED" FAULT="F2+" RUN_ID="$HERO" ./scripts/demo.sh
check_run "$HERO" "hero F2+"

if [ "${FINALE_F2X:-1}" != 0 ]; then
  echo "== 4. F2+x mode, resolver: $F2X_RESOLVER (on) [D-18 after-row]"
  host_check "before F2+x"
  F2X="finale-f2x-s$SEED-$STAMP"
  KS_IMAGE="$IMAGE" SEED="$SEED" FAULT="F2+x" RESOLVER="$F2X_RESOLVER" RUN_ID="$F2X" ./scripts/demo.sh
  check_run "$F2X" "F2+x (resolver: $F2X_RESOLVER (on))"
fi

echo "== finale preflight OK"
echo "headline (hero F2+): ./runs/$HERO   console: ./runs/$HERO.html"
[ "${FINALE_F2X:-1}" = 0 ] || echo "F2+x, resolver: $F2X_RESOLVER (on): ./runs/$F2X   console: ./runs/$F2X.html"
