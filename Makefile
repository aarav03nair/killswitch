IMAGE ?= killswitch:dev

.PHONY: image demo test shell smoke mutation-gate finale
image:
	docker build -t $(IMAGE) .

demo:
	./scripts/demo.sh

test: image
	docker run --rm --network none $(IMAGE) python -m pytest

shell: image
	mkdir -p runs
	docker run --rm -it -v "$(PWD)/runs:/app/runs" $(IMAGE) bash

# Build, run on the container-internal fs (S4-27: not a bind mount), copy out, then verify anchored with the printed
# RunAnchor (--head): exit 0, isolation=per_agent_uid, anchored=true.
smoke: image
	rm -rf runs/smoke runs/smoke-ctr && mkdir -p runs
	docker rm -f ks-smoke >/dev/null 2>&1 || true
	docker run --name ks-smoke --network none $(IMAGE) ks run --agents 2 --ticks 10 --seed 0 --out /work/runs/smoke 2>&1 | tee runs/smoke-run.log
	docker cp ks-smoke:/work/runs/smoke runs/smoke && docker rm ks-smoke >/dev/null
	grep -A1 '^RunAnchor (copy' runs/smoke-run.log | tail -n 1 > runs/smoke-anchor.txt
	test -s runs/smoke-anchor.txt
	docker run --rm --network none -v "$(PWD)/runs:/app/runs" $(IMAGE) ks verify --json --head "$$(cat runs/smoke-anchor.txt)" /app/runs/smoke | tee runs/smoke-verify.json
	python3 -c "import json; l=[x for x in open('runs/smoke-verify.json') if x.startswith('{')][-1]; j=json.loads(l); assert j['exit']==0 and j['isolation']=='per_agent_uid' and j['anchored'] is True, j; print('smoke OK (anchored)')"

# S4-21: switch off each defence in turn on a scratch snapshot (never the main tree) and run tests/redteam in the
# container; every mutant must make >=1 red-team test fail. Table: org/reports/REDTEAM-S4.md.
mutation-gate:
	IMAGE=killswitch:kabir python3 tests/redteam/mutation_gate.py

# S4-22: finale preflight. Refuses a busy host, then make smoke must give isolation=per_agent_uid, anchored=true,
# key_mode=fresh; then the hero (F2+) and F2+x (resolver: ww_rebase/1 (on), D-18). Any VOID or deadline miss = exit 3.
finale:
	KS_IMAGE=$(IMAGE) ./scripts/finale.sh
