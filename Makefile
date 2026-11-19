IMAGE ?= killswitch:dev

.PHONY: image demo test shell smoke
image:
	docker build -t $(IMAGE) .

demo:
	./scripts/demo.sh

test: image
	docker run --rm --network none $(IMAGE) python -m pytest

shell: image
	mkdir -p runs
	docker run --rm -it -v "$(PWD)/runs:/app/runs" $(IMAGE) bash

# Build, run in the container, then verify anchored with the printed RunAnchor (--head):
# exit 0, isolation=per_agent_uid, anchored=true. Covers the ./runs bind-mount chown to uid 60000.
smoke: image
	rm -rf runs/smoke && mkdir -p runs
	docker run --rm --network none -v "$(PWD)/runs:/app/runs" $(IMAGE) ks run --agents 2 --ticks 10 --seed 0 --out /app/runs/smoke 2>&1 | tee runs/smoke-run.log
	grep -A1 '^RunAnchor (copy' runs/smoke-run.log | tail -n 1 > runs/smoke-anchor.txt
	test -s runs/smoke-anchor.txt
	docker run --rm --network none -v "$(PWD)/runs:/app/runs" $(IMAGE) ks verify --json --head "$$(cat runs/smoke-anchor.txt)" /app/runs/smoke | tee runs/smoke-verify.json
	python3 -c "import json; l=[x for x in open('runs/smoke-verify.json') if x.startswith('{')][-1]; j=json.loads(l); assert j['exit']==0 and j['isolation']=='per_agent_uid' and j['anchored'] is True, j; print('smoke OK (anchored)')"
