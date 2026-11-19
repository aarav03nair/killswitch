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

# Build, run in the container, then verify: exit 0 and isolation=per_agent_uid. Covers the ./runs bind-mount chown.
smoke: image
	rm -rf runs/smoke && mkdir -p runs
	docker run --rm --network none -v "$(PWD)/runs:/app/runs" $(IMAGE) ks run --agents 2 --ticks 10 --seed 0 --out /app/runs/smoke
	docker run --rm --network none -v "$(PWD)/runs:/app/runs" $(IMAGE) ks verify --json /app/runs/smoke | tee runs/smoke-verify.json
	python3 -c "import json; l=[x for x in open('runs/smoke-verify.json') if x.startswith('{')][-1]; j=json.loads(l); assert j['exit']==0 and j['isolation']=='per_agent_uid', j; print('smoke OK')"
