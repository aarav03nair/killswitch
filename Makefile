IMAGE ?= killswitch:dev

.PHONY: image demo test shell
image:
	docker build -t $(IMAGE) .

demo:
	./scripts/demo.sh

test: image
	docker run --rm --network none $(IMAGE) python -m pytest

shell: image
	mkdir -p runs
	docker run --rm -it -v "$(PWD)/runs:/app/runs" $(IMAGE) bash
