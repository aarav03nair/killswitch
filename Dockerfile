# Project Kill Switch runtime image. python:3.13.1-slim-bookworm is multi-arch (arm64 + amd64).
FROM python:3.13.1-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY tests ./tests
# Package + deps from pyproject.toml; [test] extra so `make test` works offline at runtime.
RUN pip install ".[test]" \
 && printf '#!/bin/sh\nexec python -m ks "$@"\n' > /usr/local/bin/ks \
 && chmod +x /usr/local/bin/ks

# Deliberately root: the runtime assigns per-agent numeric uids (needs CAP_SETUID).
# Isolation is per-agent numeric uids inside the container (60001+index; witness 60000), non-dumpable
# processes, clean env, path-less socketpairs. If per-agent uids fail, per-agent attribution is void
# for that run (THREAT-MODEL). The container is the deployment unit; run with --network none.
USER root
VOLUME ["/app/runs"]
CMD ["ks", "--help"]
