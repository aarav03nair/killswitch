# Project Kill Switch runtime image. python:3.13-slim is multi-arch (arm64 + amd64).
FROM python:3.13-slim

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
# Isolation comes from the container boundary; run with --network none at runtime.
USER root
VOLUME ["/app/runs"]
CMD ["ks", "--help"]
