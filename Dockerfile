FROM python:3.14.10-slim-bookworm@sha256:3fe1a0b6c2d6b2ebb572906cdabeca75aeb558c0c17db5ffefbcf8094871c32b AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements-build.txt requirements.txt ./
RUN python -m pip install --require-hashes --no-deps -r requirements-build.txt && \
    python -m pip install --require-hashes --no-deps --no-build-isolation --target /install -r requirements.txt

FROM python:3.14.10-slim-bookworm@sha256:3fe1a0b6c2d6b2ebb572906cdabeca75aeb558c0c17db5ffefbcf8094871c32b

ENV MALLOC_ARENA_MAX=2 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNODEBUGRANGES=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY --from=builder /install /usr/local/lib/python3.14/site-packages
COPY pyproject.toml ./
COPY src ./src
# Do not inherit restrictive modes from the host checkout (for example a umask of 077).
RUN chmod -R a+rX,go-w /app

USER 10001:10001
ENTRYPOINT ["python", "-m", "tg_pm_gatekeeper.main"]
