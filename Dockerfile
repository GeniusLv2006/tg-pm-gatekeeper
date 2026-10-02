FROM python:3.14.8-slim-bookworm@sha256:c8137f4c460908c8763f281c8f22c431eb5c538514ba9553fc3a89c06b7cfb88 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements-build.txt requirements.txt ./
RUN python -m pip install --require-hashes --no-deps -r requirements-build.txt && \
    python -m pip install --require-hashes --no-deps --no-build-isolation --target /install -r requirements.txt

FROM python:3.14.8-slim-bookworm@sha256:c8137f4c460908c8763f281c8f22c431eb5c538514ba9553fc3a89c06b7cfb88

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

USER 10001:10001
ENTRYPOINT ["python", "-m", "tg_pm_gatekeeper.main"]
