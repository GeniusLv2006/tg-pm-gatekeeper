FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements-build.txt requirements.txt ./
RUN python -m pip install --require-hashes --no-deps -r requirements-build.txt && \
    python -m pip install --require-hashes --no-deps --no-build-isolation --target /install -r requirements.txt

FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9

ENV PYTHONDONTWRITEBYTECODE=1 \
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
