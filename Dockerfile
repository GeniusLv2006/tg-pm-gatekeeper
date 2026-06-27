FROM python:3.13.13-slim-bookworm@sha256:355bfa66770995d7e9a0da4b3473b44d0cb451f6b56f5615ad9c39e3c4eca03f AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements-build.txt requirements.txt ./
RUN python -m pip install --require-hashes --no-deps -r requirements-build.txt && \
    python -m pip install --require-hashes --no-deps --no-build-isolation --target /install -r requirements.txt

FROM python:3.13.13-slim-bookworm@sha256:355bfa66770995d7e9a0da4b3473b44d0cb451f6b56f5615ad9c39e3c4eca03f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY --from=builder /install /usr/local/lib/python3.13/site-packages
COPY pyproject.toml ./
COPY src ./src

USER 10001:10001
ENTRYPOINT ["python", "-m", "tg_pm_gatekeeper.main"]
