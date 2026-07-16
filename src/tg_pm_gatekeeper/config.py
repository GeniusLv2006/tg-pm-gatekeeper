# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(RuntimeError):
    """Raised when runtime configuration violates the security boundary."""


class PrivateFileError(ConfigurationError):
    """Raised when a required private file cannot be read safely."""


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or value.startswith("REPLACE_WITH_"):
        raise ConfigurationError(f"missing required setting: {name}")
    return value


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be positive")
    return value


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    value = _positive_int(name, default)
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_nonnegative_int(
    name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _optional_positive_int(name: str) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be positive")
    return value


def _boolean(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "true" if default else "false").strip().casefold()
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise ConfigurationError(f"{name} must be true or false")


def read_private_file(
    path: Path, *, minimum_bytes: int = 1, strip: bool = False
) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PrivateFileError(f"required private file is unavailable: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PrivateFileError(f"private file must be a regular non-symlink: {path}")
    if info.st_mode & 0o077:
        raise PrivateFileError(f"private file permissions are too broad: {path}")
    try:
        value = path.read_bytes()
    except OSError as exc:
        raise PrivateFileError(f"required private file is unreadable: {path}") from exc
    if strip:
        value = value.strip()
    if len(value) < minimum_bytes:
        raise PrivateFileError(f"private file is empty or too short: {path}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    api_id: int
    api_hash: str
    database_path: Path
    session_file: Path
    hmac_key_file: Path
    denylist_file: Path | None
    challenge_ttl_seconds: int
    challenge_max_attempts: int
    audit_retention_days: int
    pending_review_retention_days: int
    active_case_retention_days: int
    review_socket_path: Path
    mute_days: int
    outbound_limit_per_hour: int
    outbound_notice_reserve_per_hour: int
    outbound_notice_limit_per_sender_per_hour: int
    telegram_operator_controls_enabled: bool
    test_sender_id: int | None
    review_key_file: Path

    @classmethod
    def from_environment(cls, *, require_telegram: bool = True) -> "Settings":
        if require_telegram:
            raw_api_id = _required("TG_API_ID")
            api_hash = _required("TG_API_HASH")
        else:
            raw_api_id = os.environ.get("TG_API_ID", "1")
            api_hash = os.environ.get("TG_API_HASH", "not-used-by-cli")
        try:
            api_id = int(raw_api_id)
        except ValueError as exc:
            raise ConfigurationError("TG_API_ID must be an integer") from exc
        denylist = os.environ.get("TG_DENYLIST_FILE", "").strip()
        outbound_limit = _bounded_int("TG_OUTBOUND_LIMIT_PER_HOUR", 10, 1, 100)
        settings = cls(
            api_id=api_id,
            api_hash=api_hash,
            database_path=Path(
                os.environ.get("TG_DB_PATH", "/var/lib/tg-pm-gatekeeper/state.sqlite3")
            ),
            session_file=Path(
                os.environ.get("TG_SESSION_FILE", "/run/secrets/telegram_session")
            ),
            hmac_key_file=Path(
                os.environ.get("TG_HMAC_KEY_FILE", "/run/secrets/hmac_key")
            ),
            denylist_file=Path(denylist) if denylist else None,
            challenge_ttl_seconds=_bounded_int("TG_CHALLENGE_TTL_SECONDS", 60, 30, 600),
            challenge_max_attempts=_bounded_int("TG_CHALLENGE_MAX_ATTEMPTS", 2, 1, 5),
            audit_retention_days=_positive_int("TG_AUDIT_RETENTION_DAYS", 30),
            pending_review_retention_days=_bounded_int(
                "TG_PENDING_REVIEW_RETENTION_DAYS", 7, 1, 7
            ),
            active_case_retention_days=_bounded_int(
                "TG_ACTIVE_CASE_RETENTION_DAYS", 30, 1, 30
            ),
            review_socket_path=Path(
                os.environ.get(
                    "TG_DASHBOARD_SOCKET_PATH",
                    os.environ.get(
                        "TG_REVIEW_SOCKET_PATH",
                        "/var/lib/tg-pm-gatekeeper/review.sock",
                    ),
                )
            ),
            mute_days=_positive_int("TG_MUTE_DAYS", 3650),
            outbound_limit_per_hour=outbound_limit,
            outbound_notice_reserve_per_hour=_bounded_nonnegative_int(
                "TG_OUTBOUND_NOTICE_RESERVE_PER_HOUR",
                min(3, outbound_limit - 1),
                0,
                outbound_limit - 1,
            ),
            outbound_notice_limit_per_sender_per_hour=_bounded_int(
                "TG_OUTBOUND_NOTICE_LIMIT_PER_SENDER_PER_HOUR", 3, 1, 100
            ),
            telegram_operator_controls_enabled=_boolean(
                "TG_TELEGRAM_OPERATOR_CONTROLS_ENABLED"
            ),
            test_sender_id=_optional_positive_int("TG_TEST_SENDER_ID"),
            review_key_file=Path(
                os.environ.get("TG_REVIEW_KEY_FILE", "/run/secrets/review_key")
            ),
        )
        private_paths = {
            settings.session_file,
            settings.hmac_key_file,
            settings.review_key_file,
        }
        if len(private_paths) != 3:
            raise ConfigurationError(
                "session, state HMAC, and review keys must be separate"
            )
        return settings
