# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(RuntimeError):
    """Raised when runtime configuration violates the security boundary."""


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
    raw = os.environ.get(name, "on" if default else "off").strip().casefold()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be on or off")


def read_private_file(
    path: Path, *, minimum_bytes: int = 1, strip: bool = False
) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ConfigurationError(f"required private file is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ConfigurationError(f"private file must be a regular non-symlink: {path}")
    if info.st_mode & 0o077:
        raise ConfigurationError(f"private file permissions are too broad: {path}")
    value = path.read_bytes()
    if strip:
        value = value.strip()
    if len(value) < minimum_bytes:
        raise ConfigurationError(f"private file is empty or too short: {path}")
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
    review_retention_days: int
    review_socket_path: Path
    mute_days: int
    outbound_limit_per_hour: int
    test_sender_id: int | None
    dataset_collection: bool
    dataset_path: Path
    dataset_key_file: Path
    dataset_retention_days: int
    dataset_max_messages_per_sender: int

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
            review_retention_days=min(_positive_int("TG_REVIEW_RETENTION_DAYS", 7), 7),
            review_socket_path=Path(
                os.environ.get(
                    "TG_REVIEW_SOCKET_PATH",
                    "/var/lib/tg-pm-gatekeeper/review.sock",
                )
            ),
            mute_days=_positive_int("TG_MUTE_DAYS", 3650),
            outbound_limit_per_hour=_bounded_int(
                "TG_OUTBOUND_LIMIT_PER_HOUR", 10, 1, 100
            ),
            test_sender_id=_optional_positive_int("TG_TEST_SENDER_ID"),
            dataset_collection=_boolean("TG_DATASET_COLLECTION"),
            dataset_path=Path(
                os.environ.get(
                    "TG_DATASET_PATH",
                    "/var/lib/tg-pm-gatekeeper/training.sqlite3",
                )
            ),
            dataset_key_file=Path(
                os.environ.get("TG_DATASET_KEY_FILE", "/run/secrets/dataset_key")
            ),
            dataset_retention_days=_bounded_int("TG_DATASET_RETENTION_DAYS", 30, 1, 90),
            dataset_max_messages_per_sender=_bounded_int(
                "TG_DATASET_MAX_MESSAGES_PER_SENDER", 3, 1, 10
            ),
        )
        if settings.dataset_path == settings.database_path:
            raise ConfigurationError("training and state databases must be separate")
        private_paths = {
            settings.session_file,
            settings.hmac_key_file,
            settings.dataset_key_file,
        }
        if len(private_paths) != 3:
            raise ConfigurationError(
                "session, state HMAC, and dataset keys must be separate"
            )
        return settings
