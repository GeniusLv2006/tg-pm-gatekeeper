#!/usr/bin/env python3
from __future__ import annotations

import getpass
import os
import re
import secrets
from pathlib import Path

from telethon.sessions import StringSession
from telethon.sync import TelegramClient


TARGETS = (
    Path("telegram.session.secret"),
    Path("hmac.key"),
    Path("config.env"),
    Path("deny-domains.txt"),
)
API_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def write_private_file(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)


def render_config(api_id: int, api_hash: str) -> bytes:
    return (
        f"TG_API_ID={api_id}\n"
        f"TG_API_HASH={api_hash}\n"
        "TG_DB_PATH=/var/lib/tg-pm-gatekeeper/state.sqlite3\n"
        "TG_SESSION_FILE=/run/secrets/telegram_session\n"
        "TG_HMAC_KEY_FILE=/run/secrets/hmac_key\n"
        "TG_DENYLIST_FILE=/run/config/deny-domains.txt\n"
        "TG_CHALLENGE_TTL_SECONDS=600\n"
        "TG_CHALLENGE_MAX_ATTEMPTS=2\n"
        "TG_AUDIT_RETENTION_DAYS=30\n"
        "TG_MUTE_DAYS=3650\n"
        "TG_OUTBOUND_LIMIT_PER_HOUR=10\n"
    ).encode("ascii")


def main() -> None:
    existing = [str(path) for path in TARGETS if path.exists()]
    if existing:
        raise SystemExit("refusing to overwrite existing initialization files")

    try:
        api_id = int(input("Telegram API ID: ").strip())
    except ValueError:
        raise SystemExit("Telegram API ID must be an integer") from None
    api_hash = getpass.getpass("Telegram API hash: ").strip()
    if api_id <= 0 or not API_HASH_RE.fullmatch(api_hash):
        raise SystemExit("invalid Telegram API ID or API hash format")
    phone = input("Telegram phone number: ").strip()
    if not phone:
        raise SystemExit("Telegram phone number is required")

    client = TelegramClient(StringSession(), api_id, api_hash)
    try:
        client.start(
            phone=phone,
            code_callback=lambda: getpass.getpass("Telegram login code: ").strip(),
            password=lambda: getpass.getpass("Telegram 2FA password: "),
        )
        session = client.session.save().encode("ascii") + b"\n"
    finally:
        client.disconnect()

    values = {
        TARGETS[0]: session,
        TARGETS[1]: secrets.token_bytes(32),
        TARGETS[2]: render_config(api_id, api_hash),
        TARGETS[3]: b"# One normalized denied domain per line.\n",
    }
    created: list[Path] = []
    try:
        for path, value in values.items():
            write_private_file(path, value)
            created.append(path)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise

    print("Initialization files created with mode 0600.")
    print("Do not print, commit, or send their contents.")


if __name__ == "__main__":
    main()
