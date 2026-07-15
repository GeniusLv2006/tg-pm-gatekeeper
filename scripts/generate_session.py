#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import getpass
import os
from pathlib import Path

from telethon.sessions import StringSession
from telethon.sync import TelegramClient


def main() -> None:
    destination = Path("telegram.session.secret")
    if destination.exists():
        raise SystemExit("refusing to overwrite telegram.session.secret")
    api_id = int(input("Telegram API ID: ").strip())
    api_hash = getpass.getpass("Telegram API hash: ").strip()
    phone = input("Telegram phone number: ").strip()
    client = TelegramClient(StringSession(), api_id, api_hash)
    client.start(
        phone=phone,
        code_callback=lambda: getpass.getpass("Telegram login code: ").strip(),
        password=lambda: getpass.getpass("Telegram 2FA password: "),
    )
    try:
        session = client.session.save()
    finally:
        client.disconnect()
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as output:
        output.write(session)
        output.write("\n")
    print(
        "Session written to telegram.session.secret with mode 0600; never commit or paste it."
    )


if __name__ == "__main__":
    main()
