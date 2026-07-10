# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import argparse
import json
import os
import sys

from .config import ConfigurationError, Settings, read_private_file
from .crypto import IdentifierProtector
from .store import StateStore, StoreMigrationError


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="tg-pm-gatekeeper-cli")
    subcommands = command.add_subparsers(dest="command", required=True)
    subcommands.add_parser("status")
    mode = subcommands.add_parser("mode")
    mode.add_argument("value", choices=("status", "monitor", "protect"))
    subcommands.add_parser("healthcheck")
    allow = subcommands.add_parser("allow")
    allow.add_argument("user_id", type=int)
    revoke = subcommands.add_parser("revoke")
    revoke.add_argument("user_id", type=int)
    return command


def run(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    settings = Settings.from_environment(require_telegram=False)
    store = StateStore(settings.database_path)
    try:
        if args.command == "healthcheck":
            return 0 if store.healthy() else 1
        if args.command == "status":
            print(json.dumps(store.statistics(), sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "mode":
            if args.value == "status":
                print(f"mode={store.get_mode()}")
                return 0
            if args.value == "protect":
                failures = store.protect_preflight()
                read_private_file(settings.review_key_file, minimum_bytes=32)
                if failures:
                    raise ValueError("; ".join(failures))
            store.set_mode(args.value)
            print(f"mode={args.value}")
            return 0
        key = read_private_file(settings.hmac_key_file, minimum_bytes=32)
        sender_key = IdentifierProtector(key).sender_key(args.user_id)
        if args.command == "allow":
            if store.sender(sender_key).status in {
                "challenge_issuing",
                "challenge_archiving",
                "challenged",
                "quarantined",
                "suppressed",
            }:
                raise ValueError(
                    "sender requires dashboard review to restore Telegram state"
                )
            store.allow(sender_key)
            print("sender=allowed")
        else:
            store.revoke(sender_key)
            print("sender=revoked")
        return 0
    finally:
        store.close()


def main() -> None:
    os.umask(0o077)
    try:
        raise SystemExit(run())
    except (ConfigurationError, OSError, StoreMigrationError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
