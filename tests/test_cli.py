# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import os
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

from tg_pm_gatekeeper.cli import run
from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.store import StateStore

from .legacy_references import LEGACY_KEY, LEGACY_RESTRICTION_REFERENCE

USER_ID = 123456789
KEY = b"k" * 32
SENDER_KEY = IdentifierProtector(KEY).sender_key(USER_ID)


class CliTests(unittest.TestCase):
    def test_cli_migrates_legacy_references_with_the_hmac_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            key_file = root / "hmac_key"
            key_file.write_bytes(LEGACY_KEY)
            key_file.chmod(0o600)
            store = StateStore(database)
            store.suppress(
                "sender",
                "permanent_suppression",
                until=None,
                restriction_reference=LEGACY_RESTRICTION_REFERENCE,
            )
            store._connection.execute("PRAGMA user_version=8")
            store._connection.commit()
            store.close()

            environment = {
                "TG_DB_PATH": str(database),
                "TG_HMAC_KEY_FILE": str(key_file),
            }
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(run(["mode", "status"]), 0)

            store = StateStore(database)
            reference = store.sender("sender").restriction_reference
            store.close()
            assert reference is not None
            self.assertEqual(reference[0], 2)
            self.assertEqual(
                IdentifierProtector(LEGACY_KEY).open_restriction_reference(reference),
                (123456789, -987654321),
            )

    def test_healthcheck_on_current_schema_never_reads_the_hmac_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            store = StateStore(database)
            store.heartbeat()
            store.close()
            environment = {
                "TG_DB_PATH": str(database),
                "TG_HMAC_KEY_FILE": str(Path(directory) / "missing_key"),
            }
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(run(["healthcheck"]), 0)

    def sender_environment(
        self, directory: str, prepare: Callable[[StateStore], object]
    ) -> tuple[Path, dict[str, str]]:
        root = Path(directory)
        database = root / "state.sqlite3"
        key_file = root / "hmac_key"
        key_file.write_bytes(KEY)
        key_file.chmod(0o600)
        store = StateStore(database)
        prepare(store)
        store.close()
        return database, {
            "TG_DB_PATH": str(database),
            "TG_HMAC_KEY_FILE": str(key_file),
        }

    def test_sender_commands_refuse_states_that_need_telegram_restore(self) -> None:
        cases: dict[str, Callable[[StateStore], object]] = {
            "challenge_issuing": lambda store: store.begin_challenge_issue(
                SENDER_KEY, "challenge", "digest", 700, "prompt", b"reference", 100
            ),
            "quarantined": lambda store: store.quarantine(
                SENDER_KEY, restriction_reference=b"control"
            ),
            "suppressed": lambda store: store.suppress(
                SENDER_KEY,
                "permanent_suppression",
                until=None,
                reference=b"reference",
                restriction_reference=b"control",
            ),
        }
        for command in ("allow", "revoke"):
            for status, prepare in cases.items():
                with (
                    self.subTest(command=command, status=status),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    database, environment = self.sender_environment(directory, prepare)
                    with patch.dict(os.environ, environment, clear=True):
                        with self.assertRaisesRegex(ValueError, "dashboard review"):
                            run([command, str(USER_ID)])

                    store = StateStore(database)
                    state = store.sender(SENDER_KEY)
                    store.close()
                    self.assertEqual(state.status, status)
                    if status != "challenge_issuing":
                        self.assertEqual(state.restriction_reference, b"control")

    def test_revoke_returns_allowed_sender_to_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database, environment = self.sender_environment(
                directory, lambda store: store.allow(SENDER_KEY)
            )
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(run(["revoke", str(USER_ID)]), 0)

            store = StateStore(database)
            self.assertEqual(store.sender(SENDER_KEY).status, "unknown")
            store.close()
