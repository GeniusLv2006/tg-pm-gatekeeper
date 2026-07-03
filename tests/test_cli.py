from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tg_pm_gatekeeper.cli import run
from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.store import StateStore


class CliTests(unittest.TestCase):
    def test_mode_monitor_replaces_legacy_pause_resume_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            with patch.dict(os.environ, {"TG_DB_PATH": str(database)}, clear=True):
                self.assertEqual(run(["mode", "monitor"]), 0)
                with self.assertRaises(SystemExit):
                    run(["pause"])
                with self.assertRaises(SystemExit):
                    run(["resume"])

    def test_allow_refuses_incomplete_challenge_without_telegram_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            key_file = root / "hmac_key"
            key = b"k" * 32
            key_file.write_bytes(key)
            key_file.chmod(0o600)
            sender_key = IdentifierProtector(key).sender_key(123456789)
            store = StateStore(database)
            store.begin_challenge_issue(
                sender_key,
                "challenge",
                "digest",
                700,
                "prompt",
                b"reference",
                100,
            )
            store.close()

            environment = {
                "TG_DB_PATH": str(database),
                "TG_HMAC_KEY_FILE": str(key_file),
            }
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(ValueError, "dashboard review"):
                    run(["allow", "123456789"])

            store = StateStore(database)
            self.assertEqual(store.sender(sender_key).status, "challenge_issuing")
            store.close()


if __name__ == "__main__":
    unittest.main()
