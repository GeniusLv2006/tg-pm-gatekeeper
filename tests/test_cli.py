# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tg_pm_gatekeeper.cli import run
from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.evidence import EvidenceProtector, EvidenceStore
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

    def test_evidence_status_purge_and_removed_samples_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            evidence_path = root / "evidence.sqlite3"
            evidence_key = root / "evidence.key"
            key = b"e" * 32
            evidence_key.write_bytes(key)
            evidence_key.chmod(0o600)
            evidence = EvidenceStore(evidence_path, EvidenceProtector(key))
            evidence.collect(
                sender_id=123,
                message_id=1,
                payload={"text": "private-cli-canary"},
                automatic_hint="uncertain",
                retention_days=7,
                max_per_sender=3,
            )
            evidence.close()

            environment = {
                "TG_DB_PATH": str(database),
                "TG_EVIDENCE_KEY_FILE": str(evidence_key),
                "TG_EVIDENCE_PATH": str(evidence_path),
                "TG_EVIDENCE_COLLECTION": "on",
            }
            with patch.dict(os.environ, environment, clear=True):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(run(["evidence", "status"]), 0)
                status = json.loads(output.getvalue())
                self.assertTrue(status["collection_enabled"])
                self.assertEqual(status["total"], 1)

                with self.assertRaisesRegex(ValueError, "samples export has been removed"):
                    run(["samples", "export"])

                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(
                        run(
                            [
                                "evidence",
                                "purge",
                                "--confirm",
                                "DELETE-ALL-SAMPLES",
                            ]
                        ),
                        0,
                    )
                self.assertIn("evidence_deleted=1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
