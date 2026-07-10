# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from scripts.initialize import render_config, write_private_file
from tg_pm_gatekeeper.config import ConfigurationError, Settings


class InitializeTests(unittest.TestCase):
    def test_private_file_has_owner_only_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            write_private_file(path, b"value")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_bytes(), b"value")

    def test_config_contains_runtime_paths(self) -> None:
        config = render_config(1, "TEST_API_HASH_DO_NOT_USE").decode("ascii")
        self.assertIn("TG_API_ID=1", config)
        self.assertIn("TG_SESSION_FILE=/run/secrets/telegram_session", config)
        self.assertIn("TG_REVIEW_KEY_FILE=/run/secrets/review_key", config)
        self.assertIn("TG_PENDING_REVIEW_RETENTION_DAYS=7", config)
        self.assertIn("TG_ACTIVE_CASE_RETENTION_DAYS=30", config)
        self.assertIn("TG_TEST_SENDER_ID=\n", config)
        self.assertNotIn("REPLACE_WITH_", config)

    def test_public_example_matches_generated_config_keys(self) -> None:
        generated = render_config(1, "TEST_API_HASH_DO_NOT_USE").decode("ascii")
        example = (Path(__file__).resolve().parents[1] / ".env.example").read_text(
            encoding="utf-8"
        )

        def keys(value: str) -> set[str]:
            return {
                line.partition("=")[0]
                for line in value.splitlines()
                if line and not line.startswith("#") and "=" in line
            }

        self.assertEqual(keys(example), keys(generated))

    def test_challenge_configuration_is_bounded(self) -> None:
        with patch.dict("os.environ", {"TG_CHALLENGE_TTL_SECONDS": "10"}, clear=True):
            with self.assertRaisesRegex(ConfigurationError, "between 30 and 600"):
                Settings.from_environment(require_telegram=False)

    def test_review_key_must_be_cryptographically_separate(self) -> None:
        with patch.dict(
            os.environ,
            {
                "TG_HMAC_KEY_FILE": "/tmp/shared.key",
                "TG_REVIEW_KEY_FILE": "/tmp/shared.key",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(ConfigurationError, "must be separate"):
                Settings.from_environment(require_telegram=False)

    def test_retention_configuration_is_bounded(self) -> None:
        for name, value, expected in (
            ("TG_PENDING_REVIEW_RETENTION_DAYS", "8", "between 1 and 7"),
            ("TG_ACTIVE_CASE_RETENTION_DAYS", "31", "between 1 and 30"),
        ):
            with self.subTest(name=name), patch.dict(
                os.environ, {name: value}, clear=True
            ):
                with self.assertRaisesRegex(ConfigurationError, expected):
                    Settings.from_environment(require_telegram=False)


if __name__ == "__main__":
    unittest.main()
