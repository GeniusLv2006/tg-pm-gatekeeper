# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
        self.assertIn("TG_DATASET_KEY_FILE=/run/secrets/dataset_key", config)
        self.assertIn("TG_DATASET_COLLECTION=off", config)
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

    def test_dataset_configuration_is_bounded(self) -> None:
        with patch.dict("os.environ", {"TG_DATASET_RETENTION_DAYS": "91"}, clear=True):
            with self.assertRaisesRegex(ConfigurationError, "between 1 and 90"):
                Settings.from_environment(require_telegram=False)

    def test_dataset_files_must_be_cryptographically_separate(self) -> None:
        with patch.dict(
            os.environ,
            {
                "TG_DB_PATH": "/tmp/shared.sqlite3",
                "TG_DATASET_PATH": "/tmp/shared.sqlite3",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(ConfigurationError, "must be separate"):
                Settings.from_environment(require_telegram=False)

        with patch.dict(
            os.environ,
            {
                "TG_HMAC_KEY_FILE": "/tmp/shared.key",
                "TG_DATASET_KEY_FILE": "/tmp/shared.key",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(ConfigurationError, "must be separate"):
                Settings.from_environment(require_telegram=False)


if __name__ == "__main__":
    unittest.main()
