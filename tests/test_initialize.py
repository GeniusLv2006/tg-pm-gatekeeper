from __future__ import annotations

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
        self.assertIn("TG_TEST_SENDER_ID=\n", config)
        self.assertNotIn("REPLACE_WITH_", config)

    def test_challenge_configuration_is_bounded(self) -> None:
        with patch.dict(
            "os.environ", {"TG_CHALLENGE_TTL_SECONDS": "10"}, clear=True
        ):
            with self.assertRaisesRegex(ConfigurationError, "between 30 and 600"):
                Settings.from_environment(require_telegram=False)


if __name__ == "__main__":
    unittest.main()
