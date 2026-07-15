# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from tg_pm_gatekeeper.config import ConfigurationError, PrivateFileError
from tg_pm_gatekeeper.main import main
from tg_pm_gatekeeper.store import StoreMigrationError
from tg_pm_gatekeeper.telegram_adapter import TelegramAuthorizationError


class MainTests(unittest.TestCase):
    def test_startup_failures_are_classified_without_error_details(self) -> None:
        cases = (
            (PrivateFileError("secret path"), "startup_private_file_failed"),
            (ConfigurationError("secret value"), "startup_configuration_failed"),
            (StoreMigrationError("database detail"), "startup_database_migration_failed"),
            (
                TelegramAuthorizationError("session detail"),
                "startup_telegram_session_failed",
            ),
            (RuntimeError("runtime detail"), "startup_runtime_failed"),
        )
        for failure, event in cases:
            with self.subTest(event=event):
                logger = Mock()
                with (
                    patch("tg_pm_gatekeeper.main.configure_logging"),
                    patch(
                        "tg_pm_gatekeeper.main.async_main",
                        new=Mock(return_value=object()),
                    ),
                    patch("tg_pm_gatekeeper.main.asyncio.run", side_effect=failure),
                    patch("tg_pm_gatekeeper.main.logging.getLogger", return_value=logger),
                    self.assertRaisesRegex(SystemExit, "1"),
                ):
                    main()
                logger.critical.assert_called_once_with(event)


if __name__ == "__main__":
    unittest.main()
