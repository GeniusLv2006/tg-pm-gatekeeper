from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tg_pm_gatekeeper.store import StateStore


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_default_mode_is_observe(self) -> None:
        self.assertEqual(self.store.get_mode(), "observe")
        self.store.set_mode("enforce")
        self.assertEqual(self.store.get_mode(), "enforce")

    def test_message_claim_is_idempotent(self) -> None:
        self.assertTrue(self.store.claim_message("sender", 1, 100))
        self.assertFalse(self.store.claim_message("sender", 1, 100))

    def test_state_does_not_require_raw_identity(self) -> None:
        self.store.allow("hmac-value", 100)
        self.assertEqual(self.store.sender("hmac-value").status, "allowed")
        self.assertNotIn("123456789", str(self.store.statistics()))

    def test_heartbeat_health(self) -> None:
        self.store.heartbeat(100)
        self.assertTrue(self.store.healthy(now=150))
        self.assertFalse(self.store.healthy(now=221))


if __name__ == "__main__":
    unittest.main()
