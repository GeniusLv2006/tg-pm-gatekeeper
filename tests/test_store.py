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

    def test_review_decision_erases_reversible_reference(self) -> None:
        review_id = self.store.enqueue_review(
            "sender", b"sealed-reference", "would_challenge", "[]", "{}", 700, 100
        )
        self.assertEqual(self.store.statistics()["pending_reviews"], 1)
        self.assertTrue(self.store.decide_review(review_id, "legitimate", 200))
        item = self.store.review_item(review_id)
        self.assertIsNotNone(item)
        self.assertEqual(item.status, "legitimate")
        self.assertIsNone(item.reference)
        self.assertEqual(self.store.statistics()["pending_reviews"], 0)

    def test_review_reference_expires_at_its_own_deadline(self) -> None:
        self.store.enqueue_review(
            "sender", b"sealed-reference", "would_challenge", "[]", "{}", 200, 100
        )
        self.store.prune(30, now=201)
        self.assertEqual(self.store.review_items(), [])

    def test_pending_reviews_are_consolidated_per_sender(self) -> None:
        first_id = self.store.enqueue_review(
            "sender", b"first", "would_challenge", "[]", "{}", 700, 100
        )
        second_id = self.store.enqueue_review(
            "sender",
            b"second",
            "would_quarantine",
            '["HR-01_LINK_BUTTON"]',
            "{}",
            800,
            200,
        )
        third_id = self.store.enqueue_review(
            "sender", b"third", "would_challenge", "[]", "{}", 900, 300
        )
        self.assertEqual((first_id, second_id, third_id), (first_id,) * 3)
        item = self.store.review_item(first_id)
        self.assertEqual(item.message_count, 3)
        self.assertEqual(item.classification, "would_quarantine")
        self.assertEqual(item.reference, b"second")


if __name__ == "__main__":
    unittest.main()
