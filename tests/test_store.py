from __future__ import annotations

import tempfile
import unittest
import sqlite3
from pathlib import Path

from tg_pm_gatekeeper.store import StateStore, StoreMigrationError


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

    def test_challenge_activation_clears_transient_recovery_data(self) -> None:
        self.store.begin_challenge_issue(
            "sender", "challenge", "digest", 200, "prompt", b"reference", 100
        )
        self.assertTrue(self.store.bind_challenge_message("sender", 42, 101))
        self.assertTrue(self.store.activate_challenge("sender", 102))
        state = self.store.sender("sender")
        self.assertEqual(state.status, "challenged")
        self.assertEqual(state.challenge_message_id, 42)
        self.assertIsNone(state.challenge_prompt)
        self.assertIsNone(state.challenge_action_reference)

    def test_automated_message_index_is_pruned_with_audit_retention(self) -> None:
        self.store.record_automated_message("sender", 42, 100)
        self.assertTrue(self.store.is_automated_message("sender", 42))
        self.store.prune(1, now=86_501)
        self.assertFalse(self.store.is_automated_message("sender", 42))

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
            '["HR-01_MULTIPLE_LINK_BUTTONS"]',
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


class StoreMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "legacy.sqlite3"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def create_legacy_database(self, status: str) -> None:
        connection = sqlite3.connect(self.path)
        connection.executescript(
            """
            CREATE TABLE sender_state (
                sender_key TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK (
                    status IN ('unknown', 'challenged', 'allowed', 'quarantined')
                ),
                challenge_id TEXT,
                answer_digest TEXT,
                challenge_expires_at INTEGER,
                attempts INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO settings(key, value) VALUES ('mode', 'observe');
            """
        )
        connection.execute(
            "INSERT INTO sender_state VALUES (?, ?, NULL, NULL, NULL, 0, 100)",
            ("sender", status),
        )
        connection.commit()
        connection.close()

    def test_v0_database_migrates_preserving_allowed_sender(self) -> None:
        self.create_legacy_database("allowed")
        store = StateStore(self.path)
        try:
            self.assertEqual(store.sender("sender").status, "allowed")
            self.assertEqual(store.get_mode(), "observe")
            version = store._connection.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(version, 1)
            columns = {
                row[1]
                for row in store._connection.execute("PRAGMA table_info(sender_state)")
            }
            self.assertIn("challenge_message_id", columns)
            self.assertIn("challenge_action_reference", columns)
        finally:
            store.close()

    def test_v0_database_refuses_active_challenge(self) -> None:
        self.create_legacy_database("challenged")
        with self.assertRaises(StoreMigrationError):
            StateStore(self.path)


if __name__ == "__main__":
    unittest.main()
