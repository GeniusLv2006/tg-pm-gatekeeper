# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from tg_pm_gatekeeper.store import DialogSnapshot, StateStore, StoreMigrationError


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_default_mode_is_monitor(self) -> None:
        self.assertEqual(self.store.get_mode(), "monitor")
        self.store.set_mode("protect")
        self.assertEqual(self.store.get_mode(), "protect")

    def test_message_claim_is_idempotent(self) -> None:
        self.assertTrue(self.store.claim_message("sender", 1, 100))
        self.assertFalse(self.store.claim_message("sender", 1, 100))

    def test_test_cleanup_is_scoped_and_cannot_reset_newer_state(self) -> None:
        self.store.claim_message("sender", 1, 100)
        self.store.finish_message("sender", 1, "challenged")
        self.store.record_automated_message("sender", 2, 101)
        self.store.claim_message("sender", 3, 102)
        self.assertEqual(self.store.message_ids_since("sender", 101), [2, 3])
        self.assertEqual(self.store.latest_challenge_started_at("sender", 200), 100)

        self.store.mark_provisional("sender", 200)
        self.assertFalse(self.store.reset_test_sender("sender", 199, 260))
        self.assertEqual(self.store.sender("sender").status, "provisional")
        self.assertTrue(self.store.reset_test_sender("sender", 200, 260))
        self.assertEqual(self.store.sender("sender").status, "unknown")

    def test_challenge_message_lookup_is_bounded_by_message_id(self) -> None:
        self.store.record_automated_message("sender", 10, 100)
        self.store.record_automated_message("sender", 12, 102)
        self.store.claim_message("sender", 11, 101)
        self.store.finish_message("sender", 11, "challenge_incorrect")
        self.store.record_automated_message("sender", 14, 104)
        self.assertEqual(self.store.message_ids_between("sender", 10, 12), [10, 11, 12])

    def test_latest_challenge_terminal_event_distinguishes_wrong_from_timeout(
        self,
    ) -> None:
        self.store.audit("sender", "CHALLENGE_TIMEOUT", "already_archived", 100)
        self.store.audit("sender", "attempts_exhausted", "scheduled", 200)
        self.assertEqual(
            self.store.latest_challenge_terminal_event("sender", 150),
            ("attempts_exhausted", "scheduled"),
        )
        self.assertIsNone(self.store.latest_challenge_terminal_event("sender", 201))

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
        self.assertEqual(state.challenge_action_reference, b"reference")

    def test_automated_message_index_is_pruned_with_audit_retention(self) -> None:
        self.store.record_automated_message("sender", 42, 100)
        self.assertTrue(self.store.is_automated_message("sender", 42))
        self.store.prune(1, now=86_501)
        self.assertFalse(self.store.is_automated_message("sender", 42))

    def test_heartbeat_health(self) -> None:
        self.store.heartbeat(100)
        self.assertTrue(self.store.healthy(now=150))
        self.assertFalse(self.store.healthy(now=221))

    def test_dialog_snapshot_round_trip_and_clear(self) -> None:
        snapshot = DialogSnapshot(folder_id=2, silent=True, mute_until=500)
        self.store.save_dialog_snapshot("sender", snapshot)
        self.assertEqual(self.store.dialog_snapshot("sender"), snapshot)
        self.store.clear_dialog_snapshot("sender")
        self.assertIsNone(self.store.dialog_snapshot("sender"))

    def test_statistics_include_privacy_safe_challenge_funnel(self) -> None:
        now = int(time.time())
        self.store.audit("sender", "CHALLENGE_SENT", "archived_muted", now)
        self.store.audit("sender", "CHALLENGE_CORRECT", "provisional", now)
        statistics = self.store.statistics()
        self.assertEqual(statistics["challenge_sent_7d"], 1)
        self.assertEqual(statistics["challenge_correct_7d"], 1)
        self.assertNotIn("sender", str(statistics))

    def test_monitor_cancels_pending_delete_and_stale_revision_blocks_claim(
        self,
    ) -> None:
        state = self.store.suppress(
            "sender", "attempts_exhausted", until=700, reference=b"reference", now=100
        )
        action_id = self.store.schedule_action(
            "sender",
            reason="attempts_exhausted",
            reference=b"reference",
            execute_at=110,
            expected_revision=state.revision,
            now=100,
        )
        self.store.set_mode("protect")
        self.assertIsNotNone(self.store.claim_action(action_id))
        self.store.set_mode("monitor")
        self.assertEqual(self.store.pending_actions(), [])
        self.assertEqual(self.store.statistics()["pending_reviews"], 1)

        other = self.store.suppress(
            "other", "critical_rule", until=None, reference=b"other", now=200
        )
        other_action = self.store.schedule_action(
            "other",
            reason="critical_rule",
            reference=b"other",
            execute_at=210,
            expected_revision=other.revision,
            now=200,
        )
        self.store.set_mode("protect")
        self.store.allow("other", 205)
        self.assertIsNone(self.store.claim_action(other_action))

    def test_monitor_preserves_mode_independent_test_action(self) -> None:
        self.store.quarantine("test-sender", 100)
        state = self.store.sender("test-sender")
        action_id = self.store.schedule_action(
            "test-sender",
            reason="attempts_exhausted",
            reference=b"test-reference",
            execute_at=110,
            expected_revision=state.revision,
            mode_independent=True,
            now=100,
        )

        self.store.set_mode("monitor")

        action = self.store.claim_action(action_id)
        self.assertIsNotNone(action)
        assert action is not None
        self.assertEqual(action.sender_key, "test-sender")
        self.assertEqual(self.store.statistics()["pending_reviews"], 0)

    def test_protect_preflight_rejects_stale_pending_action(self) -> None:
        self.store.heartbeat()
        state = self.store.suppress(
            "sender", "critical_rule", until=None, reference=b"reference", now=100
        )
        self.store.schedule_action(
            "sender",
            reason="critical_rule",
            reference=b"reference",
            execute_at=100,
            expected_revision=state.revision,
            now=100,
        )
        self.store.allow("sender", 101)
        # Recreate an intentionally stale row to exercise the preflight guard.
        self.store.schedule_action(
            "sender",
            reason="critical_rule",
            reference=b"reference",
            execute_at=102,
            expected_revision=state.revision,
            now=102,
        )

        self.assertIn(
            "stale pending actions require review",
            self.store.protect_preflight(),
        )

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
            self.assertEqual(store.get_mode(), "monitor")
            version = store._connection.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(version, 2)
            columns = {
                row[1]
                for row in store._connection.execute("PRAGMA table_info(sender_state)")
            }
            self.assertIn("challenge_message_id", columns)
            self.assertIn("challenge_action_reference", columns)
            tables = {
                row[0]
                for row in store._connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertIn("automated_messages", tables)
        finally:
            store.close()

    def test_v0_database_refuses_active_challenge(self) -> None:
        self.create_legacy_database("challenged")
        with self.assertRaises(StoreMigrationError):
            StateStore(self.path)

    def test_v1_database_adds_dialog_snapshot_table_compatibly(self) -> None:
        store = StateStore(self.path)
        store._connection.execute("DROP TABLE dialog_snapshots")
        store._connection.commit()
        store.close()

        reopened = StateStore(self.path)
        try:
            table = reopened._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='dialog_snapshots'"
            ).fetchone()
            self.assertIsNotNone(table)
            self.assertEqual(
                reopened._connection.execute("PRAGMA user_version").fetchone()[0],
                2,
            )
        finally:
            reopened.close()

    def test_v1_mode_and_sender_schema_migrate_to_v2(self) -> None:
        connection = sqlite3.connect(self.path)
        connection.executescript(
            """
            CREATE TABLE sender_state (
                sender_key TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK (status IN (
                    'unknown','challenge_issuing','challenge_archiving','challenged',
                    'provisional','allowed','quarantined')),
                challenge_id TEXT, answer_digest TEXT,
                challenge_expires_at INTEGER, challenge_message_id INTEGER,
                challenge_prompt TEXT, challenge_action_reference BLOB,
                guidance_sent INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL
            );
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO settings VALUES ('mode','enforce');
            INSERT INTO sender_state(sender_key,status,updated_at)
                VALUES ('sender','allowed',100);
            PRAGMA user_version=1;
            """
        )
        connection.close()
        store = StateStore(self.path)
        try:
            self.assertEqual(store.get_mode(), "protect")
            self.assertEqual(store.sender("sender").status, "allowed")
            self.assertEqual(store.sender("sender").revision, 0)
            self.assertEqual(
                store._connection.execute("PRAGMA user_version").fetchone()[0], 2
            )
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
