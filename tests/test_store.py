# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tg_pm_gatekeeper.store import (
    CAMPAIGN_WINDOW_SECONDS,
    SENDER_LINKED_TABLES,
    DialogSnapshot,
    StateStore,
    StoreMigrationError,
)


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

    def test_outbound_reserve_sender_limit_and_status_metrics(self) -> None:
        common = {
            "limit": 5,
            "notice_reserve": 2,
            "notice_sender_limit": 2,
            "now": 1000,
        }
        for index in range(3):
            self.assertTrue(
                self.store.claim_outbound_slot(
                    **common,
                    sender_key=f"challenge-{index}",
                    category="challenge",
                )
            )
        self.assertFalse(
            self.store.claim_outbound_slot(
                **common, sender_key="challenge-blocked", category="challenge"
            )
        )
        for _ in range(2):
            self.assertTrue(
                self.store.claim_outbound_slot(
                    **common, sender_key="notice-sender", category="notice"
                )
            )
        self.assertFalse(
            self.store.claim_outbound_slot(
                **common, sender_key="notice-sender", category="notice"
            )
        )
        self.assertFalse(
            self.store.claim_outbound_slot(
                **common, sender_key="other-notice-sender", category="notice"
            )
        )
        self.assertEqual(
            self.store.outbound_statistics(now=1000),
            {
                "outbound_total_1h": 5,
                "outbound_challenge_1h": 3,
                "outbound_notice_1h": 2,
                "outbound_quota_rejected_1h": 3,
            },
        )
        self.assertEqual(self.store.statistics(now=1000)["outbound_total_1h"], 5)

    def test_outbound_claim_is_atomic_across_connections(self) -> None:
        path = Path(self.temp.name) / "concurrent.sqlite3"
        seed = StateStore(path)
        seed.close()
        barrier = threading.Barrier(10)

        def claim(index: int) -> bool:
            store = StateStore(path)
            try:
                barrier.wait()
                return store.claim_outbound_slot(
                    limit=4,
                    notice_reserve=0,
                    notice_sender_limit=3,
                    sender_key=f"sender-{index}",
                    category="challenge",
                    now=1000,
                )
            finally:
                store.close()

        with ThreadPoolExecutor(max_workers=10) as executor:
            outcomes = list(executor.map(claim, range(10)))

        self.assertEqual(sum(outcomes), 4)
        verify = StateStore(path)
        try:
            self.assertEqual(verify.outbound_statistics(now=1000)["outbound_total_1h"], 4)
            self.assertEqual(
                verify.outbound_statistics(now=1000)["outbound_quota_rejected_1h"],
                6,
            )
        finally:
            verify.close()

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

    def test_operator_artifact_cleanup_survives_restart_and_retries(self) -> None:
        self.store.schedule_operator_artifacts([10, 11, 10], 200)
        self.assertEqual(self.store.next_operator_artifact_delete_at(), 200)
        self.assertEqual(self.store.due_operator_artifacts(199), [])
        self.assertEqual(
            self.store.statistics(now=199)["operator_cleanup_pending"], 2
        )

        self.store.close()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")
        self.assertEqual(self.store.due_operator_artifacts(200), [(10, 0), (11, 0)])

        self.store.retry_operator_artifacts([10], 230)
        self.store.complete_operator_artifacts([11])
        self.assertEqual(self.store.due_operator_artifacts(229), [])
        self.assertEqual(self.store.due_operator_artifacts(230), [(10, 1)])
        statistics = self.store.statistics(now=230)
        self.assertEqual(statistics["operator_cleanup_pending"], 1)
        self.assertEqual(statistics["operator_cleanup_retrying"], 1)

        self.store.complete_operator_artifacts([10])
        self.assertIsNone(self.store.next_operator_artifact_delete_at())
        self.assertEqual(
            self.store.statistics(now=230)["operator_cleanup_pending"], 0
        )

    def test_heartbeat_health(self) -> None:
        self.store.heartbeat(100)
        self.assertTrue(self.store.healthy(now=95))
        self.assertFalse(self.store.healthy(now=94))
        self.assertTrue(self.store.healthy(now=150))
        self.assertFalse(self.store.healthy(now=221))

    def test_dialog_snapshot_round_trip_and_clear(self) -> None:
        snapshot = DialogSnapshot(folder_id=2, silent=True, mute_until=500)
        self.store.save_dialog_snapshot("sender", snapshot)
        self.assertEqual(self.store.dialog_snapshot("sender"), snapshot)
        self.store.clear_dialog_snapshot("sender")
        self.assertIsNone(self.store.dialog_snapshot("sender"))

    def test_enforcement_review_is_visible_only_for_active_restriction(self) -> None:
        self.store.save_enforcement_review(
            "sender",
            reference=b"sealed-reference",
            envelope=b"encrypted-content",
            reason="challenge_pending",
            expires_at=800,
            now=100,
        )
        self.assertIsNone(self.store.enforcement_review("sender", now=101))
        self.store.suppress(
            "sender", "attempts_exhausted", until=700, reference=b"ref", now=200
        )
        self.assertTrue(
            self.store.activate_enforcement_review(
                "sender", "attempts_exhausted", 800, now=200
            )
        )
        item = self.store.enforcement_review("sender", now=201)
        self.assertIsNotNone(item)
        self.assertEqual(item.reason, "attempts_exhausted")
        self.assertEqual(item.status, "suppressed")
        self.store.allow("sender", 300)
        self.assertIsNone(self.store.enforcement_review("sender", now=301))

    def test_enforcement_statistics_distinguish_legacy_manual_spam(self) -> None:
        review_id = self.store.enqueue_review(
            "legacy",
            b"sealed-reference",
            "would_quarantine",
            "[]",
            "{}",
            800,
            100,
        )
        self.store.quarantine("legacy", 200)
        self.assertTrue(self.store.decide_review(review_id, "spam", 200))

        stats = self.store.enforcement_statistics(now=300)
        self.assertEqual(stats["quarantined"], 1)
        self.assertEqual(stats["reviewable"], 0)
        self.assertEqual(stats["unreviewable"], 1)
        self.assertEqual(stats["reason:manual_spam"], 1)

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
        self.assertIsNotNone(self.store.claim_action(action_id, now=100))
        self.store.set_mode("monitor")
        self.assertEqual(self.store.pending_actions(), [])
        self.assertEqual(self.store.statistics(now=100)["pending_reviews"], 1)

        other = self.store.suppress(
            "other", "permanent_suppression", until=None, reference=b"other", now=200
        )
        other_action = self.store.schedule_action(
            "other",
            reason="permanent_suppression",
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

    def test_configured_retention_applies_to_generated_exception_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(
                Path(directory) / "state.sqlite3",
                pending_review_retention_days=1,
            )
            try:
                state = store.suppress(
                    "sender",
                    "permanent_suppression",
                    until=None,
                    reference=b"reference",
                    now=100,
                )
                store.schedule_action(
                    "sender",
                    reason="permanent_suppression",
                    reference=b"reference",
                    execute_at=200,
                    expected_revision=state.revision,
                    now=100,
                )
                store.set_mode("protect")
                before = int(time.time())
                store.set_mode("monitor")
                review = store.review_items(now=before)[0]
                self.assertGreaterEqual(review.expires_at, before + 86400)
                self.assertLessEqual(review.expires_at, before + 86401)

                other = store.suppress(
                    "other",
                    "permanent_suppression",
                    until=None,
                    reference=b"other",
                    now=300,
                )
                other_id = store.schedule_action(
                    "other",
                    reason="permanent_suppression",
                    reference=b"other",
                    execute_at=400,
                    expected_revision=other.revision,
                    now=300,
                )
                action = next(
                    action
                    for action in store.pending_actions()
                    if action.id == other_id
                )
                assert action is not None
                store.enqueue_action_failure(action, now=500)
                generated = next(
                    item for item in store.review_items(now=500) if item.sender_key == "other"
                )
                self.assertEqual(generated.expires_at, 500 + 86400)
            finally:
                store.close()

    def test_protect_preflight_rejects_stale_pending_action(self) -> None:
        self.store.heartbeat()
        state = self.store.suppress(
            "sender", "permanent_suppression", until=None, reference=b"reference", now=100
        )
        self.store.schedule_action(
            "sender",
            reason="permanent_suppression",
            reference=b"reference",
            execute_at=100,
            expected_revision=state.revision,
            now=100,
        )
        self.store.allow("sender", 101)
        # Recreate an intentionally stale row to exercise the preflight guard.
        self.store.schedule_action(
            "sender",
            reason="permanent_suppression",
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
        self.assertEqual(self.store.statistics(now=100)["pending_reviews"], 1)
        self.assertTrue(self.store.decide_review(review_id, "legitimate", 200))
        item = self.store.review_item(review_id)
        self.assertIsNotNone(item)
        self.assertEqual(item.status, "legitimate")
        self.assertIsNone(item.reference)
        self.assertEqual(self.store.statistics(now=200)["pending_reviews"], 0)

    def test_statistics_exclude_expired_pending_reviews_before_prune(self) -> None:
        self.store.enqueue_review(
            "sender", b"sealed-reference", "would_challenge", "[]", "{}", 200, 100
        )

        self.assertEqual(self.store.statistics(now=199)["pending_reviews"], 1)
        self.assertEqual(self.store.statistics(now=200)["pending_reviews"], 0)

    def test_statistics_report_recent_adaptive_decisions_without_payloads(self) -> None:
        self.store.record_decision(
            "sender-a",
            detector="deterministic",
            signals='[{"code":"LOW_INFORMATION_OPENER"}]',
            assessment="standard",
            risk_score=5,
            model_version=None,
            decision_basis="risk_below_strict_threshold",
            planned_action="standard_challenge",
            actual_action="challenged",
            policy_version="adaptive-v2",
            now=100,
        )
        self.store.record_decision(
            "sender-b",
            detector="deterministic",
            signals='[{"code":"REPEATED_CAMPAIGN"}]',
            assessment="permanent_suppression",
            risk_score=110,
            model_version=None,
            decision_basis="repeated_campaign_destructive_gate",
            planned_action="permanent_suppression",
            actual_action="suppressed",
            policy_version="adaptive-v1",
            now=200,
        )
        stats = self.store.statistics(now=300)
        self.assertEqual(stats["standard_challenge_7d"], 1)
        self.assertEqual(stats["strict_challenge_7d"], 0)
        self.assertEqual(stats["permanent_suppression_7d"], 1)
        self.assertEqual(stats["repeated_campaign_7d"], 1)

    def test_campaign_observation_counts_distinct_recent_senders(self) -> None:
        self.assertEqual(self.store.observe_campaign("digest", "sender-a", now=100), 1)
        self.assertEqual(self.store.observe_campaign("digest", "sender-a", now=200), 1)
        self.assertEqual(self.store.observe_campaign("digest", "sender-b", now=300), 2)
        self.assertEqual(
            self.store.observe_campaign(
                "boundary",
                "sender-a",
                now=100,
            ),
            1,
        )
        self.assertEqual(
            self.store.observe_campaign(
                "boundary",
                "sender-b",
                now=100 + CAMPAIGN_WINDOW_SECONDS,
            ),
            2,
        )
        self.assertEqual(
            self.store.observe_campaign(
                "expired",
                "sender-a",
                now=100,
            ),
            1,
        )
        self.assertEqual(
            self.store.observe_campaign(
                "expired",
                "sender-b",
                now=300 + CAMPAIGN_WINDOW_SECONDS + 1,
            ),
            1,
        )

    def test_prune_uses_campaign_observation_window(self) -> None:
        self.store.observe_campaign("expired", "sender-a", now=100)
        self.store.observe_campaign(
            "retained",
            "sender-b",
            now=100 + CAMPAIGN_WINDOW_SECONDS,
        )
        self.store.prune(30, now=100 + CAMPAIGN_WINDOW_SECONDS + 1)
        rows = self.store._connection.execute(
            "SELECT fingerprint FROM campaign_events ORDER BY fingerprint"
        ).fetchall()
        self.assertEqual([row["fingerprint"] for row in rows], ["retained"])

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
            '[{"code":"MULTIPLE_LINK_BUTTONS","source":"button","weight":25}]',
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

    def test_archived_permanent_restrictions_are_partitioned_after_work_finishes(
        self,
    ) -> None:
        state = self.store.suppress(
            "sender", "manual_permanent_suppression", until=None,
            reference=b"reference", now=100,
        )
        self.assertTrue(self.store.archive_restriction("sender", 110))
        action_id = self.store.schedule_action(
            "sender", reason="manual_permanent_suppression", reference=b"reference",
            execute_at=120, expected_revision=state.revision, now=110,
        )
        self.assertEqual(self.store.active_restriction_count(archived=False), 1)
        self.assertEqual(self.store.active_restriction_count(archived=True), 0)

        self.assertTrue(self.store.finish_action(action_id, "completed", 120))
        self.assertEqual(self.store.active_restriction_count(archived=False), 0)
        self.assertEqual(self.store.active_restriction_count(archived=True), 1)
        item = self.store.active_restrictions(archived=True)[0]
        self.assertEqual(item.archived_at, 110)
        self.assertFalse(item.has_open_actions)

    def test_enforcement_statistics_follow_list_partitions(self) -> None:
        self.store.quarantine("attention-quarantine", 100)
        self.store.suppress(
            "attention-temporary", "challenge_timeout", until=900, now=100,
            restriction_reference=b"identity",
        )
        self.store.suppress(
            "archived", "permanent_suppression", until=None, now=100,
        )
        self.assertTrue(self.store.archive_restriction("archived", 110))

        attention = self.store.enforcement_statistics(archived=False, now=200)
        archived = self.store.enforcement_statistics(archived=True, now=200)
        everything = self.store.enforcement_statistics(now=200)

        self.assertEqual((attention["quarantined"], attention["suppressed"]), (1, 1))
        self.assertEqual((archived["quarantined"], archived["suppressed"]), (0, 1))
        self.assertEqual((everything["quarantined"], everything["suppressed"]), (1, 2))
        self.assertEqual(
            attention["quarantined"] + attention["suppressed"],
            self.store.active_restriction_count(archived=False),
        )
        self.assertEqual(
            archived["suppressed"], self.store.active_restriction_count(archived=True)
        )
        self.assertNotIn("reason:permanent_suppression", attention)
        self.assertEqual(archived["reason:permanent_suppression"], 1)
        self.assertEqual(attention["unidentified"], 1)
        self.assertEqual(archived["unidentified"], 1)
        self.assertEqual(everything["unidentified"], 2)

    def test_reason_filter_matches_displayed_derived_reason(self) -> None:
        review_id = self.store.enqueue_review(
            "legacy", b"reference", "would_quarantine", "[]", "{}", 800, 100
        )
        self.store.quarantine("legacy", 200)
        self.assertTrue(self.store.decide_review(review_id, "spam", 200))
        self.store.quarantine("unknown-reason", 200)

        for reason, sender_key in (
            ("manual_spam", "legacy"),
            ("reason_unavailable", "unknown-reason"),
        ):
            with self.subTest(reason=reason):
                self.assertEqual(
                    self.store.active_restriction_count(archived=False, reason=reason), 1
                )
                items = self.store.active_restrictions(archived=False, reason=reason)
                self.assertEqual([item.sender_key for item in items], [sender_key])
                self.assertEqual(items[0].reason, reason)

    def test_forget_archived_restriction_erases_sender_linked_data(self) -> None:
        self.store.suppress(
            "sender", "manual_permanent_suppression", until=None,
            restriction_reference=b"identity", now=100,
        )
        self.store.archive_restriction("sender", 110)
        self.store.audit("sender", "TEST", "recorded", 100)
        self.store.save_dialog_snapshot(
            "sender", DialogSnapshot(folder_id=1, silent=True, mute_until=200)
        )
        self.store.observe_campaign("fingerprint", "sender", now=100)

        self.assertTrue(self.store.forget_restriction("sender"))
        self.assertEqual(self.store.sender("sender").status, "unknown")
        for table, statement in (
            ("sender_state", "SELECT COUNT(*) FROM sender_state WHERE sender_key=?"),
            ("audit", "SELECT COUNT(*) FROM audit WHERE sender_key=?"),
            (
                "dialog_snapshots",
                "SELECT COUNT(*) FROM dialog_snapshots WHERE sender_key=?",
            ),
            (
                "campaign_events",
                "SELECT COUNT(*) FROM campaign_events WHERE sender_key=?",
            ),
        ):
            count = self.store._connection.execute(
                statement, ("sender",)
            ).fetchone()[0]
            self.assertEqual(count, 0, table)

    def test_forget_covers_every_sender_linked_table(self) -> None:
        tables = [
            str(row[0])
            for row in self.store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        ]
        linked = {
            table
            for table in tables
            if any(
                column[1] == "sender_key"
                for column in self.store._connection.execute(
                    f"PRAGMA table_info({table})"
                )
            )
        }
        self.assertEqual(linked, set(SENDER_LINKED_TABLES))
        self.assertEqual(SENDER_LINKED_TABLES[-1], "sender_state")

    def test_release_expired_suppression_clears_restriction_data(self) -> None:
        state = self.store.suppress(
            "sender", "challenge_timeout", until=200,
            restriction_reference=b"identity", now=100,
        )
        self.store.enqueue_review(
            "sender", b"review-reference", "would_quarantine", "[]", "{}",
            expires_at=500_000, now=100,
        )
        self.store.save_enforcement_review(
            "sender", reference=b"reference", envelope=b"envelope",
            reason="challenge_timeout", expires_at=500_000, now=100,
        )
        self.store.save_dialog_snapshot(
            "sender", DialogSnapshot(folder_id=1, silent=True, mute_until=200)
        )
        action_id = self.store.schedule_action(
            "sender", reason="challenge_timeout", reference=b"action-reference",
            execute_at=150, expected_revision=state.revision, now=100,
        )

        self.assertFalse(self.store.release_expired_suppression("sender", 199))
        self.assertTrue(self.store.release_expired_suppression("sender", 200))

        released = self.store.sender("sender")
        self.assertEqual(released.status, "unknown")
        self.assertEqual(released.revision, state.revision + 1)
        self.assertIsNone(released.restriction_reference)
        for table in ("enforcement_reviews", "review_queue", "dialog_snapshots"):
            count = self.store._connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE sender_key='sender'"  # noqa: S608
            ).fetchone()[0]
            self.assertEqual(count, 0, table)
        action = self.store._connection.execute(
            "SELECT status,reference FROM pending_actions WHERE id=?", (action_id,)
        ).fetchone()
        self.assertEqual(tuple(action), ("cancelled", b""))
        self.assertFalse(self.store.release_expired_suppression("sender", 300))

    def test_prune_releases_expired_temporary_and_forgets_old_archive(self) -> None:
        temporary_state = self.store.suppress(
            "temporary", "challenge_timeout", until=200,
            restriction_reference=b"identity", now=100,
        )
        self.store.enqueue_review(
            "temporary", b"review-reference", "would_quarantine", "[]", "{}",
            expires_at=500_000, now=100,
        )
        action_id = self.store.schedule_action(
            "temporary", reason="challenge_timeout", reference=b"action-reference",
            execute_at=150, expected_revision=temporary_state.revision, now=100,
        )
        self.store.save_dialog_snapshot(
            "temporary", DialogSnapshot(folder_id=1, silent=True, mute_until=200)
        )
        self.store.suppress("old", "permanent_suppression", until=None, now=100)
        self.store.archive_restriction("old", 100)
        self.store.suppress("new", "permanent_suppression", until=None, now=100)
        self.store.archive_restriction("new", 150_000)

        metrics = self.store.prune(
            30, now=200_000, archived_restriction_retention_days=1
        )

        self.assertEqual(metrics["temporary_released"], 1)
        self.assertEqual(metrics["auto_forgotten"], 1)
        self.assertEqual(self.store.sender("temporary").status, "unknown")
        self.assertIsNone(self.store.dialog_snapshot("temporary"))
        self.assertEqual(
            self.store._connection.execute(
                "SELECT COUNT(*) FROM review_queue WHERE sender_key='temporary'"
            ).fetchone()[0], 0,
        )
        action = self.store._connection.execute(
            "SELECT status,reference FROM pending_actions WHERE id=?", (action_id,)
        ).fetchone()
        self.assertEqual(tuple(action), ("cancelled", b""))
        self.assertEqual(self.store.sender("old").status, "unknown")
        self.assertEqual(self.store.sender("new").status, "suppressed")
        second_connection = StateStore(self.store.path)
        try:
            self.assertEqual(second_connection.statistics()["auto_forgotten"], 1)
            self.assertEqual(second_connection.statistics()["temporary_released"], 1)
        finally:
            second_connection.close()

    def test_old_failed_action_blocks_auto_forget_after_audit_retention(self) -> None:
        state = self.store.suppress("sender", "permanent_suppression", until=None, now=100)
        self.store.archive_restriction("sender", 100)
        action_id = self.store.schedule_action(
            "sender", reason="permanent_suppression", reference=b"reference",
            execute_at=110, expected_revision=state.revision, now=100,
        )
        self.store.finish_action(action_id, "failed", 110)

        metrics = self.store.prune(
            1, now=200_000, archived_restriction_retention_days=1
        )

        self.assertEqual(metrics["auto_forgotten"], 0)
        self.assertEqual(metrics["auto_forget_skipped"], 1)
        self.assertEqual(self.store.sender("sender").status, "suppressed")
        self.assertEqual(self.store.active_restriction_count(archived=False), 1)

    def test_database_statistics_are_aggregate_and_path_free(self) -> None:
        statistics = self.store.statistics()
        self.assertGreater(statistics["database_page_count"], 0)
        self.assertGreater(statistics["database_page_size"], 0)
        self.assertNotIn(self.temp.name, str(statistics))


class StoreMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "legacy.sqlite3"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_v6_database_adds_operator_artifact_cleanup_queue(self) -> None:
        store = StateStore(self.path)
        store._connection.executescript(
            "DROP TABLE operator_artifacts; PRAGMA user_version=6;"
        )
        store.close()

        reopened = StateStore(self.path)
        try:
            table = reopened._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='operator_artifacts'"
            ).fetchone()
            self.assertIsNotNone(table)
            self.assertEqual(
                reopened._connection.execute("PRAGMA user_version").fetchone()[0], 8
            )
            self.assertEqual(reopened.due_operator_artifacts(100), [])
        finally:
            reopened.close()

    def test_v7_database_adds_archive_column_without_archiving_existing_rows(self) -> None:
        store = StateStore(self.path)
        store.suppress("sender", "permanent_suppression", until=None, now=100)
        store._connection.execute("DROP INDEX sender_state_archive_idx")
        store._connection.execute("ALTER TABLE sender_state DROP COLUMN archived_at")
        store._connection.execute("PRAGMA user_version=7")
        store.close()

        reopened = StateStore(self.path)
        try:
            columns = {
                row["name"]
                for row in reopened._connection.execute(
                    "PRAGMA table_info(sender_state)"
                )
            }
            self.assertIn("archived_at", columns)
            self.assertIsNone(reopened.active_restriction("sender").archived_at)
            self.assertEqual(
                reopened._connection.execute("PRAGMA user_version").fetchone()[0], 8
            )
        finally:
            reopened.close()

    def test_v7_archive_migration_rolls_back_on_index_conflict(self) -> None:
        store = StateStore(self.path)
        store._connection.execute("DROP INDEX sender_state_archive_idx")
        store._connection.execute("ALTER TABLE sender_state DROP COLUMN archived_at")
        store._connection.execute(
            "CREATE TABLE sender_state_archive_idx (collision INTEGER)"
        )
        store._connection.execute("PRAGMA user_version=7")
        store.close()

        with self.assertRaises(sqlite3.OperationalError):
            StateStore(self.path)
        connection = sqlite3.connect(self.path)
        try:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(sender_state)")
            }
            self.assertNotIn("archived_at", columns)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 7)
        finally:
            connection.close()

    def test_unsupported_schema_is_refused_without_mutation(self) -> None:
        for version in (5, 9):
            with self.subTest(version=version):
                self.path.unlink(missing_ok=True)
                store = StateStore(self.path)
                store.close()
                connection = sqlite3.connect(self.path)
                connection.execute(f"PRAGMA user_version={version}")
                connection.close()

                with self.assertRaisesRegex(
                    StoreMigrationError,
                    f"unsupported database schema version: {version}",
                ):
                    StateStore(self.path)

                connection = sqlite3.connect(self.path)
                try:
                    self.assertEqual(
                        connection.execute("PRAGMA user_version").fetchone()[0],
                        version,
                    )
                finally:
                    connection.close()

if __name__ == "__main__":
    unittest.main()
