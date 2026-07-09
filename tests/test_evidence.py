# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from tg_pm_gatekeeper.evidence import EvidenceProtector, EvidenceStore


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "evidence.sqlite3"
        self.protector = EvidenceProtector(b"d" * 32)
        self.store = EvidenceStore(self.path, self.protector)
        self.now = int(time.time())

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def collect(self, message_id: int, *, sender_id: int = 123) -> int | None:
        return self.store.collect(
            sender_id=sender_id,
            message_id=message_id,
            payload={
                "text": f"private-canary-{message_id}",
                "button_texts": ["Open private offer"],
                "urls": [
                    {
                        "url": "https://example.invalid/private/path?token=secret",
                        "kind": "external_web",
                        "sources": ["message"],
                    }
                ],
                "features": {"has_link": True},
                "signals": ["HR-03_PROMOTION_WITH_LINK"],
                "policy_version": "rules-v2",
            },
            automatic_hint="uncertain",
            retention_days=7,
            max_per_sender=3,
            now=self.now,
        ).record_id

    def test_content_is_encrypted_and_file_is_private(self) -> None:
        record_id = self.collect(1)
        self.assertIsNotNone(record_id)
        record = self.store.record(record_id)
        self.assertEqual(record.payload["text"], "private-canary-1")
        self.assertEqual(record.payload["button_texts"], ["Open private offer"])
        self.assertIn("private/path", record.payload["urls"][0]["url"])
        database = self.path.read_bytes()
        self.assertNotIn(b"private-canary-1", database)
        self.assertNotIn(b"Open private offer", database)
        self.assertNotIn(b"https://example.invalid", database)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_tampered_or_wrong_key_is_rejected(self) -> None:
        record_id = self.collect(1)
        wrong_key_store = EvidenceStore(self.path, EvidenceProtector(b"w" * 32))
        try:
            with self.assertRaises(ValueError):
                wrong_key_store.record(record_id)
        finally:
            wrong_key_store.close()
        envelope = bytes(
            self.store._connection.execute(
                "SELECT envelope FROM evidence_records WHERE id=?", (record_id,)
            ).fetchone()[0]
        )
        self.store._connection.execute(
            "UPDATE evidence_records SET envelope=? WHERE id=?",
            (envelope[:-1] + bytes([envelope[-1] ^ 1]), record_id),
        )
        self.store._connection.commit()
        with self.assertRaises(ValueError):
            self.store.record(record_id)

    def test_enforcement_content_uses_an_independent_authenticated_envelope(self) -> None:
        payload = {"text": "review-canary", "quote_text": "quoted-canary"}
        envelope = self.protector.seal_enforcement(payload)
        self.assertEqual(self.protector.open_enforcement(envelope), payload)
        with self.assertRaises(ValueError):
            self.protector.open(envelope)
        with self.assertRaises(ValueError):
            EvidenceProtector(b"w" * 32).open_enforcement(envelope)
        with self.assertRaises(ValueError):
            self.protector.open_enforcement(
                envelope[:-1] + bytes([envelope[-1] ^ 1])
            )

    def test_unknown_schema_version_is_rejected(self) -> None:
        alternate = Path(self.temp.name) / "future.sqlite3"
        connection = sqlite3.connect(alternate)
        connection.execute("PRAGMA user_version=99")
        connection.close()

        with self.assertRaisesRegex(ValueError, "unsupported evidence schema"):
            EvidenceStore(alternate, self.protector)

    def test_per_sender_limit_deduplication_and_expiry(self) -> None:
        self.assertIsNotNone(self.collect(1))
        self.assertIsNone(self.collect(1))
        self.assertIsNotNone(self.collect(2))
        self.assertIsNotNone(self.collect(3))
        self.assertIsNone(self.collect(4))
        self.assertEqual(self.store.prune(now=self.now + 7 * 86400), 3)

    def test_review_outcome_and_purge(self) -> None:
        first = self.collect(1)
        second = self.collect(2, sender_id=456)
        self.assertTrue(self.store.review(first, "correct"))
        self.assertEqual(self.store.record(first).review_outcome, "correct")
        self.assertEqual(self.store.statistics()["correct"], 1)
        self.assertEqual(self.store.purge(), 2)
        self.assertIsNone(self.store.record(second))

    def test_terminal_action_reencrypts_payload_and_updates_automatic_hint(self) -> None:
        record_id = self.collect(1)
        self.assertTrue(
            self.store.update_record_action(
                record_id,
                automatic_hint="legitimate_candidate",
                actual_action="provisional",
            )
        )
        record = self.store.record(record_id)
        self.assertEqual(record.automatic_hint, "legitimate_candidate")
        self.assertEqual(record.payload["actual_action"], "provisional")
        self.assertNotIn(b"provisional", self.path.read_bytes())

    def test_finalize_updates_only_latest_challenged_record(self) -> None:
        first = self.collect(1)
        second = self.collect(2)
        self.store.update_record_action(
            first, automatic_hint="uncertain", actual_action="would_challenge"
        )
        self.store.update_record_action(
            second, automatic_hint="uncertain", actual_action="challenged"
        )

        self.assertTrue(
            self.store.finalize_challenged_record(
                123,
                automatic_hint="legitimate_candidate",
                actual_action="provisional",
            )
        )
        self.assertEqual(
            self.store.record(first).payload["actual_action"], "would_challenge"
        )
        self.assertEqual(
            self.store.record(second).payload["actual_action"], "provisional"
        )
        self.assertFalse(
            self.store.finalize_challenged_record(
                123, automatic_hint="spam_candidate", actual_action="suppressed"
            )
        )

    def test_collection_statistics_are_rolling_and_pruned(self) -> None:
        self.collect(1)
        self.collect(1)
        self.collect(2)
        self.collect(3)
        self.collect(4)
        self.store.record_no_signal(self.now)
        self.store.collect(
            sender_id=456,
            message_id=1,
            payload={"schema_version": 1, "text": "", "signals": ["HR-02"]},
            automatic_hint="uncertain",
            retention_days=7,
            max_per_sender=3,
            sample_kind="structural",
            now=self.now,
        )

        stats = self.store.statistics(retention_days=7, now=self.now)
        self.assertEqual(stats["collection_collected_content"], 3)
        self.assertEqual(stats["collection_collected_structural"], 1)
        self.assertEqual(stats["collection_skipped_duplicate"], 1)
        self.assertEqual(stats["collection_skipped_sender_cap"], 1)
        self.assertEqual(stats["collection_skipped_no_signal"], 1)

        later = self.now + 8 * 86400
        self.store.prune(later, retention_days=7)
        stats = self.store.statistics(retention_days=7, now=later)
        self.assertEqual(stats["collection_collected_content"], 0)
        self.assertEqual(
            self.store._connection.execute(
                "SELECT COUNT(*) FROM collection_stats"
            ).fetchone()[0],
            0,
        )

    def test_legacy_dataset_database_is_discarded_without_migration(self) -> None:
        legacy_path = Path(self.temp.name) / "legacy-training.sqlite3"
        envelope = self.protector.seal({"schema_version": 2, "text": "legacy"})
        connection = sqlite3.connect(legacy_path)
        connection.executescript(
            """
            CREATE TABLE samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_token TEXT NOT NULL,
                message_token TEXT NOT NULL UNIQUE,
                envelope BLOB NOT NULL,
                weak_label TEXT NOT NULL,
                manual_label TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            PRAGMA user_version=1;
            """
        )
        connection.execute(
            "INSERT INTO samples(sender_token,message_token,envelope,weak_label,created_at,expires_at) "
            "VALUES (?,?,?,?,?,?)",
            ("sender", "message", envelope, "uncertain", self.now, self.now + 86400),
        )
        connection.commit()
        connection.close()

        migrated = EvidenceStore(legacy_path, self.protector)
        try:
            self.assertEqual(
                migrated._connection.execute("PRAGMA user_version").fetchone()[0], 1
            )
            self.assertEqual(migrated.statistics()["total"], 0)
            self.assertIsNone(
                migrated._connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='samples'"
                ).fetchone()
            )
        finally:
            migrated.close()


if __name__ == "__main__":
    unittest.main()
