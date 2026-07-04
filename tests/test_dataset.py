# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from tg_pm_gatekeeper.dataset import DatasetProtector, TrainingStore


class DatasetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "training.sqlite3"
        self.protector = DatasetProtector(b"d" * 32)
        self.store = TrainingStore(self.path, self.protector)
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
                "features": {"has_link": True},
                "signals": ["HR-03_PROMOTION_WITH_LINK"],
                "policy_version": "rules-v2",
            },
            weak_label="uncertain",
            retention_days=30,
            max_per_sender=3,
            now=self.now,
        )

    def test_content_is_encrypted_and_file_is_private(self) -> None:
        sample_id = self.collect(1)
        self.assertIsNotNone(sample_id)
        self.assertEqual(
            self.store.sample(sample_id).payload["text"], "private-canary-1"
        )
        self.assertNotIn(b"private-canary-1", self.path.read_bytes())
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_tampered_or_wrong_key_is_rejected(self) -> None:
        sample_id = self.collect(1)
        wrong_key_store = TrainingStore(self.path, DatasetProtector(b"w" * 32))
        try:
            with self.assertRaises(ValueError):
                wrong_key_store.sample(sample_id)
        finally:
            wrong_key_store.close()
        envelope = bytes(
            self.store._connection.execute(
                "SELECT envelope FROM samples WHERE id=?", (sample_id,)
            ).fetchone()[0]
        )
        self.store._connection.execute(
            "UPDATE samples SET envelope=? WHERE id=?",
            (envelope[:-1] + bytes([envelope[-1] ^ 1]), sample_id),
        )
        self.store._connection.commit()
        with self.assertRaises(ValueError):
            self.store.sample(sample_id)

    def test_enforcement_content_uses_an_independent_authenticated_envelope(self) -> None:
        payload = {"text": "review-canary", "quote_text": "quoted-canary"}
        envelope = self.protector.seal_enforcement(payload)
        self.assertEqual(self.protector.open_enforcement(envelope), payload)
        with self.assertRaises(ValueError):
            self.protector.open(envelope)
        with self.assertRaises(ValueError):
            DatasetProtector(b"w" * 32).open_enforcement(envelope)
        with self.assertRaises(ValueError):
            self.protector.open_enforcement(
                envelope[:-1] + bytes([envelope[-1] ^ 1])
            )

    def test_unknown_schema_version_is_rejected(self) -> None:
        alternate = Path(self.temp.name) / "future.sqlite3"
        connection = sqlite3.connect(alternate)
        connection.execute("PRAGMA user_version=99")
        connection.close()

        with self.assertRaisesRegex(ValueError, "unsupported dataset schema"):
            TrainingStore(alternate, self.protector)

    def test_per_sender_limit_deduplication_and_expiry(self) -> None:
        self.assertIsNotNone(self.collect(1))
        self.assertIsNone(self.collect(1))
        self.assertIsNotNone(self.collect(2))
        self.assertIsNotNone(self.collect(3))
        self.assertIsNone(self.collect(4))
        self.assertEqual(self.store.prune(now=self.now + 30 * 86400), 3)

    def test_label_export_and_purge(self) -> None:
        first = self.collect(1)
        second = self.collect(2, sender_id=456)
        self.assertTrue(self.store.label(first, "spam"))
        output = Path(self.temp.name) / "samples.jsonl"
        self.assertEqual(self.store.export(output), 1)
        row = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(row["label"], "spam")
        self.assertEqual(row["label_source"], "manual")
        self.assertEqual(row["sender_group"], "sender-000001")
        self.assertNotIn("sender_token", row)
        self.assertNotIn("message_id", row)
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.store.export(output)
        self.assertEqual(self.store.purge(), 2)
        self.assertIsNone(self.store.sample(second))

    def test_terminal_outcome_reencrypts_payload_and_updates_weak_label(self) -> None:
        sample_id = self.collect(1)
        self.assertEqual(
            self.store.update_sender_outcome(
                123, weak_label="legitimate_candidate", actual_action="provisional"
            ),
            1,
        )
        sample = self.store.sample(sample_id)
        self.assertEqual(sample.weak_label, "legitimate_candidate")
        self.assertEqual(sample.payload["actual_action"], "provisional")
        self.assertNotIn(b"provisional", self.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
