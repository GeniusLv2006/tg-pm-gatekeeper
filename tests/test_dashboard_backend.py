# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from tg_pm_gatekeeper.crypto import ActiveCaseProtector, IdentifierProtector
from tg_pm_gatekeeper.dashboard_backend import (
    DashboardBackendError,
    InProcessDashboardBackend,
)
from tg_pm_gatekeeper.service import GatekeeperService
from tg_pm_gatekeeper.store import StateStore


class FakeTelegramClient:
    def __init__(self) -> None:
        self.message = SimpleNamespace(message="transient-canary", media=None)

    async def get_messages(self, _peer, ids):
        return self.message if ids == 42 else None

    async def get_entity(self, peer):
        sender = SimpleNamespace(first_name="Test", last_name="Sender", username="test")
        return [sender for _ in peer] if isinstance(peer, list) else sender


class DashboardBackendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")
        self.protector = IdentifierProtector(b"k" * 32)
        self.service = GatekeeperService(
            self.store,
            self.protector,
            active_case_protector=ActiveCaseProtector(b"r" * 32),
        )
        self.client = FakeTelegramClient()
        self.backend = InProcessDashboardBackend(
            self.store,
            self.service,
            self.client,
            mute_days=30,
        )
        reference = self.protector.seal_review_reference(123456789, 987654321, 42)
        self.review_id = self.store.enqueue_review(
            "a" * 64,
            reference,
            "would_quarantine",
            '[]',
            '{}',
            int(time.time()) + 600,
            int(time.time()),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    async def test_read_models_are_json_serializable_and_content_is_transient(
        self,
    ) -> None:
        overview = await self.backend.request("overview", {})
        listing = await self.backend.request("reviews.list", {"page": 1})
        detail = await self.backend.request(
            "reviews.detail", {"review_id": self.review_id}
        )

        json.dumps({"overview": overview, "listing": listing, "detail": detail})
        self.assertEqual(detail["message"], "transient-canary")
        self.assertNotIn(
            b"transient-canary",
            (Path(self.temp.name) / "state.sqlite3").read_bytes(),
        )

    async def test_decision_is_atomic_and_erases_review_reference(self) -> None:
        result = await self.backend.request(
            "reviews.decide",
            {"review_id": self.review_id, "action": "dismiss"},
        )

        self.assertEqual(result, {"outcome": "completed"})
        self.assertIsNone(self.store.review_item(self.review_id).reference)
        with self.assertRaisesRegex(DashboardBackendError, "review_already_decided"):
            await self.backend.request(
                "reviews.decide",
                {"review_id": self.review_id, "action": "dismiss"},
            )

    async def test_unknown_method_and_invalid_identifiers_fail_closed(self) -> None:
        with self.assertRaisesRegex(DashboardBackendError, "unknown_method"):
            await self.backend.request("database.query", {})
        with self.assertRaisesRegex(DashboardBackendError, "invalid_request"):
            await self.backend.request("cases.detail", {"sender_key": "not-a-key"})


if __name__ == "__main__":
    unittest.main()
