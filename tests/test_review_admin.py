from __future__ import annotations

import tempfile
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

from telethon import functions

from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.review_admin import ReviewAdminServer
from tg_pm_gatekeeper.store import StateStore


class FakeTelegramClient:
    def __init__(self) -> None:
        self.requests: list[object] = []

    async def get_messages(self, peer, ids):
        return SimpleNamespace(message="transient-canary", media=None)

    async def get_entity(self, peer):
        return SimpleNamespace(first_name="Test", last_name="Sender", username=None)

    async def __call__(self, request):
        self.requests.append(request)


class ReviewAdminTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")
        self.protector = IdentifierProtector(b"k" * 32)
        self.client = FakeTelegramClient()
        self.server = ReviewAdminServer(
            Path(self.temp.name) / "review.sock",
            self.store,
            self.protector,
            self.client,
            mute_days=30,
        )
        reference = self.protector.seal_review_reference(123456789, -987654321, 42)
        self.review_id = self.store.enqueue_review(
            "sender",
            reference,
            "would_quarantine",
            '["HR-01_LINK_BUTTON"]',
            "{}",
            700,
            100,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    async def test_show_fetches_message_without_persisting_it(self) -> None:
        status, _, response = await self.server._dispatch(
            "GET", f"/review/{self.review_id}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"transient-canary", response)
        self.assertIn(b'http-equiv="refresh" content="30"', response)
        self.assertIn(b"Live connection", response)
        database = (Path(self.temp.name) / "state.sqlite3").read_bytes()
        self.assertNotIn(b"transient-canary", database)

    async def test_queue_page_exposes_fresh_connection_feedback(self) -> None:
        response = self.server._index_page()
        self.assertIn(b'http-equiv="refresh" content="10"', response)
        self.assertIn(b"Live connection", response)
        self.assertIn(b"Response ", response)
        self.assertIn(b"Connection check repeats every 10 seconds", response)

    async def test_review_page_uses_one_aligned_component_rail(self) -> None:
        status, _, response = await self.server._dispatch(
            "GET", f"/review/{self.review_id}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(
            b".decision-panel{position:relative;width:calc(100% - 2.5rem);"
            b"max-width:1080px",
            response,
        )
        self.assertNotIn(b".decision-panel h2{max-width:", response)
        self.assertIn(
            b".actions{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))",
            response,
        )
        self.assertIn(b"button{width:100%;min-height:3.25rem", response)

    async def test_admin_server_uses_owner_only_unix_socket(self) -> None:
        await self.server.start()
        try:
            self.assertTrue(stat.S_ISSOCK(self.server.socket_path.stat().st_mode))
            self.assertEqual(
                stat.S_IMODE(self.server.socket_path.stat().st_mode), 0o600
            )
        finally:
            await self.server.stop()
        self.assertFalse(self.server.socket_path.exists())

    async def test_legitimate_decision_allows_and_erases_reference(self) -> None:
        body = urlencode(
            {"token": self.server._csrf_token, "action": "legitimate"}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/")
        self.assertEqual(self.store.sender("sender").status, "allowed")
        self.assertIsNone(self.store.review_item(self.review_id).reference)

    async def test_spam_decision_performs_explicit_telegram_actions(self) -> None:
        body = urlencode(
            {"token": self.server._csrf_token, "action": "spam"}
        ).encode()
        status, _, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(len(self.client.requests), 2)
        self.assertIsInstance(
            self.client.requests[0], functions.folders.EditPeerFoldersRequest
        )
        self.assertEqual(self.store.sender("sender").status, "quarantined")


if __name__ == "__main__":
    unittest.main()
