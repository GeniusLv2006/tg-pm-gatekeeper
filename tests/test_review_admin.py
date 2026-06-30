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
from tg_pm_gatekeeper.service import GatekeeperService
from tg_pm_gatekeeper.store import StateStore


class FakeTelegramClient:
    def __init__(self) -> None:
        self.requests: list[object] = []
        self.entity_requests = 0

    async def get_messages(self, peer, ids):
        return SimpleNamespace(message="transient-canary", media=None)

    async def get_entity(self, peer):
        self.entity_requests += 1
        sender = SimpleNamespace(
            first_name="Test", last_name="Sender", username="testsender"
        )
        return [sender for _ in peer] if isinstance(peer, list) else sender

    async def __call__(self, request):
        self.requests.append(request)


class ReviewAdminTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")
        self.protector = IdentifierProtector(b"k" * 32)
        self.service = GatekeeperService(self.store, self.protector)
        self.client = FakeTelegramClient()
        self.cancelled: list[str] = []
        self.server = ReviewAdminServer(
            Path(self.temp.name) / "review.sock",
            self.store,
            self.service,
            self.client,
            mute_days=30,
            cancel_timeout=self.cancelled.append,
        )
        reference = self.protector.seal_review_reference(123456789, -987654321, 42)
        self.review_id = self.store.enqueue_review(
            "sender",
            reference,
            "would_quarantine",
            '["HR-01_MULTIPLE_LINK_BUTTONS"]',
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
        self.assertIn(b"Telegram ID", response)
        self.assertIn(b"123456789", response)
        self.assertIn(b'http-equiv="refresh" content="30"', response)
        self.assertIn(b"Live connection", response)
        database = (Path(self.temp.name) / "state.sqlite3").read_bytes()
        self.assertNotIn(b"transient-canary", database)
        self.assertNotIn(b"Test Sender", database)
        self.assertNotIn(b"testsender", database)
        self.assertNotIn(b"123456789", database)

    async def test_queue_page_exposes_fresh_connection_feedback(self) -> None:
        response = await self.server._index_page()
        self.assertIn(b'http-equiv="refresh" content="10"', response)
        self.assertIn(b"Live connection", response)
        self.assertIn(b"Response ", response)
        self.assertIn(b"Connection check repeats every 10 seconds", response)
        self.assertIn(b"Test Sender (@testsender)", response)
        self.assertIn(b"ID 123456789", response)

    async def test_queue_identity_uses_short_lived_memory_cache(self) -> None:
        first = await self.server._index_page()
        second = await self.server._index_page()
        self.assertIn(b"Test Sender", first)
        self.assertIn(b"Test Sender", second)
        self.assertEqual(self.client.entity_requests, 1)

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
        self.assertEqual(self.cancelled, ["sender"])
        self.assertIsNone(self.store.review_item(self.review_id).reference)
        self.assertNotIn("sender", self.server._identity_cache)

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
        self.assertEqual(self.cancelled, ["sender"])

    async def test_spam_decision_does_not_repeat_existing_quarantine(self) -> None:
        self.store.quarantine("sender", 150)
        body = urlencode(
            {"token": self.server._csrf_token, "action": "spam"}
        ).encode()
        status, _, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(self.client.requests, [])
        self.assertEqual(self.store.sender("sender").status, "quarantined")
        self.assertEqual(self.cancelled, ["sender"])

    async def test_legitimate_decision_restores_gatekeeper_quarantine(self) -> None:
        self.store.quarantine("sender", 150)
        body = urlencode(
            {"token": self.server._csrf_token, "action": "legitimate"}
        ).encode()
        status, _, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(len(self.client.requests), 2)
        self.assertIsInstance(
            self.client.requests[0], functions.folders.EditPeerFoldersRequest
        )
        self.assertEqual(
            self.client.requests[0].folder_peers[0].folder_id, 0
        )
        self.assertEqual(self.store.sender("sender").status, "allowed")

    async def test_legitimate_decision_resolves_active_challenge(self) -> None:
        self.store.set_challenge("sender", "challenge", "digest", 700, 42, 150)
        body = urlencode(
            {"token": self.server._csrf_token, "action": "legitimate"}
        ).encode()
        status, _, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(len(self.client.requests), 2)
        self.assertEqual(self.store.sender("sender").status, "allowed")
        self.assertEqual(self.cancelled, ["sender"])


if __name__ == "__main__":
    unittest.main()
