# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import tempfile
import stat
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

from telethon import functions

from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.dataset import DatasetProtector, TrainingStore
from tg_pm_gatekeeper.review_admin import ReviewAdminServer
from tg_pm_gatekeeper.service import GatekeeperService
from tg_pm_gatekeeper.store import StateStore


class FakeTelegramClient:
    def __init__(self) -> None:
        self.requests: list[object] = []
        self.entity_requests = 0
        self.fail_next_mute = False
        self.message = SimpleNamespace(
            message="transient-canary", media=None, reply_to=None
        )

    async def get_messages(self, peer, ids):
        return self.message

    async def get_entity(self, peer):
        self.entity_requests += 1
        sender = SimpleNamespace(
            first_name="Test", last_name="Sender", username="testsender"
        )
        return [sender for _ in peer] if isinstance(peer, list) else sender

    async def __call__(self, request):
        self.requests.append(request)
        if isinstance(request, functions.messages.GetPeerDialogsRequest):
            return SimpleNamespace(
                dialogs=[
                    SimpleNamespace(
                        folder_id=0,
                        notify_settings=SimpleNamespace(silent=False, mute_until=None),
                    )
                ]
            )
        if self.fail_next_mute and isinstance(
            request, functions.account.UpdateNotifySettingsRequest
        ):
            self.fail_next_mute = False
            raise RuntimeError("mute failed")


class ReviewAdminTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")
        self.protector = IdentifierProtector(b"k" * 32)
        self.review_protector = DatasetProtector(b"r" * 32)
        self.service = GatekeeperService(
            self.store,
            self.protector,
            review_content_protector=self.review_protector,
        )
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
            int(time.time()) + 700,
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
        self.assertIn(b"Connected", response)
        database = (Path(self.temp.name) / "state.sqlite3").read_bytes()
        self.assertNotIn(b"transient-canary", database)
        self.assertNotIn(b"Test Sender", database)
        self.assertNotIn(b"testsender", database)
        self.assertNotIn(b"123456789", database)

    async def test_deleted_telegram_message_can_resolve_local_review(self) -> None:
        self.client.message = None
        status, _, response = await self.server._dispatch(
            "GET", f"/review/{self.review_id}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"Telegram message unavailable", response)
        self.assertIn(b"Resolve deleted conversation", response)
        self.assertIn(b"without changing Telegram or trust state", response)

        body = urlencode(
            {"token": self.server._csrf_token, "action": "dismiss"}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/")
        item = self.store.review_item(self.review_id)
        self.assertEqual(item.status, "dismissed")
        self.assertIsNone(item.reference)

    async def test_deleted_review_resolves_through_authenticated_post(self) -> None:
        self.client.message = None
        body = urlencode(
            {"token": self.server._csrf_token, "action": "dismiss"}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST",
            f"/review/{self.review_id}",
            body,
            request_headers={
                "host": "127.0.0.1:8765",
                "origin": "http://127.0.0.1:8765",
                "cookie": f"gatekeeper_session={self.server._session_token}",
            },
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/")
        self.assertEqual(self.store.review_item(self.review_id).status, "dismissed")

    async def test_authenticated_post_accepts_missing_origin(self) -> None:
        self.client.message = None
        body = urlencode(
            {"token": self.server._csrf_token, "action": "dismiss"}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST",
            f"/review/{self.review_id}",
            body,
            request_headers={
                "host": "127.0.0.1:8765",
                "cookie": f"gatekeeper_session={self.server._session_token}",
            },
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/")
        self.assertEqual(self.store.review_item(self.review_id).status, "dismissed")

    async def test_authenticated_post_accepts_noncanonical_origin(self) -> None:
        body = urlencode(
            {"token": self.server._csrf_token, "action": "dismiss"}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST",
            f"/review/{self.review_id}",
            body,
            request_headers={
                "host": "127.0.0.1:8765",
                "origin": "null",
                "cookie": f"gatekeeper_session={self.server._session_token}",
            },
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/")
        self.assertEqual(self.store.review_item(self.review_id).status, "dismissed")

    async def test_authenticated_post_rejects_invalid_csrf_for_any_origin(self) -> None:
        body = urlencode({"token": "invalid", "action": "dismiss"}).encode()
        for origin in ("https://example.com", "null"):
            with self.subTest(origin=origin):
                status, _, response = await self.server._dispatch(
                    "POST",
                    f"/review/{self.review_id}",
                    body,
                    request_headers={
                        "host": "127.0.0.1:8765",
                        "origin": origin,
                        "cookie": (
                            f"gatekeeper_session={self.server._session_token}"
                        ),
                    },
                )
                self.assertEqual(status, 400)
                self.assertIn(b"Invalid action token", response)
                self.assertEqual(
                    self.store.review_item(self.review_id).status, "pending"
                )

    async def test_queue_page_exposes_fresh_connection_feedback(self) -> None:
        response = await self.server._index_page()
        self.assertIn(b'http-equiv="refresh" content="10"', response)
        self.assertIn(b"Connected", response)
        self.assertIn(b"Updated ", response)
        self.assertIn(b"checks the connection every 10 seconds", response)
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
        self.assertIn(b"button{width:100%}", response)

    async def test_error_page_uses_dashboard_layout_and_actionable_copy(self) -> None:
        response = self.server._page("Invalid access token")
        self.assertIn(b"class='masthead'", response)
        self.assertIn(b"class='error-card'", response)
        self.assertIn(b"has already been used", response)
        self.assertIn(b"scripts/review-tunnel.sh SSH_TARGET", response)
        self.assertIn(b"width:min(100%,680px)", response)
        self.assertIn(b"class='error-content'", response)
        self.assertIn(b"max-width:46ch;margin:0 auto;text-align:left", response)
        self.assertNotIn(
            b".error-content{max-width:46ch;margin:0 auto;text-align:center",
            response,
        )
        self.assertNotIn(b"<body><h1>", response)

    async def test_admin_server_uses_owner_only_unix_socket(self) -> None:
        await self.server.start()
        try:
            self.assertTrue(stat.S_ISSOCK(self.server.socket_path.stat().st_mode))
            self.assertEqual(
                stat.S_IMODE(self.server.socket_path.stat().st_mode), 0o600
            )
        finally:
            await self.server.stop()

    async def test_production_dispatch_requires_access_cookie(self) -> None:
        status, _, _ = await self.server._dispatch(
            "GET", "/", b"", request_headers={"host": "127.0.0.1:8765"}
        )
        self.assertEqual(status, 404)
        login_token = self.server._access_token
        status, headers, _ = await self.server._dispatch(
            "GET",
            f"/login?token={login_token}",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(status, 303)
        self.assertNotEqual(self.server._access_token, login_token)
        replay_status, _, _ = await self.server._dispatch(
            "GET",
            f"/login?token={login_token}",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(replay_status, 400)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, _ = await self.server._dispatch(
            "GET",
            "/",
            b"",
            request_headers={"host": "127.0.0.1:8765", "cookie": cookie},
        )
        self.assertEqual(status, 200)

    async def test_dataset_list_hides_text_until_detail_and_supports_label(
        self,
    ) -> None:
        training = TrainingStore(
            Path(self.temp.name) / "training.sqlite3",
            DatasetProtector(b"d" * 32),
        )
        self.addCleanup(training.close)
        sample_id = training.collect(
            sender_id=123,
            message_id=1,
            payload={
                "schema_version": 2,
                "text": "dataset-private-canary",
                "quote_text": "quoted-dataset-canary",
                "features": {"has_quote": True},
            },
            weak_label="uncertain",
            retention_days=30,
            max_per_sender=3,
        )
        self.server.training_store = training
        index = self.server._dataset_index_page()
        self.assertNotIn(b"dataset-private-canary", index)
        self.assertIn(b"Manually labeled", index)
        self.assertIn(b"Weak spam / legitimate / uncertain", index)
        self.assertIn(b"Expiring within 24 hours", index)
        self.assertIn(b"Dataset overview", index)
        self.assertIn(b"Exportable manual labels", index)
        self.assertNotIn(b"gold labels ready", index)
        self.assertIn(b'font-feature-settings:"tnum" 1,"zero" 1', index)
        status, _, detail = self.server._dispatch_dataset(
            "GET", f"/dataset/{sample_id}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"dataset-private-canary", detail)
        self.assertIn(b"quoted-dataset-canary", detail)
        self.assertIn(b"Quoted context", detail)
        body = urlencode({"token": self.server._csrf_token, "action": "spam"}).encode()
        status, _, _ = self.server._dispatch_dataset(
            "POST", f"/dataset/{sample_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(training.sample(sample_id).manual_label, "spam")
        self.assertFalse(self.server.socket_path.exists())

    async def test_active_enforcement_shows_encrypted_content_and_allows_sender(
        self,
    ) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_review_reference(
            123456789, -987654321, 42
        )
        envelope = self.review_protector.seal_enforcement(
            {
                "schema_version": 1,
                "text": "enforcement-private-canary",
                "quote_text": "quoted-enforcement-canary",
                "rule_codes": ["HR-06_DENIED_DOMAIN"],
                "features": {"has_quote": True},
            }
        )
        self.store.save_enforcement_review(
            sender_key,
            reference=reference,
            envelope=envelope,
            reason="attempts_exhausted",
            expires_at=int(time.time()) + 700,
        )
        self.store.suppress(
            sender_key,
            "attempts_exhausted",
            until=int(time.time()) + 700,
            reference=reference,
        )
        index = await self.server._enforcement_index_page()
        self.assertIn(b"Active enforcement", index)
        self.assertIn(b"Test Sender (@testsender)", index)
        self.assertIn(b"Reviewable snapshots", index)
        self.assertIn(b"State reasons:", index)
        self.assertIn(b"Every active restriction currently has a reviewable snapshot", index)
        self.assertNotIn(b"<dt>Reasons</dt>", index)
        self.assertNotIn(b"enforcement-private-canary", index)
        status, _, detail = await self.server._dispatch_enforcement(
            "GET", f"/enforcement/{sender_key}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"enforcement-private-canary", detail)
        self.assertIn(b"quoted-enforcement-canary", detail)
        self.assertIn(b"Quoted context", detail)

        keep_body = urlencode(
            {"token": self.server._csrf_token, "action": "keep"}
        ).encode()
        status, _, _ = await self.server._dispatch_enforcement(
            "POST", f"/enforcement/{sender_key}", keep_body
        )
        self.assertEqual(status, 303)
        self.assertEqual(self.store.sender(sender_key).status, "suppressed")
        self.assertIsNotNone(self.store.enforcement_review(sender_key))

        body = urlencode(
            {"token": self.server._csrf_token, "action": "allow"}
        ).encode()
        status, headers, _ = await self.server._dispatch_enforcement(
            "POST", f"/enforcement/{sender_key}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/enforcement")
        self.assertEqual(self.store.sender(sender_key).status, "allowed")
        self.assertIsNone(self.store.enforcement_review(sender_key))

    async def test_active_enforcement_disables_allow_without_identity(self) -> None:
        sender_key = self.protector.sender_key(987654321)
        envelope = self.review_protector.seal_enforcement(
            {"schema_version": 1, "text": "private-canary", "quote_text": ""}
        )
        self.store.save_enforcement_review(
            sender_key,
            reference=None,
            envelope=envelope,
            reason="reference_unavailable",
            expires_at=int(time.time()) + 700,
        )
        self.store.quarantine(sender_key)
        item = self.store.enforcement_review(sender_key)
        status, _, detail = await self.server._show_enforcement(item)
        self.assertEqual(status, 200)
        self.assertIn(b"Allow unavailable", detail)
        self.assertIn(b"disabled", detail)

    async def test_active_enforcement_explains_legacy_state_without_snapshot(
        self,
    ) -> None:
        self.store.quarantine("legacy-sender")
        review_id = self.store.enqueue_review(
            "legacy-sender",
            b"sealed-reference",
            "would_quarantine",
            "[]",
            "{}",
            int(time.time()) + 700,
        )
        self.assertTrue(self.store.decide_review(review_id, "spam"))

        page = await self.server._enforcement_index_page()
        self.assertIn(b"manual spam 1", page)
        self.assertIn(b"1 active restriction", page)
        self.assertIn(b"has no encrypted snapshot", page)
        self.assertIn(b"No reviewable active restrictions", page)

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
        body = urlencode({"token": self.server._csrf_token, "action": "spam"}).encode()
        status, _, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(len(self.client.requests), 3)
        self.assertIsInstance(
            self.client.requests[1], functions.folders.EditPeerFoldersRequest
        )
        self.assertEqual(self.store.sender("sender").status, "quarantined")
        item = self.store.enforcement_review("sender")
        self.assertIsNotNone(item)
        self.assertEqual(item.reason, "manual_spam")
        payload = self.review_protector.open_enforcement(item.envelope)
        self.assertEqual(payload["text"], "transient-canary")
        self.assertIsNotNone(self.store.dialog_snapshot("sender"))
        self.assertEqual(self.cancelled, ["sender"])

    async def test_spam_decision_does_not_repeat_existing_quarantine(self) -> None:
        self.store.quarantine("sender", 150)
        body = urlencode({"token": self.server._csrf_token, "action": "spam"}).encode()
        status, _, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(self.client.requests, [])
        self.assertEqual(self.store.sender("sender").status, "quarantined")
        self.assertEqual(self.cancelled, ["sender"])

    async def test_spam_partial_archive_failure_is_compensated(self) -> None:
        self.client.fail_next_mute = True
        body = urlencode({"token": self.server._csrf_token, "action": "spam"}).encode()
        status, _, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 500)
        folder_requests = [
            request
            for request in self.client.requests
            if isinstance(request, functions.folders.EditPeerFoldersRequest)
        ]
        self.assertEqual(
            [request.folder_peers[0].folder_id for request in folder_requests],
            [1, 0],
        )
        self.assertEqual(self.store.sender("sender").status, "unknown")
        self.assertIsNone(self.store.enforcement_review("sender"))
        self.assertEqual(self.store.review_item(self.review_id).status, "pending")

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
        self.assertEqual(self.client.requests[0].folder_peers[0].folder_id, 0)
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
