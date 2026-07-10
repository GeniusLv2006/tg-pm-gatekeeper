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
from tg_pm_gatekeeper.evidence import EvidenceProtector, EvidenceStore
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
        self.review_protector = EvidenceProtector(b"r" * 32)
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
        state = self.store.suppress(
            "sender", "critical_rule", until=None, reference=b"reference"
        )
        self.store.schedule_action(
            "sender",
            reason="critical_rule",
            reference=b"reference",
            execute_at=int(time.time()) + 600,
            expected_revision=state.revision,
        )
        status, _, response = await self.server._dispatch(
            "GET", f"/review/{self.review_id}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"Telegram Message Unavailable", response)
        self.assertIn(b"Resolve and Cancel Pending Jobs", response)
        self.assertIn(b"Telegram and trust state are unchanged", response)

        body = urlencode(
            {"token": self.server._csrf_token, "action": "dismiss"}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/review")
        item = self.store.review_item(self.review_id)
        self.assertEqual(item.status, "dismissed")
        self.assertIsNone(item.reference)
        self.assertEqual(self.store.sender("sender").status, "suppressed")
        self.assertEqual(self.store.pending_actions(), [])

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
        self.assertEqual(headers["Location"], "/review")
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
        self.assertEqual(headers["Location"], "/review")
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
        self.assertEqual(headers["Location"], "/review")
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
                self.assertIn(b"Invalid Action Token", response)
                self.assertEqual(
                    self.store.review_item(self.review_id).status, "pending"
                )

    async def test_queue_page_exposes_fresh_connection_feedback(self) -> None:
        response = await self.server._review_queue_page()
        self.assertIn(b'http-equiv="refresh" content="10"', response)
        self.assertIn(b"Connected", response)
        self.assertIn(b"Updated ", response)
        self.assertIn(b"checks the connection every 10 seconds", response)
        self.assertIn(b"Test Sender (@testsender)", response)
        self.assertIn(b"ID 123456789", response)
        self.assertIn(b"Review Reason", response)
        self.assertNotIn(b">Simulation<", response)

    async def test_queue_labels_protect_mode_exception_as_real_review_reason(
        self,
    ) -> None:
        reference = self.protector.seal_review_reference(987654321, 123456789, 43)
        self.store.enqueue_review(
            "protect-sender",
            reference,
            "challenge_unavailable",
            "[]",
            "{}",
            int(time.time()) + 700,
        )

        response = await self.server._review_queue_page()

        self.assertIn("Challenge Unavailable · Protect".encode(), response)
        self.assertNotIn(b">Simulation<", response)

    async def test_queue_identity_uses_short_lived_memory_cache(self) -> None:
        first = await self.server._review_queue_page()
        second = await self.server._review_queue_page()
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
        response = self.server._page("Invalid Access Token")
        self.assertIn(b"class='masthead'", response)
        self.assertIn(b"class='error-card'", response)
        self.assertIn(b"has already been used", response)
        self.assertIn(b"scripts/dashboard-tunnel.sh SSH_TARGET", response)
        self.assertNotIn(b"Return to Dashboard", response)
        self.assertIn(b"width:min(100%,680px)", response)
        self.assertIn(b"class='error-content'", response)
        self.assertIn(b".error-content{width:100%;text-align:left", response)
        self.assertNotIn(b".error-content{max-width:", response)
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
        status, _, response = await self.server._dispatch(
            "GET", "/", b"", request_headers={"host": "127.0.0.1:8765"}
        )
        self.assertEqual(status, 404)
        self.assertIn(b"Dashboard Session Missing", response)
        self.assertNotIn(b"Return to Dashboard", response)
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

    async def test_legacy_dataset_and_enforcement_routes_redirect(self) -> None:
        status, headers, _ = await self.server._dispatch("GET", "/dataset", b"")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/evidence")

        status, headers, _ = await self.server._dispatch("GET", "/dataset/12", b"")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/evidence/12")

        status, headers, _ = await self.server._dispatch("GET", "/enforcement", b"")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases")

        status, headers, _ = await self.server._dispatch(
            "GET", "/enforcement/sender-key", b""
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases/sender-key")

    async def test_evidence_log_hides_text_until_detail_and_supports_review(
        self,
    ) -> None:
        evidence = EvidenceStore(
            Path(self.temp.name) / "evidence.sqlite3",
            EvidenceProtector(b"d" * 32),
        )
        self.addCleanup(evidence.close)
        sample_id = evidence.collect(
            sender_id=123,
            message_id=1,
            payload={
                "schema_version": 4,
                "text": "evidence-private-canary",
                "quote_text": "quoted-evidence-canary",
                "features": {"has_quote": True},
                "planned_action": "challenge",
                "actual_action": "would_challenge",
            },
            automatic_hint="uncertain",
            retention_days=30,
            max_per_sender=3,
        ).record_id
        evidence.collect(
            sender_id=123,
            message_id=2,
            payload={"schema_version": 4, "text": "second-private-canary"},
            automatic_hint="uncertain",
            retention_days=30,
            max_per_sender=3,
        )
        self.server.evidence_store = evidence
        index = self.server._evidence_index_page()
        self.assertNotIn(b"evidence-private-canary", index)
        self.assertIn(b"Operator Reviewed", index)
        self.assertIn(b"Spam / Legitimate / Uncertain Hints", index)
        self.assertIn(b"Expiring Within 24 Hours", index)
        self.assertIn(b"Evidence Log", index)
        self.assertIn(b"Collection Activity", index)
        self.assertIn(b"Eligible unknown-sender messages", index)
        self.assertNotIn(b"Exportable manual labels", index)
        self.assertNotIn(b"Dataset overview", index)
        self.assertNotIn(b"gold labels ready", index)
        self.assertIn(b'font-feature-settings:"tnum" 1,"zero" 1', index)
        sender_prefix = evidence.records()[0].sender_token[:8].encode()
        self.assertEqual(index.count(b"Sender " + sender_prefix), 2)
        status, _, detail = self.server._dispatch_evidence(
            "GET", f"/evidence/{sample_id}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"evidence-private-canary", detail)
        self.assertIn(b"quoted-evidence-canary", detail)
        self.assertIn(b"Quoted Context", detail)
        self.assertIn(b"Assessment Context", detail)
        self.assertIn(b"Correct Assessment", detail)
        self.assertIn(b"Full Decrypted Evidence Payload", detail)
        self.assertIn("Simulated Challenge · Monitor".encode(), detail)
        body = urlencode(
            {"token": self.server._csrf_token, "action": "correct"}
        ).encode()
        status, _, _ = self.server._dispatch_evidence(
            "POST", f"/evidence/{sample_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(evidence.record(sample_id).review_outcome, "correct")
        self.assertFalse(self.server.socket_path.exists())

    async def test_evidence_structural_record_explains_missing_content(self) -> None:
        evidence = EvidenceStore(
            Path(self.temp.name) / "structural.sqlite3",
            EvidenceProtector(b"d" * 32),
        )
        self.addCleanup(evidence.close)
        sample_id = evidence.collect(
            sender_id=123,
            message_id=2,
            payload={
                "schema_version": 3,
                "text": "",
                "quote_text": "",
                "preview_text": "",
                "domains": ["spam.invalid"],
                "quote_domains": [],
                "url_shape": {"has_query": True},
                "quote_url_shape": {},
                "features": {"forwarded": True, "has_link_button": True},
                "signals": ["HR-02_FORWARDED_LINK_BUTTON"],
            },
            automatic_hint="spam_candidate",
            retention_days=30,
            max_per_sender=3,
            sample_kind="structural",
        ).record_id
        self.server.evidence_store = evidence

        status, _, detail = self.server._dispatch_evidence(
            "GET", f"/evidence/{sample_id}", b""
        )

        self.assertEqual(status, 200)
        self.assertIn(b"Limited Textual Evidence", detail)
        self.assertIn(b"spam.invalid", detail)
        self.assertIn(b"Select Insufficient Evidence", detail)
        self.assertIn(b"Link Shape", detail)
        self.assertNotIn(b"Structural-Only Evidence", detail)

    async def test_active_case_uses_case_specific_limited_evidence_guidance(
        self,
    ) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_review_reference(
            123456789, -987654321, 42
        )
        envelope = self.review_protector.seal_enforcement(
            {
                "schema_version": 4,
                "text": "",
                "quote_text": "",
                "preview_text": "",
                "button_texts": ["Open"],
                "urls": [{"url": "https://example.invalid"}],
                "signals": ["HR-01_MULTIPLE_LINK_BUTTONS"],
            }
        )
        self.store.save_enforcement_review(
            sender_key,
            reference=reference,
            envelope=envelope,
            reason="critical_rule",
            expires_at=int(time.time()) + 700,
        )
        self.store.suppress(
            sender_key,
            "critical_rule",
            until=None,
            reference=reference,
        )

        item = self.store.enforcement_review(sender_key)
        status, _, detail = await self.server._show_enforcement(item)

        self.assertEqual(status, 200)
        self.assertIn(b"Limited Textual Evidence", detail)
        self.assertIn(b"deciding whether to allow the sender", detail)
        self.assertNotIn(b"Select Insufficient Evidence", detail)
        self.assertIn(b"Decrypted Local Evidence", detail)

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
        self.assertIn(b"Active Cases", index)
        self.assertIn(b"Test Sender (@testsender)", index)
        self.assertIn(b"Reviewable Evidence", index)
        self.assertIn(b"State Reasons:", index)
        self.assertIn(b"Every active case currently has reviewable evidence", index)
        self.assertNotIn(b"<dt>Reasons</dt>", index)
        self.assertNotIn(b"enforcement-private-canary", index)
        status, _, detail = await self.server._dispatch_enforcement(
            "GET", f"/cases/{sender_key}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"enforcement-private-canary", detail)
        self.assertIn(b"quoted-enforcement-canary", detail)
        self.assertIn(b"Quoted Context", detail)
        self.assertIn(b"No saved dialog state is available", detail)

        keep_body = urlencode(
            {"token": self.server._csrf_token, "action": "keep"}
        ).encode()
        status, _, _ = await self.server._dispatch_enforcement(
            "POST", f"/cases/{sender_key}", keep_body
        )
        self.assertEqual(status, 303)
        self.assertEqual(self.store.sender(sender_key).status, "suppressed")
        self.assertIsNotNone(self.store.enforcement_review(sender_key))

        body = urlencode(
            {"token": self.server._csrf_token, "action": "allow"}
        ).encode()
        status, headers, _ = await self.server._dispatch_enforcement(
            "POST", f"/cases/{sender_key}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases")
        self.assertEqual(self.store.sender(sender_key).status, "allowed")
        self.assertIsNone(self.store.enforcement_review(sender_key))

    async def test_expired_suppression_does_not_offer_to_extend_restriction(
        self,
    ) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_review_reference(
            123456789, -987654321, 42
        )
        envelope = self.review_protector.seal_enforcement(
            {"schema_version": 4, "text": "private-canary"}
        )
        self.store.save_enforcement_review(
            sender_key,
            reference=reference,
            envelope=envelope,
            reason="challenge_timeout",
            expires_at=int(time.time()) + 700,
        )
        self.store.suppress(
            sender_key,
            "challenge_timeout",
            until=int(time.time()) - 1,
            reference=reference,
        )

        item = self.store.enforcement_review(sender_key)
        status, _, detail = await self.server._show_enforcement(item)

        self.assertEqual(status, 200)
        self.assertIn(b"Release pending", detail)
        self.assertIn(b"Record Without Extending Restriction", detail)

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
        self.assertIn(b"Allow Unavailable", detail)
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
        self.assertIn(b"Manual Spam Review 1", page)
        self.assertIn(b"1 active case", page)
        self.assertIn(b"has no encrypted snapshot", page)
        self.assertIn(b"No active cases", page)

    async def test_legitimate_decision_allows_and_erases_reference(self) -> None:
        body = urlencode(
            {"token": self.server._csrf_token, "action": "legitimate"}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/review")
        self.assertEqual(self.store.sender("sender").status, "allowed")
        self.assertEqual(self.cancelled, ["sender"])
        self.assertIsNone(self.store.review_item(self.review_id).reference)
        self.assertNotIn("sender", self.server._identity_cache)

    async def test_spam_decision_performs_explicit_telegram_actions(self) -> None:
        self.client.message = SimpleNamespace(
            message="transient-canary https://body.invalid/private?token=body-secret",
            media=SimpleNamespace(
                webpage=SimpleNamespace(
                    url="https://preview.invalid/path?token=preview-secret",
                    site_name="Preview Site",
                    title="Preview Title",
                    description="Preview Description",
                    author=None,
                )
            ),
            reply_to=SimpleNamespace(
                quote_text="quoted context https://quote.invalid/secret"
            ),
            reply_markup=SimpleNamespace(
                rows=[
                    SimpleNamespace(
                        buttons=[
                            SimpleNamespace(
                                text="Open private offer",
                                url="https://button.invalid/start?token=button-secret",
                            )
                        ]
                    )
                ]
            ),
        )
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
        self.assertEqual(payload["schema_version"], 4)
        self.assertIn("transient-canary", payload["text"])
        self.assertIn("Preview Title", payload["preview_text"])
        self.assertEqual(payload["button_texts"], ["Open private offer"])
        serialized = str(payload)
        self.assertIn("button-secret", serialized)
        self.assertIn("preview-secret", serialized)
        self.assertIn("body-secret", serialized)
        self.assertIn("quote.invalid", serialized)
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
