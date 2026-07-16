# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import stat
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

from telethon import functions, types

from tg_pm_gatekeeper.crypto import ActiveCaseProtector, IdentifierProtector
from tg_pm_gatekeeper.message_facts import facts_from_message
from tg_pm_gatekeeper.review_admin import ReviewAdminServer
from tg_pm_gatekeeper.service import GatekeeperService
from tg_pm_gatekeeper.store import DialogSnapshot, StateStore


class FakeTelegramClient:
    def __init__(self) -> None:
        self.requests: list[object] = []
        self.entity_requests = 0
        self.fail_entity_requests = False
        self.fail_next_mute = False
        self.message = SimpleNamespace(
            message="transient-canary", media=None, reply_to=None
        )

    async def get_messages(self, peer, ids):
        return self.message

    async def get_entity(self, peer):
        self.entity_requests += 1
        if self.fail_entity_requests:
            raise RuntimeError("identity lookup failed")
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
        self.review_protector = ActiveCaseProtector(b"r" * 32)
        self.service = GatekeeperService(
            self.store,
            self.protector,
            active_case_protector=self.review_protector,
        )
        self.client = FakeTelegramClient()
        self.cancelled: list[str] = []
        self.scheduled_deletions: list[tuple[int, int]] = []
        self.server = ReviewAdminServer(
            Path(self.temp.name) / "review.sock",
            self.store,
            self.service,
            self.client,
            mute_days=30,
            cancel_timeout=self.cancelled.append,
            schedule_dialog_deletion=lambda action_id, delete_at: (
                self.scheduled_deletions.append((action_id, delete_at))
            ),
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
        self.assertNotIn(b'http-equiv="refresh"', response)
        self.assertIn(b'data-live-refresh="notice"', response)
        self.assertIn(b"Actions are paused to prevent a stale decision", response)
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
            f"/{self.server._capability_token}/review/{self.review_id}",
            body,
            request_headers={
                "host": "127.0.0.1:8765",
                "origin": "http://127.0.0.1:8765",
            },
        )
        self.assertEqual(status, 303)
        self.assertEqual(
            headers["Location"], f"/{self.server._capability_token}/review"
        )
        self.assertEqual(self.store.review_item(self.review_id).status, "dismissed")

    async def test_authenticated_post_accepts_missing_origin(self) -> None:
        self.client.message = None
        body = urlencode(
            {"token": self.server._csrf_token, "action": "dismiss"}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST",
            f"/{self.server._capability_token}/review/{self.review_id}",
            body,
            request_headers={
                "host": "127.0.0.1:8765",
            },
        )
        self.assertEqual(status, 303)
        self.assertEqual(
            headers["Location"], f"/{self.server._capability_token}/review"
        )
        self.assertEqual(self.store.review_item(self.review_id).status, "dismissed")

    async def test_authenticated_post_accepts_noncanonical_origin(self) -> None:
        body = urlencode(
            {"token": self.server._csrf_token, "action": "dismiss"}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST",
            f"/{self.server._capability_token}/review/{self.review_id}",
            body,
            request_headers={
                "host": "127.0.0.1:8765",
                "origin": "null",
            },
        )
        self.assertEqual(status, 303)
        self.assertEqual(
            headers["Location"], f"/{self.server._capability_token}/review"
        )
        self.assertEqual(self.store.review_item(self.review_id).status, "dismissed")

    async def test_authenticated_post_rejects_invalid_csrf_for_any_origin(self) -> None:
        body = urlencode({"token": "invalid", "action": "dismiss"}).encode()
        for origin in ("https://example.com", "null"):
            with self.subTest(origin=origin):
                status, _, response = await self.server._dispatch(
                    "POST",
                    f"/{self.server._capability_token}/review/{self.review_id}",
                    body,
                    request_headers={
                        "host": "127.0.0.1:8765",
                        "origin": origin,
                    },
                )
                self.assertEqual(status, 400)
                self.assertIn(b"Invalid Action Token", response)
                self.assertEqual(
                    self.store.review_item(self.review_id).status, "pending"
                )

    async def test_queue_page_uses_in_place_connection_feedback(self) -> None:
        response = await self.server._review_queue_page()
        self.assertNotIn(b'http-equiv="refresh"', response)
        self.assertIn(b'data-live-refresh="replace"', response)
        self.assertIn(b'<script src="/dashboard.js" defer></script>', response)
        self.assertIn(b"Connected", response)
        self.assertIn(b"Checked ", response)
        self.assertIn(b"checked quietly while this tab is visible", response)
        self.assertIn(b"updates in place only when review state changes", response)
        self.assertIn(b"Test Sender (@testsender)", response)
        self.assertIn(b"ID 123456789", response)
        self.assertIn(b"Review Reason", response)
        self.assertNotIn(b">Simulation<", response)

    async def test_masthead_places_page_indicator_before_connection(self) -> None:
        response = await self.server._enforcement_index_page()
        section = response.index(b"data-section-indicator")
        connection = response.index(b"data-connection data-state")
        self.assertLess(section, connection)

    async def test_dashboard_script_pauses_hidden_tabs_and_replaces_regions(self) -> None:
        status, headers, response = await self.server._dispatch(
            "GET", "/dashboard.js", b""
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/javascript; charset=utf-8")
        self.assertIn(b"document.visibilityState", response)
        self.assertIn(b"region.replaceWith(replacement)", response)

    async def test_status_version_changes_without_exposing_review_content(self) -> None:
        status, headers, response = await self.server._dispatch(
            "GET", "/dashboard/status?path=%2Freview", b""
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertNotIn(b"transient-canary", response)
        first = response

        self.store.enqueue_review(
            "sender",
            self.protector.seal_review_reference(123456789, -987654321, 43),
            "would_quarantine",
            '[]',
            '{}',
            int(time.time()) + 700,
            101,
        )
        _, _, second = await self.server._dispatch(
            "GET", "/dashboard/status?path=%2Freview", b""
        )
        self.assertNotEqual(first, second)

    async def test_status_endpoint_rejects_unknown_page(self) -> None:
        status, headers, response = await self.server._dispatch(
            "GET", "/dashboard/status?path=%2Funknown", b""
        )
        self.assertEqual(status, 404)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(response, b"{}")

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
            reader, writer = await asyncio.open_unix_connection(self.server.socket_path)
            writer.write(
                (
                    f"GET /{self.server._capability_token}/dashboard.js HTTP/1.1\r\n"
                    "Host: 127.0.0.1:8765\r\n\r\n"
                ).encode("ascii")
            )
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()
            self.assertIn(b"Content-Type: text/javascript; charset=utf-8", response)
            self.assertIn(b"script-src 'self'; connect-src 'self'", response)
            self.assertIn(b"Cache-Control: no-store", response)
            self.assertIn(b"Referrer-Policy: no-referrer", response)
            self.assertNotIn(b"Set-Cookie:", response)
        finally:
            await self.server.stop()

    async def test_production_dispatch_requires_capability_path(self) -> None:
        status, _, response = await self.server._dispatch(
            "GET", "/", b"", request_headers={"host": "127.0.0.1:8765"}
        )
        self.assertEqual(status, 404)
        self.assertIn(b"Dashboard Access Missing", response)
        self.assertNotIn(b"Return to Dashboard", response)
        for protected_path in (
            "/dashboard.js",
            "/dashboard/status?path=%2Freview",
        ):
            protected_status, _, _ = await self.server._dispatch(
                "GET",
                protected_path,
                b"",
                request_headers={"host": "127.0.0.1:8765"},
            )
            self.assertEqual(protected_status, 404)
        login_token = self.server._access_token
        status, headers, _ = await self.server._dispatch(
            "GET",
            f"/login?token={login_token}",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(status, 303)
        self.assertNotEqual(self.server._access_token, login_token)
        capability = self.server._capability_token
        self.assertEqual(headers["Location"], f"/{capability}/")
        self.assertNotIn("Set-Cookie", headers)
        replay_status, _, _ = await self.server._dispatch(
            "GET",
            f"/login?token={login_token}",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(replay_status, 400)
        status, _, page = await self.server._dispatch(
            "GET",
            f"/{capability}/",
            b"",
            request_headers={
                "host": "127.0.0.1:8765",
                "cookie": "gatekeeper_session=unrelated-local-service-cookie",
            },
        )
        self.assertEqual(status, 200)
        self.assertIn(f"href='/{capability}/review'".encode(), page)
        self.assertIn(f'src="/{capability}/dashboard.js"'.encode(), page)
        self.assertNotIn(b"href='/review'", page)
        for protected_path in (
            "/dashboard.js",
            "/dashboard/status?path=%2Freview",
        ):
            protected_status, _, _ = await self.server._dispatch(
                "GET",
                f"/{capability}{protected_path}",
                b"",
                request_headers={"host": "127.0.0.1:8765"},
            )
            self.assertEqual(protected_status, 200)

        next_login_token = self.server._access_token
        status, next_headers, _ = await self.server._dispatch(
            "GET",
            f"/login?token={next_login_token}",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(status, 303)
        self.assertNotEqual(self.server._capability_token, capability)
        self.assertEqual(
            next_headers["Location"], f"/{self.server._capability_token}/"
        )
        stale_status, _, _ = await self.server._dispatch(
            "GET",
            f"/{capability}/",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(stale_status, 404)

    async def test_pending_reviews_are_paginated_with_stable_page_links(self) -> None:
        now = int(time.time())
        for index in range(50):
            self.store.enqueue_review(
                f"sender-{index:02d}",
                self.protector.seal_review_reference(
                    200_000_000 + index, -987654321, 1000 + index
                ),
                "would_challenge",
                "[]",
                "{}",
                now + 700,
                now + index + 1,
            )

        first = await self.server._review_queue_page(page=1)
        second = await self.server._review_queue_page(page=2)

        self.assertIn(b"Page 1 of 2", first)
        self.assertIn(b"href='/review?page=2'", first)
        self.assertNotIn(b"href='/review?page=0'", first)
        self.assertIn(b"Page 2 of 2", second)
        self.assertIn(b"href='/review?page=1'", second)
        self.assertNotIn(b"href='/review?page=3'", second)

        status, _, _ = await self.server._dispatch("GET", "/review?page=3", b"")
        self.assertEqual(status, 404)
        status, _, _ = await self.server._dispatch(
            "GET", "/dashboard/status?path=%2Freview%3Fpage%3D3", b""
        )
        self.assertEqual(status, 404)

    async def test_active_case_identity_lookup_is_batched_and_failure_cached(
        self,
    ) -> None:
        for index in range(3):
            user_id = 300_000_000 + index
            self.store.quarantine(
                f"restricted-{index}",
                restriction_reference=self.protector.seal_restriction_reference(
                    user_id, -987654321
                ),
            )
        items = self.store.active_restrictions()

        identities = await self.server._live_enforcement_identities(items)
        self.assertEqual(len(identities), 3)
        self.assertEqual(self.client.entity_requests, 1)

        self.server._identity_cache.clear()
        self.client.fail_entity_requests = True
        failed = await self.server._live_enforcement_identities(items)
        repeated = await self.server._live_enforcement_identities(items)
        self.assertEqual(len(failed), 3)
        self.assertEqual(len(repeated), 3)
        self.assertEqual(self.client.entity_requests, 2)

    async def test_legacy_enforcement_routes_redirect(self) -> None:
        status, headers, _ = await self.server._dispatch("GET", "/enforcement", b"")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases")

        status, headers, _ = await self.server._dispatch(
            "GET", "/enforcement/sender-key", b""
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases/sender-key")

    async def test_active_case_uses_case_specific_limited_evidence_guidance(
        self,
    ) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_review_reference(
            123456789, -987654321, 42
        )
        envelope = self.review_protector.seal(
            {
                "schema_version": 4,
                "text": "",
                "quote_text": "",
                "preview_text": "",
                "button_texts": ["Open"],
                "urls": [{"url": "https://example.invalid"}],
                "rule_codes": ["HR-01_MULTIPLE_LINK_BUTTONS"],
                "severity": "critical",
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
            restriction_reference=self.protector.seal_restriction_reference(
                123456789, -987654321
            ),
        )

        item = self.store.active_restriction(sender_key)
        status, _, detail = await self.server._show_enforcement(item)

        self.assertEqual(status, 200)
        self.assertIn(b"Limited Textual Evidence", detail)
        self.assertIn(b"deciding whether to allow the sender", detail)
        self.assertIn(b"Decrypted Local Evidence", detail)
        self.assertIn(b"Critical HR Match", detail)
        self.assertIn(b"Legacy HR Decision", detail)
        self.assertIn(b"<dt>Risk Score</dt><dd>Critical</dd>", detail)
        self.assertIn(b"Evidence Signals", detail)
        self.assertIn(b"<ol class='signal-list'", detail)
        self.assertIn(b"<li class='signal-item'>", detail)
        self.assertIn(b"HR-01 \xc2\xb7 Multiple Link Buttons", detail)

    async def test_active_case_shows_adaptive_signal_breakdown(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_review_reference(
            123456789, -987654321, 42
        )
        explanation = "Telegram <preview> metadata contains promotional language."
        envelope = self.review_protector.seal(
            {
                "schema_version": 5,
                "text": "synthetic",
                "signals": [
                    {
                        "code": "PROMOTIONAL_LANGUAGE",
                        "source": "preview",
                        "weight": 20,
                        "explanation": explanation,
                    }
                ],
                "risk_score": 30,
                "challenge_profile": "strict",
                "planned_action": "strict_challenge",
                "decision_basis": "risk_score_requires_strict_challenge",
                "policy_version": "adaptive-v1",
                "features": {},
            }
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
            until=int(time.time()) + 700,
            reference=reference,
            restriction_reference=self.protector.seal_restriction_reference(
                123456789, -987654321
            ),
        )

        status, _, detail = await self.server._show_enforcement(
            self.store.active_restriction(sender_key)
        )

        self.assertEqual(status, 200)
        self.assertIn(b"<dt>Risk Score</dt><dd>30</dd>", detail)
        self.assertIn(b"<dt>Policy Decision</dt><dd>Strict Challenge</dd>", detail)
        self.assertIn(b"<ol class='signal-list' aria-label='Evidence signals'>", detail)
        self.assertIn(b"<strong>Promotional Language</strong>", detail)
        self.assertIn(b"<span class='signal-source'>Preview</span>", detail)
        self.assertIn(b"<span class='signal-score'>+20</span>", detail)
        self.assertIn(b"Telegram &lt;preview&gt; metadata", detail)
        self.assertNotIn(explanation.encode(), detail)
        self.assertNotIn(b"Legacy HR Decision", detail)

    async def test_dashboard_contains_only_actionable_review_areas(self) -> None:
        page = await self.server._dashboard_page()

        self.assertIn(b"Active Cases", page)
        self.assertIn(b"Pending Reviews", page)

    async def test_active_enforcement_shows_encrypted_content_and_allows_sender(
        self,
    ) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_review_reference(
            123456789, -987654321, 42
        )
        envelope = self.review_protector.seal(
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
            restriction_reference=self.protector.seal_restriction_reference(
                123456789, -987654321
            ),
        )
        index = await self.server._enforcement_index_page()
        self.assertIn(b"Active Cases", index)
        self.assertIn(b"Test Sender (@testsender)", index)
        self.assertIn(b"Reviewable Evidence", index)
        self.assertIn(b"State Reasons:", index)
        self.assertIn(b"Every active restriction currently has reviewable evidence", index)
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
        envelope = self.review_protector.seal(
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
            restriction_reference=self.protector.seal_restriction_reference(
                123456789, -987654321
            ),
        )

        item = self.store.active_restriction(sender_key)
        status, _, detail = await self.server._show_enforcement(item)

        self.assertEqual(status, 200)
        self.assertIn(b"Release pending", detail)
        self.assertIn(b"Record Without Extending Restriction", detail)

    async def test_expired_evidence_remains_listed_and_restorable(self) -> None:
        user_id = 123456789
        sender_key = self.protector.sender_key(user_id)
        review_reference = self.protector.seal_review_reference(
            user_id, -987654321, 42
        )
        self.store.save_enforcement_review(
            sender_key,
            reference=review_reference,
            envelope=self.review_protector.seal(
                {"schema_version": 4, "text": "expired-private-canary"}
            ),
            reason="critical_rule",
            expires_at=int(time.time()) - 1,
        )
        self.store.suppress(
            sender_key,
            "critical_rule",
            until=None,
            restriction_reference=self.protector.seal_restriction_reference(
                user_id, -987654321
            ),
        )

        index = await self.server._enforcement_index_page()
        self.assertIn(b"Test Sender (@testsender)", index)
        self.assertIn(b"Expired or unavailable", index)
        self.assertNotIn(b"expired-private-canary", index)

        status, _, detail = await self.server._dispatch_enforcement(
            "GET", f"/cases/{sender_key}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"Evidence expired or unavailable", detail)
        self.assertIn(b"Allow Now", detail)
        self.assertNotIn(b"expired-private-canary", detail)

        body = urlencode(
            {"token": self.server._csrf_token, "action": "allow"}
        ).encode()
        status, headers, _ = await self.server._dispatch_enforcement(
            "POST", f"/cases/{sender_key}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases")
        self.assertEqual(self.store.sender(sender_key).status, "allowed")
        self.assertIsNone(self.store.sender(sender_key).restriction_reference)

    async def test_invalid_evidence_does_not_block_allow_action(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        self.store.save_enforcement_review(
            sender_key,
            reference=self.protector.seal_review_reference(
                123456789, -987654321, 42
            ),
            envelope=b"invalid-encrypted-evidence",
            reason="critical_rule",
            expires_at=int(time.time()) + 700,
        )
        self.store.suppress(
            sender_key,
            "critical_rule",
            until=None,
            restriction_reference=self.protector.seal_restriction_reference(
                123456789, -987654321
            ),
        )

        item = self.store.active_restriction(sender_key)
        status, _, detail = await self.server._show_enforcement(item)

        self.assertEqual(status, 200)
        self.assertIn(b"failed authentication", detail)
        self.assertIn(b"Allow Now", detail)

    async def test_active_enforcement_disables_allow_without_identity(self) -> None:
        sender_key = self.protector.sender_key(987654321)
        envelope = self.review_protector.seal(
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
        item = self.store.active_restriction(sender_key)
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
        self.assertIn(b"1 restriction has no reviewable evidence", page)
        self.assertIn(b"Identity unavailable", page)
        self.assertIn(b"Expired or unavailable", page)
        self.assertIn(b"Allow an unidentified restricted sender by Telegram User ID", page)
        self.assertIn(b"Allow Future Messages Without Restore", page)
        self.assertNotIn(b'http-equiv="refresh" content="10"', page)

    async def test_expired_case_can_be_allowed_by_user_id_without_restore(self) -> None:
        user_id = 771_234_567
        sender_key = self.protector.sender_key(user_id)
        state = self.store.suppress(
            sender_key,
            "critical_rule",
            until=None,
            reference=b"expired-reference",
        )
        self.store.schedule_action(
            sender_key,
            reason="critical_rule",
            reference=b"expired-reference",
            execute_at=int(time.time()) + 600,
            expected_revision=state.revision,
        )
        self.store.save_dialog_snapshot(
            sender_key,
            DialogSnapshot(folder_id=1, silent=True, mute_until=None),
        )

        body = urlencode(
            {"token": self.server._csrf_token, "user_id": str(user_id)}
        ).encode()
        status, headers, _ = await self.server._dispatch(
            "POST", "/cases/release", body
        )

        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases")
        self.assertEqual(self.store.sender(sender_key).status, "allowed")
        self.assertIsNone(self.store.dialog_snapshot(sender_key))
        self.assertEqual(self.store.pending_actions(), [])
        self.assertEqual(self.cancelled, [sender_key])
        self.assertEqual(self.client.requests, [])
        database = (Path(self.temp.name) / "state.sqlite3").read_bytes()
        self.assertNotIn(str(user_id).encode(), database)

    async def test_release_by_user_id_allows_legacy_quarantine(self) -> None:
        user_id = 771_234_568
        sender_key = self.protector.sender_key(user_id)
        self.store.quarantine(sender_key)
        body = urlencode(
            {"token": self.server._csrf_token, "user_id": str(user_id)}
        ).encode()

        status, headers, _ = await self.server._dispatch(
            "POST", "/cases/release", body
        )

        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases")
        self.assertEqual(self.store.sender(sender_key).status, "allowed")

    async def test_release_by_user_id_requires_existing_restriction(self) -> None:
        body = urlencode(
            {"token": self.server._csrf_token, "user_id": "771234570"}
        ).encode()

        status, _, response = await self.server._dispatch(
            "POST", "/cases/release", body
        )

        self.assertEqual(status, 409)
        self.assertIn(b"Restricted Sender Not Found", response)

    async def test_release_by_user_id_rejects_identifiable_restriction(self) -> None:
        user_id = 771_234_571
        sender_key = self.protector.sender_key(user_id)
        restriction_reference = self.protector.seal_restriction_reference(
            user_id, 123456789
        )
        self.store.quarantine(
            sender_key, restriction_reference=restriction_reference
        )
        body = urlencode(
            {"token": self.server._csrf_token, "user_id": str(user_id)}
        ).encode()

        status, _, response = await self.server._dispatch(
            "POST", "/cases/release", body
        )

        self.assertEqual(status, 409)
        self.assertIn(b"Use Active Case Allow Now", response)
        state = self.store.sender(sender_key)
        self.assertEqual(state.status, "quarantined")
        self.assertEqual(state.restriction_reference, restriction_reference)

    async def test_release_by_user_id_rejects_invalid_input(self) -> None:
        for value in ("not-a-number", "0", "-1", "+1", "１"):
            body = urlencode(
                {"token": self.server._csrf_token, "user_id": value}
            ).encode()
            status, _, response = await self.server._dispatch(
                "POST", "/cases/release", body
            )
            self.assertEqual(status, 400)
            self.assertIn(b"Invalid Telegram User ID", response)

    async def test_release_by_user_id_requires_valid_csrf(self) -> None:
        user_id = 771_234_569
        sender_key = self.protector.sender_key(user_id)
        self.store.suppress(sender_key, "critical_rule", until=None)
        body = urlencode({"token": "invalid", "user_id": str(user_id)}).encode()

        status, _, response = await self.server._dispatch(
            "POST", "/cases/release", body
        )

        self.assertEqual(status, 400)
        self.assertIn(b"Invalid Action Token", response)
        self.assertEqual(self.store.sender(sender_key).status, "suppressed")

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
            entities=[
                types.MessageEntityTextUrl(
                    offset=0,
                    length=17,
                    url="https://hidden.invalid/path?token=hidden-secret",
                ),
                types.MessageEntityUrl(offset=17, length=56),
            ],
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
        self.assertEqual(self.store.sender("sender").status, "suppressed")
        self.assertEqual(
            self.store.sender("sender").suppression_reason,
            "manual_permanent_suppression",
        )
        self.assertIsNotNone(self.store.sender("sender").restriction_reference)
        item = self.store.enforcement_review("sender")
        self.assertIsNotNone(item)
        self.assertEqual(item.reason, "manual_permanent_suppression")
        self.assertGreaterEqual(item.expires_at, int(time.time()) + 30 * 86400 - 2)
        payload = self.review_protector.open(item.envelope)
        self.assertEqual(payload["schema_version"], 5)
        self.assertEqual(payload["policy_version"], "manual-review-v1")
        self.assertEqual(payload["planned_action"], "manual_permanent_suppression")
        self.assertIn("transient-canary", payload["text"])
        self.assertIn("Preview Title", payload["preview_text"])
        self.assertEqual(payload["button_texts"], ["Open private offer"])
        serialized = str(payload)
        self.assertIn("button-secret", serialized)
        self.assertIn("preview-secret", serialized)
        self.assertIn("body-secret", serialized)
        self.assertIn("quote.invalid", serialized)
        self.assertIn("hidden-secret", serialized)
        extracted = facts_from_message(self.client.message)
        payload_urls = {entry["url"] for entry in payload["urls"]}
        self.assertEqual(payload_urls, set(extracted.urls))
        self.assertIsNotNone(self.store.dialog_snapshot("sender"))
        self.assertEqual(self.cancelled, ["sender"])
        self.assertEqual(len(self.scheduled_deletions), 1)
        self.assertTrue(self.store.pending_actions()[0].mode_independent)

    async def test_spam_decision_converts_existing_quarantine_to_suppression(self) -> None:
        self.store.quarantine("sender", 150)
        body = urlencode({"token": self.server._csrf_token, "action": "spam"}).encode()
        status, _, _ = await self.server._dispatch(
            "POST", f"/review/{self.review_id}", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(self.client.requests, [])
        self.assertEqual(self.store.sender("sender").status, "suppressed")
        self.assertEqual(len(self.scheduled_deletions), 1)
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
