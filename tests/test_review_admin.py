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
from tg_pm_gatekeeper.review_admin import (
    DASHBOARD_SESSION_ABSOLUTE_SECONDS,
    DASHBOARD_SESSION_COOKIE,
    DASHBOARD_SESSION_IDLE_SECONDS,
    ReviewAdminServer,
)
from tg_pm_gatekeeper.service import GatekeeperService
from tg_pm_gatekeeper.store import ActiveRestriction, DialogSnapshot, StateStore


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

    def authenticated_headers(self, **extra: str) -> dict[str, str]:
        if self.server._session_token is None:
            self.server._activate_session()
        return {
            "host": "127.0.0.1:8765",
            "cookie": (
                f"{DASHBOARD_SESSION_COOKIE}={self.server._session_token}"
            ),
            **extra,
        }

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
        self.assertIn(b"Dismiss &amp; Cancel Jobs", response)
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
            request_headers=self.authenticated_headers(
                origin="http://127.0.0.1:8765"
            ),
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
            request_headers=self.authenticated_headers(),
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
            request_headers=self.authenticated_headers(origin="null"),
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
                    request_headers=self.authenticated_headers(origin=origin),
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
        self.assertIn(b"The list refreshes in place only when review state changes", response)
        self.assertIn(b"class='logout-form' method='post' action='/logout'", response)
        self.assertIn(b">Sign Out</button>", response)
        self.assertIn(b"Test Sender (@testsender)", response)
        self.assertIn(b"ID 123456789", response)
        self.assertIn(b"<th>Review</th>", response)

    async def test_archive_cleanup_is_inside_main_and_live_region(self) -> None:
        page = await self.server._enforcement_index_page(archived=True)
        main_start = page.index(b"<main class='list-main' data-live-region=")
        cleanup = page.index(b"class='queue-intro compact-intro archive-tools'")
        main_end = page.index(b"</main>", main_start)
        self.assertLess(main_start, cleanup)
        self.assertLess(cleanup, main_end)
        self.assertIn(b"Preview release and forget", page[cleanup:main_end])

    async def test_dashboard_pages_share_navigation_shell(self) -> None:
        for page in (
            await self.server._dashboard_page(),
            await self.server._review_queue_page(),
            await self.server._enforcement_index_page(),
            await self.server._enforcement_index_page(archived=True),
        ):
            self.assertIn(b"data-dashboard-page", page)
            self.assertIn(b"</header><div data-dashboard-content>", page)
            self.assertEqual(page.count(b'<script src="/dashboard.js"'), 1)

    async def test_confirmation_pages_support_navigation_without_polling(self) -> None:
        status, _, page = await self.server._dispatch(
            "GET", "/cases/archive/forget?days=90", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"data-dashboard-page", page)
        self.assertIn(b"data-dashboard-content", page)
        self.assertIn(b'<script src="/dashboard.js" defer></script>', page)
        self.assertNotIn(b"data-live-refresh=", page)
        error = self.server._page("Not Found")
        self.assertNotIn(b"data-dashboard-page", error)
        self.assertNotIn(b"dashboard.js", error)

    async def test_list_pages_use_five_responsive_business_columns(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        self.store.suppress(
            sender_key,
            "challenge_timeout",
            until=int(time.time()) + 700,
            restriction_reference=self.protector.seal_restriction_reference(
                123456789, -987654321
            ),
        )

        cases = await self.server._enforcement_index_page()
        reviews = await self.server._review_queue_page()

        self.assertIn(
            b"<th>Sender</th><th>State</th><th>Trigger</th><th>Evidence</th><th>Age</th>",
            cases,
        )
        self.assertIn(f"href='/cases/{sender_key}'".encode(), cases)
        self.assertNotIn(b"<details class='advanced-recovery'>", cases)
        for label in (b"Sender", b"State", b"Trigger", b"Evidence", b"Age"):
            self.assertIn(b"data-label='" + label + b"'", cases)
        self.assertIn(
            b"<th>Sender</th><th>Review</th><th>Signals</th><th>Messages</th><th>Age</th>",
            reviews,
        )
        for label in (b"Sender", b"Review", b"Signals", b"Messages", b"Age"):
            self.assertIn(b"data-label='" + label + b"'", reviews)

    async def test_queue_compacts_signals_but_detail_keeps_full_breakdown(self) -> None:
        self.store._connection.execute(
            "UPDATE review_queue SET signals=? WHERE id=?",
            (
                '[{"code":"HR-01_MULTIPLE_LINK_BUTTONS","source":"rules","weight":12,'
                '"explanation":"First explanation"},{"code":"AUTHORED_DENIED_DOMAIN",'
                '"source":"heuristics","weight":70,"explanation":"Second explanation"}]',
                self.review_id,
            ),
        )
        queue = await self.server._review_queue_page()
        _, _, detail = await self.server._dispatch(
            "GET", f"/review/{self.review_id}", b""
        )

        self.assertIn(b"Multiple Link Buttons ", queue)
        self.assertIn(b"+1 more", queue)
        self.assertNotIn(b"First explanation", queue)
        self.assertIn(b"First explanation", detail)
        self.assertIn(b"Second explanation", detail)

    async def test_dashboard_css_keeps_accessibility_rules(self) -> None:
        status, headers, page = await self.server._dispatch("GET", "/dashboard.css", b"")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/css; charset=utf-8")

        self.assertIn(b":focus-visible", page)
        self.assertIn(b"@media(prefers-reduced-motion:reduce)", page)

    def test_active_case_state_summaries_cover_release_states(self) -> None:
        now = int(time.time())

        def restriction(
            status: str, suppressed_until: int | None
        ) -> ActiveRestriction:
            return ActiveRestriction(
                sender_key="sender",
                reference=None,
                status=status,
                reason="challenge_timeout",
                suppressed_until=suppressed_until,
                updated_at=now,
                envelope=None,
                evidence_created_at=None,
                evidence_expires_at=None,
                archived_at=None,
                has_open_actions=0,
            )

        self.assertEqual(
            self.server._restriction_summary(restriction("quarantined", None)),
            "Review needed",
        )
        self.assertEqual(
            self.server._restriction_summary(restriction("suppressed", None)),
            "No automatic release",
        )
        self.assertEqual(
            self.server._restriction_summary(restriction("suppressed", now - 1)),
            "Awaiting next message",
        )
        self.assertIn(
            "remaining",
            self.server._restriction_summary(restriction("suppressed", now + 700)),
        )

    async def test_dashboard_script_pauses_hidden_tabs_and_keeps_logout_enabled(self) -> None:
        status, headers, response = await self.server._dispatch(
            "GET", "/dashboard.js", b""
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/javascript; charset=utf-8")
        self.assertIn(b"document.visibilityState", response)
        self.assertIn(b"form:not(.logout-form) button", response)

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

    async def test_queue_identity_uses_short_lived_memory_cache(self) -> None:
        first = await self.server._review_queue_page()
        second = await self.server._review_queue_page()
        self.assertIn(b"Test Sender", first)
        self.assertIn(b"Test Sender", second)
        self.assertEqual(self.client.entity_requests, 1)

    async def test_error_page_uses_dashboard_layout_and_actionable_copy(self) -> None:
        response = self.server._page("Invalid Access Token")
        self.assertIn(b'href="/dashboard-error.css"', response)
        status, headers, _ = await self.server._dispatch(
            "GET",
            "/dashboard-error.css",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/css; charset=utf-8")
        self.assertIn(b"class='masthead'", response)
        self.assertIn(b"class='error-card'", response)
        self.assertIn(b"has already been used", response)
        self.assertIn(b"scripts/dashboard-tunnel.sh SSH_TARGET", response)
        self.assertIn(b"class='error-content'", response)

    async def test_partial_request_does_not_block_shutdown(self) -> None:
        await self.server.start()
        _, writer = await asyncio.open_unix_connection(self.server.socket_path)
        writer.write(b"GET / HTTP/1.1\r\n")
        await writer.drain()
        for _ in range(100):
            if self.server._connection_tasks:
                break
            await asyncio.sleep(0)
        self.assertTrue(self.server._connection_tasks)

        await asyncio.wait_for(self.server.stop(), timeout=1)

        writer.close()
        await writer.wait_closed()
        self.assertFalse(self.server.socket_path.exists())

    async def test_disconnected_writer_is_closed_and_untracked(self) -> None:
        class Reader:
            async def readuntil(self, _separator: bytes) -> bytes:
                return b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n\r\n"

            async def readexactly(self, _length: int) -> bytes:
                return b""

        class Writer:
            def __init__(self) -> None:
                self.closed = False

            def write(self, _data: bytes) -> None:
                pass

            async def drain(self) -> None:
                raise ConnectionResetError

            def close(self) -> None:
                self.closed = True

            async def wait_closed(self) -> None:
                pass

        writer = Writer()
        await self.server._handle_connection(Reader(), writer)

        self.assertTrue(writer.closed)
        self.assertFalse(self.server._connection_tasks)
        self.assertFalse(self.server._reading_tasks)

    async def test_admin_server_uses_owner_only_unix_socket(self) -> None:
        await self.server.start()
        try:
            self.assertTrue(stat.S_ISSOCK(self.server.socket_path.stat().st_mode))
            self.assertEqual(
                stat.S_IMODE(self.server.socket_path.stat().st_mode), 0o600
            )
            reader, writer = await asyncio.open_unix_connection(self.server.socket_path)
            self.server._activate_session()
            writer.write(
                (
                    f"GET /{self.server._capability_token}/dashboard.js HTTP/1.1\r\n"
                    "Host: 127.0.0.1:8765\r\n"
                    f"Cookie: {DASHBOARD_SESSION_COOKIE}="
                    f"{self.server._session_token}\r\n\r\n"
                ).encode("ascii")
            )
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()
            self.assertIn(b"Content-Type: text/javascript; charset=utf-8", response)
            self.assertIn(b"script-src 'self'; connect-src 'self'", response)
            self.assertIn(b"style-src 'self'", response)
            self.assertNotIn(b"'unsafe-inline'", response)
            self.assertIn(b"Cache-Control: no-store", response)
            self.assertIn(b"Referrer-Policy: no-referrer", response)
            self.assertNotIn(b"Set-Cookie:", response)
        finally:
            await self.server.stop()
        self.assertFalse(self.server.socket_path.exists())
        self.assertFalse(self.server.access_token_path.exists())

    async def test_production_dispatch_requires_capability_path(self) -> None:
        status, _, response = await self.server._dispatch(
            "GET", "/", b"", request_headers={"host": "127.0.0.1:8765"}
        )
        self.assertEqual(status, 404)
        self.assertIn(b"Dashboard Access Missing", response)
        for protected_path in (
            "/dashboard.js",
            "/dashboard.css",
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
        session_token = self.server._session_token
        self.assertEqual(headers["Location"], f"/{capability}/")
        self.assertIsNotNone(session_token)
        self.assertEqual(
            headers["Set-Cookie"],
            f"{DASHBOARD_SESSION_COOKIE}={session_token}; Path=/{capability}/; "
            f"Max-Age={DASHBOARD_SESSION_ABSOLUTE_SECONDS}; HttpOnly; SameSite=Strict",
        )
        replay_status, _, _ = await self.server._dispatch(
            "GET",
            f"/login?token={login_token}",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(replay_status, 400)
        copied_status, _, copied_page = await self.server._dispatch(
            "GET",
            f"/{capability}/",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(copied_status, 404)
        self.assertIn(b"Dashboard Access Missing", copied_page)
        wrong_cookie_status, _, _ = await self.server._dispatch(
            "GET",
            f"/{capability}/",
            b"",
            request_headers={
                "host": "127.0.0.1:8765",
                "cookie": (
                    f"{DASHBOARD_SESSION_COOKIE}=unrelated-local-service-cookie"
                ),
            },
        )
        self.assertEqual(wrong_cookie_status, 404)
        status, _, page = await self.server._dispatch(
            "GET",
            f"/{capability}/",
            b"",
            request_headers=self.authenticated_headers(),
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
                request_headers=self.authenticated_headers(),
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
            request_headers={
                "host": "127.0.0.1:8765",
                "cookie": f"{DASHBOARD_SESSION_COOKIE}={session_token}",
            },
        )
        self.assertEqual(stale_status, 404)

    async def test_dashboard_session_enforces_idle_and_absolute_timeouts(self) -> None:
        self.server._activate_session()
        headers = self.authenticated_headers()
        now = time.monotonic()

        self.server._session_started_at = now - DASHBOARD_SESSION_IDLE_SECONDS + 5
        self.server._session_last_seen_at = now - DASHBOARD_SESSION_IDLE_SECONDS + 5
        status, _, _ = await self.server._dispatch(
            "GET", f"/{self.server._capability_token}/", b"", request_headers=headers
        )
        self.assertEqual(status, 200)

        self.server._session_last_seen_at = (
            time.monotonic() - DASHBOARD_SESSION_IDLE_SECONDS
        )
        status, _, response = await self.server._dispatch(
            "GET", f"/{self.server._capability_token}/", b"", request_headers=headers
        )
        self.assertEqual(status, 404)
        self.assertIn(b"Dashboard Access Missing", response)

        self.server._activate_session()
        headers = self.authenticated_headers()
        self.server._session_started_at = (
            time.monotonic() - DASHBOARD_SESSION_ABSOLUTE_SECONDS
        )
        status, _, response = await self.server._dispatch(
            "GET", f"/{self.server._capability_token}/", b"", request_headers=headers
        )
        self.assertEqual(status, 404)
        self.assertIn(b"Dashboard Access Missing", response)

    async def test_logout_revokes_session_capability_and_login_token(self) -> None:
        self.server._activate_session()
        capability = self.server._capability_token
        session_token = self.server._session_token
        access_token = self.server._access_token
        body = urlencode({"token": self.server._csrf_token}).encode()
        status, headers, _ = await self.server._dispatch(
            "POST",
            f"/{capability}/logout",
            body,
            request_headers=self.authenticated_headers(),
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/logged-out")
        self.assertEqual(
            headers["Set-Cookie"],
            f"{DASHBOARD_SESSION_COOKIE}=; Path=/{capability}/; Max-Age=0; "
            "HttpOnly; SameSite=Strict",
        )
        self.assertIsNone(self.server._session_token)
        self.assertNotEqual(self.server._capability_token, capability)
        self.assertNotEqual(self.server._access_token, access_token)
        stale_status, _, _ = await self.server._dispatch(
            "GET",
            f"/{capability}/",
            b"",
            request_headers={
                "host": "127.0.0.1:8765",
                "cookie": f"{DASHBOARD_SESSION_COOKIE}={session_token}",
            },
        )
        self.assertEqual(stale_status, 404)
        signed_out_status, _, signed_out_page = await self.server._dispatch(
            "GET",
            "/logged-out",
            b"",
            request_headers={"host": "127.0.0.1:8765"},
        )
        self.assertEqual(signed_out_status, 200)
        self.assertIn(b"Dashboard Signed Out", signed_out_page)

    async def test_logout_requires_post_and_valid_csrf(self) -> None:
        self.server._activate_session()
        path = f"/{self.server._capability_token}/logout"
        status, headers, _ = await self.server._dispatch(
            "GET", path, b"", request_headers=self.authenticated_headers()
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "POST")
        session_token = self.server._session_token
        status, _, response = await self.server._dispatch(
            "POST",
            path,
            urlencode({"token": "invalid"}).encode(),
            request_headers=self.authenticated_headers(),
        )
        self.assertEqual(status, 400)
        self.assertIn(b"Invalid Action Token", response)
        self.assertEqual(self.server._session_token, session_token)

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
        first = await self.server.backend.request("cases.list", {"page": 1})
        self.assertEqual(len(first["items"]), 3)
        self.assertEqual(self.client.entity_requests, 1)

        self.server.backend._identity_cache.clear()
        self.client.fail_entity_requests = True
        failed = await self.server.backend.request("cases.list", {"page": 1})
        repeated = await self.server.backend.request("cases.list", {"page": 1})
        self.assertEqual(len(failed["items"]), 3)
        self.assertEqual(len(repeated["items"]), 3)
        self.assertEqual(self.client.entity_requests, 2)

    async def test_active_case_uses_case_specific_limited_evidence_guidance(
        self,
    ) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_review_reference(
            123456789, -987654321, 42
        )
        envelope = self.review_protector.seal(
            {
                "schema_version": 5,
                "text": "",
                "quote_text": "",
                "preview_text": "",
                "button_texts": ["Open"],
                "urls": [{"url": "https://example.invalid"}],
                "signals": [
                    {
                        "code": "MULTIPLE_LINK_BUTTONS",
                        "source": "button",
                        "weight": 25,
                        "explanation": "Several link buttons were attached.",
                    }
                ],
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
        self.assertIn(b"Evidence Signals", detail)
        self.assertIn(b"<ol class='signal-list'", detail)
        self.assertIn(b"<strong>Multiple Link Buttons</strong>", detail)

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
                        "code": "PREVIEW_PROMOTIONAL_LANGUAGE",
                        "source": "preview",
                        "weight": 20,
                        "explanation": explanation,
                    }
                ],
                "risk_score": 30,
                "challenge_profile": "strict",
                "planned_action": "strict_challenge",
                "decision_basis": "risk_score_requires_strict_challenge",
                "policy_version": "adaptive-v2",
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
        self.assertIn(b"class=\"policy-map\"", detail)
        self.assertIn(b"Risk score 30; strict challenge starts at 30", detail)
        self.assertIn(b"<strong>30</strong><small>Additive points", detail)
        self.assertIn(b"<span class=\"policy-version\">adaptive-v2</span>", detail)
        self.assertIn(b"not a probability", detail)
        self.assertIn(b"<strong>30 \xe2\x89\xa5 70</strong>", detail)
        self.assertIn(b"gate-check unmet", detail)
        self.assertIn(b"Final Policy Decision", detail)
        self.assertIn(b"<strong>Strict Challenge</strong>", detail)
        self.assertIn(b"<ol class='signal-list' aria-label='Evidence signals'>", detail)
        self.assertIn(b"<strong>Preview Promotional Language</strong>", detail)
        self.assertIn(b"<span class='signal-source'>Preview</span>", detail)
        self.assertIn(b"<span class='signal-score'>+20</span>", detail)
        self.assertIn(b"Telegram &lt;preview&gt; metadata", detail)
        self.assertNotIn(explanation.encode(), detail)

    def test_policy_decision_panel_explains_both_permanent_gates(self) -> None:
        no_destructive_gate = self.server._policy_decision_panel(
            {
                "risk_score": 70,
                "planned_action": "strict_challenge",
                "signals": [
                    {"code": "FORWARDED_PAYLOAD"},
                    {"code": "QUOTED_MULTIPLE_LINKS"},
                    {"code": "QUOTED_PROMOTIONAL_LANGUAGE"},
                ],
            }
        )
        self.assertIn("<strong>70 ≥ 70</strong>", no_destructive_gate)
        self.assertIn("gate-check met", no_destructive_gate)
        self.assertIn("gate-check unmet", no_destructive_gate)
        self.assertIn("Not met · No non-quoted denylist match", no_destructive_gate)
        self.assertIn("score reached 70, but permanent suppression", no_destructive_gate)
        self.assertIn("<strong>Strict Challenge</strong>", no_destructive_gate)

        permanent = self.server._policy_decision_panel(
            {
                "risk_score": 100,
                "planned_action": "permanent_suppression",
                "signals": [{"code": "AUTHORED_DENIED_DOMAIN"}],
            }
        )
        self.assertEqual(permanent.count("gate-check met"), 2)
        self.assertNotIn("gate-check unmet", permanent)
        self.assertIn("Met · Non-quoted owner-denied domain", permanent)
        self.assertIn("<strong>Permanent Suppression</strong>", permanent)
        self.assertIn("Both permanent-suppression conditions were met", permanent)

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
                "schema_version": 5,
                "text": "enforcement-private-canary",
                "quote_text": "quoted-enforcement-canary",
                "signals": [],
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
            until=None,
            reference=reference,
            restriction_reference=self.protector.seal_restriction_reference(
                123456789, -987654321
            ),
        )
        index = await self.server._enforcement_index_page()
        self.assertIn(b"Active Cases", index)
        self.assertIn(b"Test Sender (@testsender)", index)
        self.assertIn(b"Reviewable Evidence", index)
        self.assertIn(b"State reasons:", index)
        self.assertIn(b"Every active restriction currently has reviewable evidence", index)
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

    async def test_archived_list_defers_identity_and_single_forget_is_confirmed(
        self,
    ) -> None:
        sender_key = "a" * 64
        self.store.suppress(
            sender_key,
            "critical_rule",
            until=None,
            restriction_reference=self.protector.seal_restriction_reference(
                123456789, -987654321
            ),
        )
        self.store.archive_restriction(sender_key, int(time.time()) - 40 * 86400)

        status, _, page = await self.server._dispatch("GET", "/cases/archive", b"")
        self.assertEqual(status, 200)
        self.assertIn(b"Archived Restrictions", page)
        self.assertIn(b"Archived Sender", page)
        self.assertEqual(self.client.entity_requests, 0)

        status, _, confirmation = await self.server._dispatch(
            "GET", f"/cases/{sender_key}/forget", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"does not restore, move, unmute, or delete", confirmation)
        body = urlencode({"token": self.server._csrf_token}).encode()
        status, headers, _ = await self.server._dispatch(
            "POST", f"/cases/{sender_key}/forget", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases/archive")
        self.assertEqual(self.store.sender(sender_key).status, "unknown")

    async def test_keep_archive_requires_confirmation_page_and_csrf(self) -> None:
        sender_key = "d" * 64
        self.store.suppress(sender_key, "critical_rule", until=None)

        status, _, confirmation = await self.server._dispatch(
            "GET", f"/cases/{sender_key}/archive", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"permanent suppression remains in force", confirmation)
        self.assertIsNone(self.store.active_restriction(sender_key).archived_at)

        status, _, _ = await self.server._dispatch(
            "POST", f"/cases/{sender_key}/archive", b"token=invalid"
        )
        self.assertEqual(status, 400)
        body = urlencode({"token": self.server._csrf_token}).encode()
        status, headers, _ = await self.server._dispatch(
            "POST", f"/cases/{sender_key}/archive", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/cases/archive")
        self.assertIsNotNone(self.store.active_restriction(sender_key).archived_at)

    async def test_bulk_forget_previews_and_rechecks_age(self) -> None:
        now = int(time.time())
        for sender_key, age in (("b" * 64, 100), ("c" * 64, 10)):
            self.store.suppress(
                sender_key, "critical_rule", until=None, now=now - age * 86400
            )
            self.store.archive_restriction(sender_key, now - age * 86400)

        status, _, preview = await self.server._dispatch(
            "GET", "/cases/archive/forget?days=90", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"1 Eligible", preview)
        body = urlencode(
            {"token": self.server._csrf_token, "days": "90"}
        ).encode()
        status, _, _ = await self.server._dispatch(
            "POST", "/cases/archive/forget", body
        )
        self.assertEqual(status, 303)
        self.assertEqual(self.store.sender("b" * 64).status, "unknown")
        self.assertEqual(self.store.sender("c" * 64).status, "suppressed")

    async def test_expired_suppression_does_not_offer_to_extend_restriction(
        self,
    ) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_review_reference(
            123456789, -987654321, 42
        )
        envelope = self.review_protector.seal(
            {"schema_version": 5, "text": "private-canary"}
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
        self.assertNotIn(b"Keep and Archive", detail)

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
                {"schema_version": 5, "text": "expired-private-canary"}
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
        self.assertIn(b"Unavailable", index)
        self.assertNotIn(b"expired-private-canary", index)

        status, _, detail = await self.server._dispatch_enforcement(
            "GET", f"/cases/{sender_key}", b""
        )
        self.assertEqual(status, 200)
        self.assertIn(b"Evidence expired or unavailable", detail)
        self.assertIn(b"Allow Sender", detail)
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
        self.assertIn(b"Allow Sender", detail)

    async def test_active_enforcement_disables_allow_without_identity(self) -> None:
        sender_key = self.protector.sender_key(987654321)
        envelope = self.review_protector.seal(
            {"schema_version": 5, "text": "private-canary", "quote_text": ""}
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
        self.assertIn(b"Identity Unavailable", page)
        self.assertIn(b"Unavailable", page)
        self.assertIn(
            b"1 restriction without a control identity requires manual ID recovery.",
            page,
        )
        self.assertIn(b"<details class='advanced-recovery'>", page)
        self.assertNotIn(b"<details class='advanced-recovery' open", page)
        self.assertIn(b"Allow an Unidentified Restricted Sender by Telegram User ID", page)
        self.assertIn(b"Allow Without Restore", page)
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
        self.assertIn(b"Use Allow Sender in Active Cases", response)
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
        self.assertNotIn("sender", self.server.backend._identity_cache)

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
        self.assertIsNotNone(self.store.active_restriction("sender").archived_at)
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
