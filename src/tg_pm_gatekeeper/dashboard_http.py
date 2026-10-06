# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Owner-only Dashboard HTTP server: request parsing, authentication gate, and routing."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

from .dashboard_protocol import DashboardBackend, DashboardBackendError
from .dashboard_session import (
    DASHBOARD_SESSION_ABSOLUTE_SECONDS,
    DASHBOARD_SESSION_COOKIE,
    DASHBOARD_SESSION_IDLE_SECONDS,
    DashboardCredentials,
)
from .dashboard_views.components import (
    confirmation_page,
    identity_from_value,
    render_page,
)
from .dashboard_views.pages import (
    case_detail_page,
    cases_list_base,
    cases_page,
    overview_page,
    paged_target,
    review_detail_page,
    review_queue_page,
)
from .states import SenderStatus

__all__ = [
    "DASHBOARD_SESSION_ABSOLUTE_SECONDS",
    "DASHBOARD_SESSION_COOKIE",
    "DASHBOARD_SESSION_IDLE_SECONDS",
    "DashboardHttpServer",
]

LOG = logging.getLogger("gatekeeper.dashboard_http")
MAX_HEADER_BYTES = 16 * 1024
MAX_BODY_BYTES = 4 * 1024
REQUEST_READ_TIMEOUT_SECONDS = 5
ASSETS = frozenset(
    {"/dashboard.js", "/dashboard-theme.js", "/dashboard.css", "/dashboard-error.css"}
)

Response = tuple[int, dict[str, str], bytes]
Handler = Callable[[str, str, str, bytes], Awaitable[Response]]
Matcher = Callable[[str], str | None]


def _exact(expected: str) -> Matcher:
    return lambda path: "" if path == expected else None


def _prefixed(prefix: str) -> Matcher:
    return lambda path: path.removeprefix(prefix) if path.startswith(prefix) else None


def _between(prefix: str, suffix: str) -> Matcher:
    def match(path: str) -> str | None:
        if not (path.startswith(prefix) and path.endswith(suffix)):
            return None
        return path.removeprefix(prefix).removesuffix(suffix)

    return match


def _asset(path: str) -> str | None:
    return path.removeprefix("/") if path in ASSETS else None


@dataclass(frozen=True, slots=True)
class Route:
    """The matcher returns the path parameter, or None when the route does not apply."""

    match: Matcher
    handler: str
    methods: frozenset[str] | None = None


GET = frozenset({"GET"})
# Order matters: the first route whose method and path both match handles the request,
# and a GET-only route lets other methods fall through to later routes.
ROUTES = (
    Route(_asset, "_serve_asset"),
    Route(_exact("/dashboard/status"), "_page_status"),
    Route(_exact("/"), "_overview_route", GET),
    Route(_exact("/review"), "_review_list_route", GET),
    Route(_exact("/cases/archive"), "_archive_list_route", GET),
    Route(_exact("/cases/archive/forget"), "_dispatch_bulk_forget"),
    Route(_between("/cases/", "/archive"), "_dispatch_archive_confirmation"),
    Route(_between("/cases/", "/forget"), "_dispatch_forget_confirmation"),
    Route(_exact("/cases"), "_cases_list_route", GET),
    Route(_exact("/cases/release"), "_dispatch_legacy_release"),
    Route(_prefixed("/cases/"), "_dispatch_enforcement"),
    Route(_between("/review/", "/spam"), "_dispatch_spam_confirmation"),
    Route(_prefixed("/review/"), "_dispatch_review"),
)


class DashboardHttpServer:
    def __init__(
        self,
        socket_path: Path,
        backend: DashboardBackend,
        *,
        on_authenticated_activity: Callable[[], None] = lambda: None,
        on_logout: Callable[[], None] = lambda: None,
    ) -> None:
        self.socket_path = socket_path
        self.backend = backend
        self._on_authenticated_activity = on_authenticated_activity
        self._on_logout = on_logout
        self._server: asyncio.AbstractServer | None = None
        self._connection_tasks: set[asyncio.Task[object]] = set()
        self._reading_tasks: set[asyncio.Task[object]] = set()
        self.access_token_path = socket_path.with_suffix(".access-token")
        self.credentials = DashboardCredentials(self.access_token_path)

    async def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_info = self.socket_path.parent.stat()
        if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o077:
            raise RuntimeError("dashboard runtime directory is not owner-only")
        try:
            info = self.socket_path.lstat()
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(info.st_mode):
                raise RuntimeError("review socket path is not a socket")
            self.socket_path.unlink()
        self._server = await asyncio.start_unix_server(
            self._handle_connection, path=self.socket_path
        )
        os.chmod(self.socket_path, 0o600)
        self.credentials.write_access_token()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            current = asyncio.current_task()
            for task in self._reading_tasks:
                if task is not current:
                    task.cancel()
            await self._server.wait_closed()
            self._server = None
        current = asyncio.current_task()
        pending = [task for task in self._connection_tasks if task is not current]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        self.access_token_path.unlink(missing_ok=True)
        self.access_token_path.with_suffix(".access-token.tmp").unlink(missing_ok=True)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._connection_tasks.add(task)
        try:
            try:
                if task is not None:
                    self._reading_tasks.add(task)
                try:
                    method, target, body, request_headers = await asyncio.wait_for(
                        self._read_request(reader), timeout=REQUEST_READ_TIMEOUT_SECONDS
                    )
                finally:
                    if task is not None:
                        self._reading_tasks.discard(task)
                status, headers, response = await self._dispatch(
                    method, target, body, request_headers=request_headers
                )
            except (ValueError, asyncio.IncompleteReadError, TimeoutError):
                status, headers, response = 400, {}, render_page("Invalid Request")
            except Exception:
                LOG.error("review_request_failed")
                status, headers, response = 500, {}, render_page("Request Failed")
            reason = {
                200: "OK",
                303: "See Other",
                400: "Bad Request",
                404: "Not Found",
                405: "Method Not Allowed",
                409: "Conflict",
                503: "Service Unavailable",
            }.get(status, "Internal Server Error")
            response_headers = {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": str(len(response)),
                "Connection": "close",
                "Cache-Control": "no-store",
                "Content-Security-Policy": (
                    "default-src 'none'; style-src 'self'; script-src 'self'; "
                    "connect-src 'self'; "
                    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
                ),
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                **headers,
            }
            head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(
                f"{name}: {value}\r\n" for name, value in response_headers.items()
            )
            writer.write(head.encode("ascii") + b"\r\n" + response)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            if task is not None:
                self._connection_tasks.discard(task)

    async def _read_request(
        self, reader: asyncio.StreamReader
    ) -> tuple[str, str, bytes, dict[str, str]]:
        header = await reader.readuntil(b"\r\n\r\n")
        if len(header) > MAX_HEADER_BYTES:
            raise ValueError("headers too large")
        lines = header.decode("iso-8859-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or parts[2] != "HTTP/1.1":
            raise ValueError("invalid request line")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            name, separator, value = line.partition(":")
            if not separator:
                raise ValueError("invalid header")
            headers[name.casefold()] = value.strip()
        try:
            content_length = int(headers.get("content-length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if content_length < 0 or content_length > MAX_BODY_BYTES:
            raise ValueError("body too large")
        return (
            parts[0],
            parts[1],
            await reader.readexactly(content_length),
            headers,
        )

    async def _dispatch(
        self,
        method: str,
        target: str,
        body: bytes,
        *,
        request_headers: dict[str, str] | None = None,
    ) -> Response:
        parsed = urlsplit(target)
        if request_headers is None:
            return await self._dispatch_routes(method, target, body)
        host = request_headers.get("host", "")
        if not (host.startswith("127.0.0.1:") or host.startswith("localhost:")):
            return 400, {}, render_page("Invalid Host")
        if parsed.path == "/dashboard-error.css":
            return await self._dispatch_routes(method, target, body)
        if parsed.path == "/logged-out":
            if method != "GET":
                return 405, {"Allow": "GET"}, b""
            return 200, {}, render_page("Dashboard Signed Out")
        credentials = self.credentials
        if parsed.path == "/login":
            token = parse_qs(parsed.query).get("token", [""])[0]
            if not credentials.accepts_login(token):
                return 400, {}, render_page("Invalid Access Token")
            credentials.start_session()
            self._on_authenticated_activity()
            credentials.write_access_token()
            return (
                303,
                {
                    "Location": f"/{credentials.capability_token}/",
                    "Set-Cookie": credentials.session_cookie_header(),
                },
                b"",
            )
        logical_path = credentials.logical_path(parsed.path)
        if logical_path is None or not credentials.has_valid_session(request_headers):
            return 404, {}, render_page("Dashboard Access Missing")
        if logical_path == "/logout":
            if method != "POST":
                return 405, {"Allow": "POST"}, b""
            try:
                values = parse_qs(body.decode("utf-8"), strict_parsing=True)
            except (UnicodeDecodeError, ValueError):
                return 400, {}, render_page("Invalid Action Token")
            if not credentials.accepts_csrf(values.get("token", [""])[0]):
                return 400, {}, render_page("Invalid Action Token")
            expired_cookie = credentials.expired_session_cookie_header()
            credentials.invalidate_session()
            asyncio.get_running_loop().call_soon(self._on_logout)
            return (
                303,
                {"Location": "/logged-out", "Set-Cookie": expired_cookie},
                b"",
            )
        logical_target = urlunsplit(parsed._replace(path=logical_path))
        status, headers, response = await self._dispatch_routes(
            method, logical_target, body
        )
        if status < 400:
            credentials.record_activity()
            self._on_authenticated_activity()
        return status, credentials.capability_headers(headers), credentials.capability_html(
            response, headers
        )

    async def _dispatch_routes(self, method: str, target: str, body: bytes) -> Response:
        parsed = urlsplit(target)
        for route in ROUTES:
            if route.methods is not None and method not in route.methods:
                continue
            param = route.match(parsed.path)
            if param is not None:
                handler: Handler = getattr(self, route.handler)
                return await handler(method, param, parsed.query, body)
        return 404, {}, render_page("Not Found")

    def _csrf_form(self, body: bytes) -> dict[str, list[str]] | None:
        """Parse a posted form; None when its CSRF token is wrong."""
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        if not self.credentials.accepts_csrf(values.get("token", [""])[0]):
            return None
        return values

    async def _serve_asset(
        self, method: str, asset_name: str, _query: str, _body: bytes
    ) -> Response:
        if method != "GET":
            return 405, {"Allow": "GET"}, b""
        content_type = (
            "text/javascript; charset=utf-8"
            if asset_name.endswith(".js")
            else "text/css; charset=utf-8"
        )
        return (
            200,
            {"Content-Type": content_type},
            files("tg_pm_gatekeeper.assets").joinpath(asset_name).read_bytes(),
        )

    async def _page_status(
        self, method: str, _param: str, query: str, _body: bytes
    ) -> Response:
        if method != "GET":
            return 405, {"Allow": "GET"}, b""
        page_path = parse_qs(query).get("path", [""])[0]
        try:
            version_result = await self.backend.request(
                "page_version", {"target": page_path}
            )
        except DashboardBackendError:
            return 404, {"Content-Type": "application/json"}, b"{}"
        version = version_result.get("version")
        if version is None:
            return 404, {"Content-Type": "application/json"}, b"{}"
        payload = json.dumps(
            {
                "version": version,
                "checked_at": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        return 200, {"Content-Type": "application/json"}, payload

    async def _overview_route(
        self, _method: str, _param: str, _query: str, _body: bytes
    ) -> Response:
        return 200, {}, await self._dashboard_page()

    async def _review_list_route(
        self, _method: str, _param: str, query: str, _body: bytes
    ) -> Response:
        page = self._page_number(query)
        if page is None:
            return 404, {}, render_page("Not Found")
        try:
            return 200, {}, await self._review_queue_page(page=page)
        except DashboardBackendError:
            return 404, {}, render_page("Not Found")

    async def _archive_list_route(
        self, _method: str, _param: str, query: str, _body: bytes
    ) -> Response:
        page = self._page_number(query)
        if page is None:
            return 404, {}, render_page("Not Found")
        values = parse_qs(query)
        reason = values.get("reason", [None])[0]
        older_text = values.get("older_days", [None])[0]
        older_days = int(older_text) if older_text in {"30", "90", "180", "365"} else None
        if older_text is not None and older_days is None:
            return 400, {}, render_page("Invalid Archive Filter")
        try:
            return 200, {}, await self._enforcement_index_page(
                page=page, archived=True, reason=reason, older_days=older_days
            )
        except DashboardBackendError:
            return 404, {}, render_page("Not Found")

    async def _cases_list_route(
        self, _method: str, _param: str, query: str, _body: bytes
    ) -> Response:
        page = self._page_number(query)
        if page is None:
            return 404, {}, render_page("Not Found")
        try:
            return 200, {}, await self._enforcement_index_page(page=page)
        except DashboardBackendError:
            return 404, {}, render_page("Not Found")

    async def _dispatch_review(
        self, method: str, raw_review_id: str, _query: str, body: bytes
    ) -> Response:
        try:
            review_id = int(raw_review_id)
        except ValueError:
            return 404, {}, render_page("Not Found")
        if method == "GET":
            try:
                return await self._show_review(review_id)
            except DashboardBackendError as exc:
                return self._backend_error(exc.code)
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, render_page("Method Not Allowed")
        values = self._csrf_form(body)
        if values is None:
            return 400, {}, render_page("Invalid Action Token")
        action = values.get("action", [""])[0]
        if action == "spam":
            # Deleting the conversation is irreversible; it is accepted only after confirmation.
            return 400, {}, render_page("Confirmation Required")
        try:
            await self.backend.request(
                "reviews.decide", {"review_id": review_id, "action": action}
            )
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/review"}, b""

    def _backend_error(self, code: str) -> Response:
        status, title = {
            "unknown_action": (400, "Unknown Action"),
            "invalid_request": (400, "Invalid Request"),
            "review_not_found": (404, "Review Item Not Found"),
            "review_already_decided": (409, "This Item Has Already Been Reviewed"),
            "review_not_pending": (409, "This Item Is No Longer Pending"),
            "case_not_found": (404, "Active Case Not Found"),
            "case_not_active": (409, "This Restriction Is No Longer Active"),
            "identity_unavailable": (409, "Telegram Identity Is Unavailable"),
            "restricted_sender_not_found": (409, "Restricted Sender Not Found"),
            "use_active_case": (409, "Use Allow Sender in Active Cases"),
            "telegram_action_failed": (
                500,
                "Telegram Action Failed; Item Was Not Changed",
            ),
            "restriction_release_failed": (500, "Restriction Release Failed"),
            "case_not_archived": (409, "This Restriction Is Not Archived"),
            "case_not_forgettable": (
                409, "This Restriction Cannot Be Forgotten While Work Is Pending"
            ),
            "core_unavailable": (503, "Dashboard Core Is Unavailable"),
        }.get(code, (500, "Request Failed"))
        return status, {}, render_page(title)

    @staticmethod
    def _page_number(query: str) -> int | None:
        raw = parse_qs(query).get("page", ["1"])[0]
        if not raw.isascii() or not raw.isdecimal():
            return None
        page = int(raw)
        return page if 1 <= page <= 100_000 else None

    async def _backend_page_version(self, target: str) -> str | None:
        result = await self.backend.request("page_version", {"target": target})
        version = result.get("version")
        return version if isinstance(version, str) else None

    async def _dispatch_enforcement(
        self, method: str, path: str, _query: str, body: bytes
    ) -> Response:
        sender_key = path.rsplit("/", 1)[-1]
        if len(sender_key) != 64 or any(char not in "0123456789abcdef" for char in sender_key):
            return 404, {}, render_page("Active Case Not Found")
        if method == "GET":
            try:
                return await self._show_enforcement(sender_key)
            except DashboardBackendError as exc:
                return self._backend_error(exc.code)
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, render_page("Method Not Allowed")
        values = self._csrf_form(body)
        if values is None:
            return 400, {}, render_page("Invalid Action Token")
        action = values.get("action", [""])[0]
        try:
            await self.backend.request(
                "cases.decide", {"sender_key": sender_key, "action": action}
            )
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/cases"}, b""

    async def _dispatch_legacy_release(
        self, method: str, _param: str, _query: str, body: bytes
    ) -> Response:
        if method != "POST":
            return 405, {"Allow": "POST"}, render_page("Method Not Allowed")
        values = self._csrf_form(body)
        if values is None:
            return 400, {}, render_page("Invalid Action Token")
        user_id_text = values.get("user_id", [""])[0]
        if not user_id_text.isascii() or not user_id_text.isdecimal():
            return 400, {}, render_page("Invalid Telegram User ID")
        user_id = int(user_id_text)
        if user_id <= 0 or user_id > (2**63 - 1):
            return 400, {}, render_page("Invalid Telegram User ID")
        try:
            await self.backend.request("cases.release_legacy", {"user_id": user_id})
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/cases"}, b""

    async def _dispatch_forget_confirmation(
        self, method: str, sender_key: str, _query: str, body: bytes
    ) -> Response:
        if len(sender_key) != 64 or any(
            char not in "0123456789abcdef" for char in sender_key
        ):
            return 404, {}, render_page("Archived Restriction Not Found")
        if method == "GET":
            try:
                item = await self.backend.request(
                    "cases.detail", {"sender_key": sender_key}
                )
            except DashboardBackendError as exc:
                return self._backend_error(exc.code)
            if item.get("archived_at") is None or item.get("suppressed_until") is not None:
                return self._backend_error("case_not_archived")
            return 200, {}, confirmation_page(
                csrf_token=self.credentials.csrf_token,
                nav="archive",
                title="Release and Forget This Archived Restriction?",
                body=(
                    "This removes all local policy, evidence, identity, snapshot, and history "
                    "data. It does not restore, move, unmute, or delete the Telegram "
                    "conversation. A future message will be handled as an unknown sender."
                ),
                action=f"/cases/{sender_key}/forget",
                button="Release and Forget",
                tone="block",
                cancel_href="/cases/archive",
                page_title="Forget Restriction",
                warning="Destructive Local Action",
            )
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, render_page("Method Not Allowed")
        values = self._csrf_form(body)
        if values is None:
            return 400, {}, render_page("Invalid Action Token")
        try:
            await self.backend.request(
                "cases.decide", {"sender_key": sender_key, "action": "forget"}
            )
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/cases/archive"}, b""

    async def _dispatch_spam_confirmation(
        self, method: str, raw_review_id: str, _query: str, body: bytes
    ) -> Response:
        if not raw_review_id.isascii() or not raw_review_id.isdecimal():
            return 404, {}, render_page("Not Found")
        review_id = int(raw_review_id)
        if method == "GET":
            try:
                item = await self.backend.request(
                    "reviews.detail", {"review_id": review_id}
                )
            except DashboardBackendError as exc:
                return self._backend_error(exc.code)
            identity_value = identity_from_value(item.get("identity"))
            identity = "this sender"
            if identity_value is not None:
                identity = identity_value.name or f"ID {identity_value.user_id}"
                if identity_value.username:
                    identity += f" (@{identity_value.username})"
            return 200, {}, confirmation_page(
                csrf_token=self.credentials.csrf_token,
                nav="reviews",
                title=f"Suppress {identity} and Delete the Conversation?",
                body=(
                    "This permanently suppresses the sender and deletes the whole Telegram "
                    "conversation for both sides. Gatekeeper archives and mutes the dialog "
                    "first if needed, then runs the deletion immediately, including in "
                    "Monitor mode. Every pending review for this sender is resolved as spam. "
                    "Deleted messages cannot be recovered; allowing the sender later only "
                    "lifts the restriction."
                ),
                action=f"/review/{review_id}/spam",
                button="Suppress and Delete",
                tone="block",
                cancel_href=f"/review/{review_id}",
                page_title="Suppress and Delete",
                warning="Irreversible Telegram Action",
            )
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, render_page("Method Not Allowed")
        values = self._csrf_form(body)
        if values is None:
            return 400, {}, render_page("Invalid Action Token")
        try:
            await self.backend.request(
                "reviews.decide", {"review_id": review_id, "action": "spam"}
            )
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/review"}, b""

    async def _dispatch_archive_confirmation(
        self, method: str, sender_key: str, _query: str, body: bytes
    ) -> Response:
        if len(sender_key) != 64 or any(
            char not in "0123456789abcdef" for char in sender_key
        ):
            return 404, {}, render_page("Active Case Not Found")
        if method == "GET":
            try:
                item = await self.backend.request(
                    "cases.detail", {"sender_key": sender_key}
                )
            except DashboardBackendError as exc:
                return self._backend_error(exc.code)
            if (
                item.get("status") != SenderStatus.SUPPRESSED
                or item.get("suppressed_until") is not None
                or item.get("archived_at") is not None
            ):
                return self._backend_error("case_not_found")
            return 200, {}, confirmation_page(
                csrf_token=self.credentials.csrf_token,
                nav="cases",
                title="Keep This Restriction and Move It to the Archive?",
                body=(
                    "The permanent suppression remains in force. The sender will remain "
                    "blocked by local policy, while its reviewable evidence keeps the existing "
                    "expiry. You can move the restriction back to Needs Attention later."
                ),
                action=f"/cases/{sender_key}/archive",
                button="Keep and Archive",
                tone="primary",
                cancel_href=f"/cases/{sender_key}",
                page_title="Archive Restriction",
            )
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, render_page("Method Not Allowed")
        values = self._csrf_form(body)
        if values is None:
            return 400, {}, render_page("Invalid Action Token")
        try:
            await self.backend.request(
                "cases.decide", {"sender_key": sender_key, "action": "keep"}
            )
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/cases/archive"}, b""

    async def _dispatch_bulk_forget(
        self, method: str, _param: str, query: str, body: bytes
    ) -> Response:
        source = parse_qs(query if method == "GET" else body.decode("utf-8"))
        raw_days = source.get("days", [""])[0]
        if raw_days not in {"30", "90", "180", "365"}:
            return 400, {}, render_page("Invalid Retention Age")
        days = int(raw_days)
        if method == "GET":
            result = await self.backend.request(
                "cases.forget_preview", {"days": days}
            )
            count = int(result["count"])
            return 200, {}, confirmation_page(
                csrf_token=self.credentials.csrf_token,
                nav="archive",
                title=(
                    f"Release and Forget {count} Archived "
                    f"Restriction{'s' if count != 1 else ''}?"
                ),
                body=(
                    f"Only permanent restrictions archived for at least {days} days and with "
                    "no pending or failed work are eligible. Telegram conversations are not "
                    "changed."
                ),
                action="/cases/archive/forget",
                hidden={"days": str(days)},
                button="Confirm Bulk Forget",
                tone="block",
                cancel_href="/cases/archive",
                page_title="Bulk Forget",
                warning="Destructive Local Action",
                disabled=count == 0,
            )
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, render_page("Method Not Allowed")
        if not self.credentials.accepts_csrf(source.get("token", [""])[0]):
            return 400, {}, render_page("Invalid Action Token")
        await self.backend.request("cases.forget_bulk", {"days": days})
        return 303, {"Location": "/cases/archive"}, b""

    async def _enforcement_index_page(
        self, *, page: int = 1, archived: bool = False,
        reason: str | None = None, older_days: int | None = None,
    ) -> bytes:
        result = await self.backend.request(
            "cases.list", {
                "page": page, "archived": archived,
                **({"reason": reason} if reason else {}),
                **({"older_days": older_days} if older_days else {}),
            }
        )
        base = cases_list_base(archived=archived, reason=reason, older_days=older_days)
        return cases_page(
            result,
            page=page,
            archived=archived,
            reason=reason,
            older_days=older_days,
            csrf_token=self.credentials.csrf_token,
            page_version=await self._backend_page_version(paged_target(base, page)),
        )

    async def _show_enforcement(
        self, item: Any | str
    ) -> Response:
        sender_key = item if isinstance(item, str) else item.sender_key
        result = await self.backend.request(
            "cases.detail", {"sender_key": sender_key}
        )
        return 200, {}, case_detail_page(
            result,
            csrf_token=self.credentials.csrf_token,
            page_version=await self._backend_page_version(f"/cases/{result['sender_key']}"),
        )

    async def _show_review(
        self, item: Any | int
    ) -> Response:
        review_id = item if isinstance(item, int) else item.id
        result = await self.backend.request(
            "reviews.detail", {"review_id": review_id}
        )
        return 200, {}, review_detail_page(
            result,
            csrf_token=self.credentials.csrf_token,
            page_version=await self._backend_page_version(f"/review/{result['id']}"),
        )

    async def _dashboard_page(self) -> bytes:
        result = await self.backend.request("overview", {})
        return overview_page(
            result,
            csrf_token=self.credentials.csrf_token,
            page_version=await self._backend_page_version("/"),
        )

    async def _review_queue_page(self, *, page: int = 1) -> bytes:
        result = await self.backend.request("reviews.list", {"page": page})
        return review_queue_page(
            result,
            page=page,
            csrf_token=self.credentials.csrf_token,
            page_version=await self._backend_page_version(paged_target("/review", page)),
        )
