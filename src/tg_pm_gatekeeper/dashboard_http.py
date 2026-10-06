# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import secrets
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from .dashboard_protocol import DashboardBackend, DashboardBackendError
from .policy import EvidenceSignal, PolicyEngine

LOG = logging.getLogger("gatekeeper.dashboard_http")
MAX_HEADER_BYTES = 16 * 1024
MAX_BODY_BYTES = 4 * 1024
REQUEST_READ_TIMEOUT_SECONDS = 5
IDENTITY_CACHE_SECONDS = 5 * 60
IDENTITY_FAILURE_CACHE_SECONDS = 30
IDENTITY_BATCH_SIZE = 100
IDENTITY_FETCH_TIMEOUT_SECONDS = 5
DASHBOARD_POLL_SECONDS = 15
DASHBOARD_SESSION_IDLE_SECONDS = 30 * 60
DASHBOARD_SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60
DASHBOARD_SESSION_COOKIE = "tg_pm_gatekeeper_session"
PAGE_SIZE = 50




@dataclass(frozen=True, slots=True)
class LiveIdentity:
    user_id: int
    name: str | None
    username: str | None


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
        self._csrf_token = secrets.token_urlsafe(32)
        self._access_token = secrets.token_urlsafe(32)
        self._capability_token = secrets.token_urlsafe(32)
        self._session_token: str | None = None
        self._session_started_at: float | None = None
        self._session_last_seen_at: float | None = None
        self.access_token_path = socket_path.with_suffix(".access-token")

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
        self._write_access_token()

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
                status, headers, response = 400, {}, self._page("Invalid Request")
            except Exception:
                LOG.error("review_request_failed")
                status, headers, response = 500, {}, self._page("Request Failed")
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
    ) -> tuple[int, dict[str, str], bytes]:
        parsed = urlsplit(target)
        if request_headers is None:
            return await self._dispatch_routes(method, target, body)
        host = request_headers.get("host", "")
        if not (host.startswith("127.0.0.1:") or host.startswith("localhost:")):
            return 400, {}, self._page("Invalid Host")
        if parsed.path == "/dashboard-error.css":
            return await self._dispatch_routes(method, target, body)
        if parsed.path == "/logged-out":
            if method != "GET":
                return 405, {"Allow": "GET"}, b""
            return 200, {}, self._page("Dashboard Signed Out")
        if parsed.path == "/login":
            token = parse_qs(parsed.query).get("token", [""])[0]
            if not secrets.compare_digest(token, self._access_token):
                return 400, {}, self._page("Invalid Access Token")
            self._access_token = secrets.token_urlsafe(32)
            self._capability_token = secrets.token_urlsafe(32)
            self._activate_session()
            self._on_authenticated_activity()
            self._write_access_token()
            return (
                303,
                {
                    "Location": f"/{self._capability_token}/",
                    "Set-Cookie": self._session_cookie_header(),
                },
                b"",
            )
        logical_path = self._logical_path(parsed.path)
        if logical_path is None or not self._has_valid_session(request_headers):
            return 404, {}, self._page("Dashboard Access Missing")
        if logical_path == "/logout":
            if method != "POST":
                return 405, {"Allow": "POST"}, b""
            try:
                values = parse_qs(body.decode("utf-8"), strict_parsing=True)
            except (UnicodeDecodeError, ValueError):
                return 400, {}, self._page("Invalid Action Token")
            token = values.get("token", [""])[0]
            if not secrets.compare_digest(token, self._csrf_token):
                return 400, {}, self._page("Invalid Action Token")
            expired_cookie = self._expired_session_cookie_header()
            self._invalidate_session()
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
            self._session_last_seen_at = time.monotonic()
            self._on_authenticated_activity()
        return status, self._capability_headers(headers), self._capability_html(
            response, headers
        )

    async def _dispatch_routes(
        self,
        method: str,
        target: str,
        body: bytes,
    ) -> tuple[int, dict[str, str], bytes]:
        parsed = urlsplit(target)
        path = parsed.path
        if path in {
            "/dashboard.js",
            "/dashboard-theme.js",
            "/dashboard.css",
            "/dashboard-error.css",
        }:
            if method != "GET":
                return 405, {"Allow": "GET"}, b""
            asset_name = path.removeprefix("/")
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
        if path == "/dashboard/status":
            if method != "GET":
                return 405, {"Allow": "GET"}, b""
            page_path = parse_qs(parsed.query).get("path", [""])[0]
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
        if path == "/" and method == "GET":
            return 200, {}, await self._dashboard_page()
        if path == "/review" and method == "GET":
            page = self._page_number(parsed.query)
            if page is None:
                return 404, {}, self._page("Not Found")
            try:
                return 200, {}, await self._review_queue_page(page=page)
            except DashboardBackendError:
                return 404, {}, self._page("Not Found")
        if path == "/cases/archive" and method == "GET":
            page = self._page_number(parsed.query)
            if page is None:
                return 404, {}, self._page("Not Found")
            values = parse_qs(parsed.query)
            reason = values.get("reason", [None])[0]
            older_text = values.get("older_days", [None])[0]
            older_days = int(older_text) if older_text in {"30", "90", "180", "365"} else None
            if older_text is not None and older_days is None:
                return 400, {}, self._page("Invalid Archive Filter")
            try:
                return 200, {}, await self._enforcement_index_page(
                    page=page, archived=True, reason=reason, older_days=older_days
                )
            except DashboardBackendError:
                return 404, {}, self._page("Not Found")
        if path == "/cases/archive/forget":
            return await self._dispatch_bulk_forget(method, parsed.query, body)
        if path.endswith("/archive") and path.startswith("/cases/"):
            sender_key = path.removeprefix("/cases/").removesuffix("/archive")
            return await self._dispatch_archive_confirmation(method, sender_key, body)
        if path.endswith("/forget") and path.startswith("/cases/"):
            sender_key = path.removeprefix("/cases/").removesuffix("/forget")
            return await self._dispatch_forget_confirmation(method, sender_key, body)
        if path == "/cases" and method == "GET":
            page = self._page_number(parsed.query)
            if page is None:
                return 404, {}, self._page("Not Found")
            try:
                return 200, {}, await self._enforcement_index_page(page=page)
            except DashboardBackendError:
                return 404, {}, self._page("Not Found")
        if path == "/cases/release":
            return await self._dispatch_legacy_release(method, body)
        if path.startswith("/cases/"):
            return await self._dispatch_enforcement(method, path, body)
        if not path.startswith("/review/"):
            return 404, {}, self._page("Not Found")
        try:
            review_id = int(path.removeprefix("/review/"))
        except ValueError:
            return 404, {}, self._page("Not Found")
        if method == "GET":
            try:
                return await self._show_review(review_id)
            except DashboardBackendError as exc:
                return self._backend_error(exc.code)
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, self._page("Method Not Allowed")
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        token = values.get("token", [""])[0]
        action = values.get("action", [""])[0]
        if not secrets.compare_digest(token, self._csrf_token):
            return 400, {}, self._page("Invalid Action Token")
        try:
            await self.backend.request(
                "reviews.decide", {"review_id": review_id, "action": action}
            )
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/review"}, b""

    def _backend_error(self, code: str) -> tuple[int, dict[str, str], bytes]:
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
        return status, {}, self._page(title)

    def _logical_path(self, path: str) -> str | None:
        parts = path.split("/", 2)
        candidate = parts[1] if len(parts) > 1 else ""
        if not secrets.compare_digest(candidate, self._capability_token):
            return None
        return "/" + parts[2] if len(parts) == 3 else "/"

    def _activate_session(self) -> None:
        now = time.monotonic()
        self._session_token = secrets.token_urlsafe(32)
        self._session_started_at = now
        self._session_last_seen_at = now

    def _invalidate_session(self) -> None:
        self._session_token = None
        self._session_started_at = None
        self._session_last_seen_at = None
        self._access_token = secrets.token_urlsafe(32)
        self._capability_token = secrets.token_urlsafe(32)
        self._write_access_token()

    def _has_valid_session(self, request_headers: dict[str, str]) -> bool:
        token = self._session_cookie_value(request_headers.get("cookie", ""))
        if (
            token is None
            or self._session_token is None
            or self._session_started_at is None
            or self._session_last_seen_at is None
            or not secrets.compare_digest(token, self._session_token)
        ):
            return False
        now = time.monotonic()
        if (
            now - self._session_last_seen_at >= DASHBOARD_SESSION_IDLE_SECONDS
            or now - self._session_started_at >= DASHBOARD_SESSION_ABSOLUTE_SECONDS
        ):
            return False
        return True

    @staticmethod
    def _session_cookie_value(raw_cookie: str) -> str | None:
        cookies = SimpleCookie()
        try:
            cookies.load(raw_cookie)
        except CookieError:
            return None
        morsel = cookies.get(DASHBOARD_SESSION_COOKIE)
        return morsel.value if morsel is not None else None

    def _session_cookie_header(self) -> str:
        return (
            f"{DASHBOARD_SESSION_COOKIE}={self._session_token}; "
            f"Path=/{self._capability_token}/; Max-Age={DASHBOARD_SESSION_ABSOLUTE_SECONDS}; "
            "HttpOnly; SameSite=Strict"
        )

    def _expired_session_cookie_header(self) -> str:
        return (
            f"{DASHBOARD_SESSION_COOKIE}=; Path=/{self._capability_token}/; "
            "Max-Age=0; HttpOnly; SameSite=Strict"
        )

    def _capability_headers(self, headers: dict[str, str]) -> dict[str, str]:
        location = headers.get("Location")
        if location is None or not location.startswith("/"):
            return headers
        return {**headers, "Location": f"/{self._capability_token}{location}"}

    def _capability_html(
        self, response: bytes, headers: dict[str, str]
    ) -> bytes:
        content_type = headers.get("Content-Type", "text/html")
        if not content_type.startswith("text/html"):
            return response
        prefix = f"/{self._capability_token}/".encode("ascii")
        for attribute in (b"href", b"action", b"src"):
            response = response.replace(attribute + b"='/", attribute + b"='" + prefix)
            response = response.replace(attribute + b'="/', attribute + b'="' + prefix)
        return response

    @staticmethod
    def _page_number(query: str) -> int | None:
        raw = parse_qs(query).get("page", ["1"])[0]
        if not raw.isascii() or not raw.isdecimal():
            return None
        page = int(raw)
        return page if 1 <= page <= 100_000 else None

    @staticmethod
    def _page_exists(page: int, total: int) -> bool:
        return page == 1 or (page - 1) * PAGE_SIZE < total

    async def _backend_page_version(self, target: str) -> str | None:
        result = await self.backend.request("page_version", {"target": target})
        version = result.get("version")
        return version if isinstance(version, str) else None

    def _write_access_token(self) -> None:
        temporary = self.access_token_path.with_suffix(".access-token.tmp")
        temporary.unlink(missing_ok=True)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as output:
                output.write(self._access_token)
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(self.access_token_path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _json_block(value: object) -> str:
        return html.escape(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))

    @staticmethod
    def _text_block(label: str, value: str, *, quote: bool = False) -> str:
        if not value:
            return ""
        css = "message quote" if quote else "message"
        return (
            f"<h3 class='field-label'>{html.escape(label)}</h3>"
            f"<pre class='{css}'>{html.escape(value)}</pre>"
        )

    @staticmethod
    def _badge(label: str, tone: str = "neutral") -> str:
        return f"<span class='badge badge-{tone}'>{html.escape(label)}</span>"

    @staticmethod
    def _case_tone(status: str, *, archived: bool = False) -> str:
        if archived:
            return "neutral"
        return {"quarantined": "hold", "suppressed": "block"}.get(status, "neutral")

    @staticmethod
    def _review_tone(classification: str) -> str:
        return "monitor" if classification.startswith("would_") else "hold"

    @staticmethod
    def _page_header(
        title: str,
        *,
        count: str | None = None,
        lede: str = "",
        meta: str = "",
        aside: str = "",
        back: tuple[str, str] | None = None,
    ) -> str:
        back_link = (
            f"<a class='back-link' href='{back[0]}'>← {html.escape(back[1])}</a>"
            if back is not None
            else ""
        )
        count_html = (
            f" <span class='title-count'>{html.escape(count)}</span>" if count else ""
        )
        lede_html = f"<p class='lede'>{lede}</p>" if lede else ""
        return (
            "<div class='page-header'><div class='page-heading'>"
            f"{back_link}<h1>{html.escape(title)}{count_html}</h1>{meta}{lede_html}</div>"
            + (f"<div class='page-header-aside'>{aside}</div>" if aside else "")
            + "</div>"
        )

    @staticmethod
    def _key_values(rows: list[tuple[str, str]]) -> str:
        return (
            "<dl class='kv'>"
            + "".join(f"<div><dt>{label}</dt><dd>{value}</dd></div>" for label, value in rows)
            + "</dl>"
        )

    @staticmethod
    def _joined(value: object) -> str:
        if not isinstance(value, list) or not value:
            return "—"
        return ", ".join(str(item) for item in value)

    @classmethod
    def _signal_summary(cls, value: object) -> str:
        if not isinstance(value, list) or not value:
            return "—"
        labels: list[str] = []
        for item in value:
            code = item.get("code") if isinstance(item, dict) else item
            if code:
                labels.append(cls._human_label(str(code)))
        if not labels:
            return "—"
        remaining = len(labels) - 1
        return labels[0] + (f" · +{remaining} more" if remaining else "")

    @classmethod
    def _signal_breakdown(cls, value: object) -> str:
        if not isinstance(value, list) or not value:
            return "<span class='empty-value'>—</span>"
        items: list[str] = []
        for item in value:
            code = item.get("code") if isinstance(item, dict) else item
            if not code:
                continue
            title = html.escape(cls._human_label(str(code)))
            source = item.get("source") if isinstance(item, dict) else None
            weight = item.get("weight") if isinstance(item, dict) else None
            explanation = item.get("explanation") if isinstance(item, dict) else None
            source_badge = (
                "<span class='signal-source'>"
                f"{html.escape(cls._human_label(str(source)))}"
                "</span>"
                if source
                else ""
            )
            score_badge = (
                f"<span class='signal-score'>+{weight:g}</span>"
                if isinstance(weight, (int, float))
                else ""
            )
            explanation_copy = (
                f"<p class='signal-explanation'>{html.escape(str(explanation))}</p>"
                if explanation
                else ""
            )
            items.append(
                "<li class='signal-item'>"
                "<div class='signal-copy'>"
                f"<div class='signal-heading'><strong>{title}</strong>{score_badge}</div>"
                f"{source_badge}{explanation_copy}"
                "</div></li>"
            )
        if not items:
            return "<span class='empty-value'>—</span>"
        return (
            "<ol class='signal-list' aria-label='Evidence signals'>"
            + "".join(items)
            + "</ol>"
        )

    @classmethod
    def _policy_decision_panel(
        cls, payload: dict[str, object], *, note: str | None = None
    ) -> str:
        raw_score = payload.get("risk_score")
        if isinstance(raw_score, bool):
            risk_score = None
        else:
            try:
                risk_score = int(raw_score)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                risk_score = None
        if risk_score is None:
            return ""

        raw_signals = payload.get("signals", [])
        policy_signals = tuple(
            EvidenceSignal(
                str(item["code"]),
                str(item.get("source", "behavior")),  # type: ignore[arg-type]
                int(item.get("weight", 0)),
                str(item.get("explanation", "")),
            )
            for item in raw_signals
            if isinstance(item, dict) and item.get("code")
        ) if isinstance(raw_signals, list) else ()
        gate_basis = PolicyEngine.destructive_gate_basis(policy_signals)
        score_gate_met = risk_score >= PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD
        destructive_gate_met = gate_basis is not None
        planned_action = str(payload.get("planned_action", "not_recorded"))
        action_label = cls._human_label(planned_action)
        action_class = {
            "standard_challenge": "standard",
            "strict_challenge": "strict",
            "permanent_suppression": "permanent",
        }.get(planned_action, "unknown")
        plotted_score = min(max(risk_score, 0), 100)
        policy_version = html.escape(str(payload.get("policy_version", "adaptive-v1")))

        if gate_basis == "owner_denied_domain":
            gate_label = "Met · Non-quoted owner-denied domain"
        elif gate_basis == "corroborated_repeated_campaign":
            gate_label = "Met · Corroborated cross-sender campaign"
        else:
            gate_label = (
                "Not met · No non-quoted denylist match or corroborated "
                "cross-sender campaign"
            )

        if planned_action == "permanent_suppression":
            outcome_copy = (
                "Both permanent-suppression conditions were met, so no challenge was sent."
            )
        elif score_gate_met and not destructive_gate_met:
            outcome_copy = (
                "The score reached 70, but permanent suppression also requires destructive "
                f"evidence. The recorded decision was {action_label.lower()}."
            )
        elif planned_action == "strict_challenge":
            outcome_copy = (
                "The score reached the strict threshold but not both permanent-suppression "
                "conditions."
            )
        else:
            outcome_copy = "The score remained below the strict-challenge threshold."

        score_state = "met" if score_gate_met else "unmet"
        gate_state = "met" if destructive_gate_met else "unmet"
        score_symbol = "✓" if score_gate_met else "×"
        gate_symbol = "✓" if destructive_gate_met else "×"
        return f"""
        <section class="rail-card policy-map" aria-label="Policy decision explanation">
          <div class="policy-outcome {action_class}">
            <small>Final Policy Decision</small><strong>{html.escape(action_label)}</strong>
            <p>{html.escape(outcome_copy)}</p>
          </div>
          <div class="policy-score-head">
            <div><span class="policy-kicker">Risk Score</span>
              <strong>{risk_score}</strong><small>Additive points · not a probability</small></div>
            <span class="policy-version">{policy_version}</span>
          </div>
          <div class="risk-track" role="img" aria-label="Risk score {risk_score}; strict challenge starts at {PolicyEngine.STRICT_CHALLENGE_THRESHOLD} and permanent score condition starts at {PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD}">
            <meter class="risk-meter" min="0" max="100" value="{plotted_score}">{plotted_score}%</meter>
            <span class="risk-mark strict-mark"><i>{PolicyEngine.STRICT_CHALLENGE_THRESHOLD}</i><b>Strict</b></span>
            <span class="risk-mark permanent-mark"><i>{PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD}</i><b>Permanent Score</b></span>
          </div>
          <p class="gate-formula">Permanent suppression requires <strong>both</strong> conditions:</p>
          <div class="gate-check {score_state}">
            <span class="gate-symbol" aria-hidden="true">{score_symbol}</span>
            <div><small>1 · Score Condition</small>
              <strong>{risk_score} ≥ {PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD}</strong>
              <p>Risk score reaches the permanent-suppression score threshold.</p></div>
          </div>
          <div class="gate-check {gate_state}">
            <span class="gate-symbol" aria-hidden="true">{gate_symbol}</span>
            <div><small>2 · Destructive Evidence</small>
              <strong>{html.escape(gate_label)}</strong>
              <p>Requires a non-quoted denied domain, or a corroborated repeated campaign.</p></div>
          </div>
          {f'<p class="policy-note">{html.escape(note)}</p>' if note else ''}
        </section>"""

    @classmethod
    def _recomputed_policy_panel(cls, recorded_signals: object) -> str:
        """Rebuild the policy view for a review, which records signals but not a score."""
        if not isinstance(recorded_signals, list) or not recorded_signals:
            return ""
        signals: list[EvidenceSignal] = []
        for item in recorded_signals:
            if not isinstance(item, dict):
                return ""
            code, source, weight = item.get("code"), item.get("source"), item.get("weight")
            # Legacy HR-rule rows carry bare codes without weights; they cannot be scored.
            if (
                not isinstance(code, str)
                or not isinstance(source, str)
                or isinstance(weight, bool)
                or not isinstance(weight, int)
            ):
                return ""
            signals.append(EvidenceSignal(code, source, weight, ""))  # type: ignore[arg-type]
        decision = PolicyEngine().decide(tuple(signals))
        return cls._policy_decision_panel(
            {
                "risk_score": decision.risk_score,
                "signals": recorded_signals,
                "planned_action": decision.planned_action,
                "policy_version": decision.policy_version,
            },
            note=(
                "Recomputed from the recorded signal weights with the current policy. "
                "Reviews do not store their original score."
            ),
        )

    def _review_sections(self, payload: dict[str, object]) -> tuple[str, str, str]:
        text = str(payload.get("text", ""))
        quote_text = str(payload.get("quote_text", ""))
        preview_text = str(payload.get("preview_text", ""))
        structural_only = not (
            text.strip() or quote_text.strip() or preview_text.strip()
        )
        button_texts = self._joined(payload.get("button_texts", []))
        domains = self._joined(payload.get("domains", []))
        quote_domains = self._joined(payload.get("quote_domains", []))
        details = self._json_block(payload)
        urls = self._json_block(payload.get("urls", []))
        quote_urls = self._json_block(payload.get("quote_urls", []))
        url_shape = self._json_block(payload.get("url_shape", {}))
        quote_url_shape = self._json_block(payload.get("quote_url_shape", {}))
        sections = (
            self._text_block("Message Text or Caption", text)
            + self._text_block("Quoted Context", quote_text, quote=True)
            + self._text_block("Telegram Webpage Preview", preview_text, quote=True)
        )
        if structural_only:
            sections += (
                "<div class='notice'><strong>Limited Textual Evidence</strong> "
                "No message text, quoted text, or webpage-preview text was retained. "
                "Review any available URLs, button text, evidence signals, and structural "
                "metadata before deciding whether to allow the sender or leave the "
                "restriction unchanged.</div>"
            )

        def value(text: str) -> str:
            if text == "—":
                return "<span class='empty-value'>—</span>"
            return f"<span class='mono'>{html.escape(text)}</span>"

        link_facts = self._key_values(
            [
                ("Button Text", value(button_texts)),
                ("Normalized Domains", value(domains)),
                ("Quoted-Context Domains", value(quote_domains)),
            ]
        )
        technical = (
            f"<details><summary>Full URLs</summary><pre>{urls}</pre></details>"
            + f"<details><summary>Quoted-Context URLs</summary><pre>{quote_urls}</pre></details>"
            + f"<details><summary>Link Shape</summary><pre>{url_shape}</pre></details>"
            + f"<details><summary>Quoted-Context Link Shape</summary><pre>{quote_url_shape}</pre></details>"
            + f"<details><summary>Full Decrypted Case Payload</summary><pre>{details}</pre></details>"
        )
        return sections, link_facts, technical

    async def _dispatch_enforcement(
        self, method: str, path: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        sender_key = path.rsplit("/", 1)[-1]
        if len(sender_key) != 64 or any(char not in "0123456789abcdef" for char in sender_key):
            return 404, {}, self._page("Active Case Not Found")
        if method == "GET":
            try:
                return await self._show_enforcement(sender_key)
            except DashboardBackendError as exc:
                return self._backend_error(exc.code)
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, self._page("Method Not Allowed")
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        if not secrets.compare_digest(values.get("token", [""])[0], self._csrf_token):
            return 400, {}, self._page("Invalid Action Token")
        action = values.get("action", [""])[0]
        try:
            await self.backend.request(
                "cases.decide", {"sender_key": sender_key, "action": action}
            )
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/cases"}, b""

    async def _dispatch_legacy_release(
        self, method: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        if method != "POST":
            return 405, {"Allow": "POST"}, self._page("Method Not Allowed")
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        if not secrets.compare_digest(values.get("token", [""])[0], self._csrf_token):
            return 400, {}, self._page("Invalid Action Token")
        user_id_text = values.get("user_id", [""])[0]
        if not user_id_text.isascii() or not user_id_text.isdecimal():
            return 400, {}, self._page("Invalid Telegram User ID")
        user_id = int(user_id_text)
        if user_id <= 0 or user_id > (2**63 - 1):
            return 400, {}, self._page("Invalid Telegram User ID")
        try:
            await self.backend.request("cases.release_legacy", {"user_id": user_id})
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/cases"}, b""

    async def _dispatch_forget_confirmation(
        self, method: str, sender_key: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        if len(sender_key) != 64 or any(
            char not in "0123456789abcdef" for char in sender_key
        ):
            return 404, {}, self._page("Archived Restriction Not Found")
        if method == "GET":
            try:
                item = await self.backend.request(
                    "cases.detail", {"sender_key": sender_key}
                )
            except DashboardBackendError as exc:
                return self._backend_error(exc.code)
            if item.get("archived_at") is None or item.get("suppressed_until") is not None:
                return self._backend_error("case_not_archived")
            return 200, {}, self._confirmation_page(
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
            return 405, {"Allow": "GET, POST"}, self._page("Method Not Allowed")
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        if not secrets.compare_digest(values.get("token", [""])[0], self._csrf_token):
            return 400, {}, self._page("Invalid Action Token")
        try:
            await self.backend.request(
                "cases.decide", {"sender_key": sender_key, "action": "forget"}
            )
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/cases/archive"}, b""

    async def _dispatch_archive_confirmation(
        self, method: str, sender_key: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        if len(sender_key) != 64 or any(
            char not in "0123456789abcdef" for char in sender_key
        ):
            return 404, {}, self._page("Active Case Not Found")
        if method == "GET":
            try:
                item = await self.backend.request(
                    "cases.detail", {"sender_key": sender_key}
                )
            except DashboardBackendError as exc:
                return self._backend_error(exc.code)
            if (
                item.get("status") != "suppressed"
                or item.get("suppressed_until") is not None
                or item.get("archived_at") is not None
            ):
                return self._backend_error("case_not_found")
            return 200, {}, self._confirmation_page(
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
            return 405, {"Allow": "GET, POST"}, self._page("Method Not Allowed")
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        if not secrets.compare_digest(values.get("token", [""])[0], self._csrf_token):
            return 400, {}, self._page("Invalid Action Token")
        try:
            await self.backend.request(
                "cases.decide", {"sender_key": sender_key, "action": "keep"}
            )
        except DashboardBackendError as exc:
            return self._backend_error(exc.code)
        return 303, {"Location": "/cases/archive"}, b""

    async def _dispatch_bulk_forget(
        self, method: str, query: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        source = parse_qs(query if method == "GET" else body.decode("utf-8"))
        raw_days = source.get("days", [""])[0]
        if raw_days not in {"30", "90", "180", "365"}:
            return 400, {}, self._page("Invalid Retention Age")
        days = int(raw_days)
        if method == "GET":
            result = await self.backend.request(
                "cases.forget_preview", {"days": days}
            )
            count = int(result["count"])
            return 200, {}, self._confirmation_page(
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
            return 405, {"Allow": "GET, POST"}, self._page("Method Not Allowed")
        if not secrets.compare_digest(source.get("token", [""])[0], self._csrf_token):
            return 400, {}, self._page("Invalid Action Token")
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
        total = int(result["total"])
        items = [SimpleNamespace(**value) for value in result["items"]]
        stats = result["stats"]
        def sender_cell(item: SimpleNamespace) -> str:
            if archived:
                return (
                    f"<a class='identity-link row-link' href='/cases/{item.sender_key}'>"
                    "Archived Sender</a>"
                )
            return self._identity_cell(
                self._identity_from_value(item.identity),
                href=f"/cases/{item.sender_key}",
            )

        def row(item: SimpleNamespace) -> str:
            tone = self._case_tone(item.status, archived=archived)
            evidence = (
                "<span class='availability'>Ready</span>"
                if item.has_evidence
                else "<span class='availability availability-unavailable'>Unavailable</span>"
            )
            age = self._relative_age(item.archived_at if archived else item.updated_at)
            return (
                f"<tr class='tone-{tone}'>"
                f"<td data-label='Sender'>{sender_cell(item)}</td>"
                f"<td data-label='State'>{self._badge(self._human_label(item.status), tone)}"
                f"<span class='cell-note'>{html.escape(self._restriction_summary(item))}</span></td>"
                f"<td data-label='Trigger'>{html.escape(self._list_reason_label(item.reason))}</td>"
                f"<td data-label='Evidence'>{evidence}</td>"
                f"<td data-label='Age' class='age'>{html.escape(age)}</td>"
                "</tr>"
            )

        rows = "".join(row(item) for item in items) or (
            "<tr class='empty-row'><td colspan='5'>"
            f"No {'archived' if archived else 'active'} restrictions.</td></tr>"
        )
        reason_counts = sorted(
            (key.removeprefix("reason:"), value)
            for key, value in stats.items()
            if key.startswith("reason:")
        )
        reasons = " · ".join(
            f"{html.escape(self._reason_label(reason))} {count}"
            for reason, count in reason_counts
        ) or "No active reasons"
        snapshot_note = (
            f"{stats['unreviewable']} restriction"
            f"{'s' if stats['unreviewable'] != 1 else ''} "
            f"{'have' if stats['unreviewable'] != 1 else 'has'} no reviewable evidence; "
            "the restriction remains visible and manageable."
            if stats["unreviewable"]
            else "Every active restriction currently has reviewable evidence."
        )
        identity_note = (
            f" {stats['unidentified']} restriction"
            f"{'s' if stats['unidentified'] != 1 else ''} without a control identity require"
            f"{'s' if stats['unidentified'] == 1 else ''} manual ID recovery."
            if stats["unidentified"]
            else " Every active restriction has a retained encrypted control identity."
        )
        recovery = ""
        if stats["unidentified"]:
            recovery = (
                "<details class='advanced-recovery'><summary>Advanced Recovery"
                f" <span class='summary-note'>{stats['unidentified']} unidentified</span></summary>"
                "<div class='advanced-recovery-content'>"
                "<h2>Allow an Unidentified Restricted Sender by Telegram User ID</h2>"
                "<p>Use this only for a restriction without an encrypted control identity, such as "
                "one created before control identities were retained or when Gatekeeper could "
                "not keep a Telegram reference. This removes the Gatekeeper restriction and cancels "
                "pending deletion jobs, but cannot restore saved Telegram folder or notification "
                "state without a peer reference. The entered ID is used only to derive the "
                "existing sender key and is not stored.</p>"
                "<form class='manual-release' method='post' action='/cases/release'>"
                f"<input type='hidden' name='token' value='{self._csrf_token}'>"
                "<label for='release-user-id'>Telegram User ID</label>"
                "<input id='release-user-id' name='user_id' type='text' inputmode='numeric' "
                "pattern='[0-9]+' autocomplete='off' required>"
                "<button class='btn btn-block' type='submit'>Allow Without Restore</button>"
                "</form></div></details>"
            )
        base = "/cases/archive" if archived else "/cases"
        filter_values: dict[str, object] = {}
        if reason:
            filter_values["reason"] = reason
        if older_days:
            filter_values["older_days"] = older_days
        filtered_base = base + (f"?{urlencode(filter_values)}" if filter_values else "")
        archive_tools = ""
        if archived:

            def filter_link(label: str, values: dict[str, object], current: bool) -> str:
                query = f"?{urlencode(values)}" if values else ""
                marker = " aria-current='true'" if current else ""
                return f"<a href='/cases/archive{query}'{marker}>{html.escape(label)}</a>"

            age_filter = {"older_days": older_days} if older_days else {}
            reason_filter = {"reason": reason} if reason else {}
            reason_links = filter_link("All", age_filter, reason is None) + "".join(
                filter_link(
                    self._reason_label(item_reason),
                    {"reason": item_reason, **age_filter},
                    reason == item_reason,
                )
                for item_reason, _ in reason_counts
            )
            age_links = filter_link("Any age", reason_filter, older_days is None) + "".join(
                filter_link(f"{days} days", {**reason_filter, "older_days": days}, older_days == days)
                for days in (30, 90, 180, 365)
            )
            forget_links = "".join(
                f"<a href='/cases/archive/forget?days={days}'>{days} days</a>"
                for days in (30, 90, 180, 365)
            )
            # One label column keeps both filters and the cleanup action aligned.
            archive_tools = (
                "<section class='archive-tools' aria-label='Archive filters and cleanup'>"
                "<span class='filter-label'>Reason</span>"
                f"<nav class='segmented' aria-label='Filter by reason'>{reason_links}</nav>"
                "<span class='filter-label'>Minimum archive age</span>"
                f"<nav class='segmented' aria-label='Minimum archive age'>{age_links}</nav>"
                "<hr class='tools-divider'>"
                "<span class='filter-label'>Preview release and forget</span>"
                "<nav class='segmented segmented-danger' aria-label='Preview release and forget'>"
                f"{forget_links}</nav></section>"
            )
        if archived:
            lede = (
                "Permanent restrictions you chose to keep. They remain enforced by local "
                "policy; review them or forget them here."
            )
        else:
            lede = (
                "Review every current restriction. Evidence availability is tracked "
                "separately; Telegram block is never used."
            )
        stat_strip = (
            "<div class='stat-block'><p class='stat-caption'>All enforced restrictions, "
            "including archived</p><dl class='stat-strip'>"
            f"<div><dt>Quarantined</dt><dd class='data-value'>{stats['quarantined']}</dd></div>"
            f"<div><dt>Suppressed</dt><dd class='data-value'>{stats['suppressed']}</dd></div>"
            f"<div><dt>Reviewable Evidence</dt><dd class='data-value'>{stats['reviewable']}</dd></div>"
            "</dl></div>"
        )
        live_region = "archived-restrictions" if archived else "active-cases"
        content = (
            self._masthead("archive" if archived else "cases", csrf_token=self._csrf_token)
            + "<main class='page'>"
            + f"<div class='live-region' data-live-region='{live_region}'>"
            + self._page_header(
                "Archived Restrictions" if archived else "Needs Attention",
                count=str(total),
                lede=lede,
                aside=stat_strip,
            )
            + "<details class='context-note'><summary>Restriction Context</summary>"
            + f"<p><strong>State reasons:</strong> {reasons}. {snapshot_note}{identity_note}</p></details>"
            + archive_tools
            + "<div class='table-shell'><table class='data-table cases-table'><thead><tr><th>Sender</th><th>State</th><th>Trigger</th><th>Evidence</th><th>Age</th></tr></thead>"
            + f"<tbody>{rows}</tbody></table></div>"
            + self._pagination(filtered_base, page, total)
            + "</div>"
            + "<section class='advanced-recovery-wrap' data-live-region='legacy-recovery'>"
            + recovery
            + "</section></main>"
        )
        return self._page(
            content,
            raw=True,
            page_title="Archived Restrictions" if archived else "Active Cases",
            live_refresh="replace",
            page_version=await self._backend_page_version(
                filtered_base if page == 1 else (
                    f"{filtered_base}{'&' if '?' in filtered_base else '?'}page={page}"
                )
            ),
        )

    async def _show_enforcement(
        self, item: Any | str
    ) -> tuple[int, dict[str, str], bytes]:
        sender_key = item if isinstance(item, str) else item.sender_key
        result = await self.backend.request(
            "cases.detail", {"sender_key": sender_key}
        )
        item = SimpleNamespace(**result)
        payload = result.get("payload")
        if not isinstance(payload, dict):
            payload = {}
        evidence_available = result.get("evidence_available") is True
        unavailable_note = {
            "authentication_failed": (
                "Encrypted evidence failed authentication and was not shown."
            ),
            "missing": "No message evidence is retained.",
        }.get(
            str(result.get("evidence_unavailable_reason")),
            "Encrypted evidence cannot be opened by this runtime.",
        )
        identity_value = self._identity_from_value(result.get("identity"))
        identity = "Identity Unavailable"
        user_id: int | None = None
        if identity_value is not None:
            user_id = identity_value.user_id
            identity = identity_value.name or "Name Unavailable"
            if identity_value.username:
                identity += f" (@{identity_value.username})"
        signal_breakdown = self._signal_breakdown(payload.get("signals", []))
        policy_panel = self._policy_decision_panel(payload)
        features = json.dumps(payload.get("features", {}), indent=2, sort_keys=True)
        observed_at = item.evidence_created_at or item.updated_at
        observed = datetime.fromtimestamp(observed_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        evidence_expiry = (
            datetime.fromtimestamp(item.evidence_expires_at, timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
            if item.evidence_expires_at is not None
            else "Expired or unavailable"
        )
        if evidence_available:
            message_html, link_facts, technical = self._review_sections(payload)
            evidence_heading = "Decrypted Local Evidence"
            evidence_note = "Encrypted at rest; decrypted only for this owner-only view."
            evidence_panels = (
                "<section class='panel'><h2 class='panel-title'>Links and Buttons</h2>"
                f"{link_facts}</section>"
            )
        else:
            message_html = (
                "<div class='empty-state'><strong>Evidence expired or unavailable.</strong> "
                "The encrypted control identity is retained only so this restriction remains "
                "visible and reversible.</div>"
            )
            technical = ""
            evidence_heading = "Restriction Control"
            evidence_note = (
                unavailable_note + " Only the encrypted control identity remains available."
            )
            evidence_panels = ""
        allow_action = (
            self._action_form(
                item.sender_key, "allow", "Allow Sender", base="cases", tone="allow"
            )
            if user_id is not None
            else "<button class='btn' type='button' disabled>Allow Unavailable</button>"
        )
        if result.get("has_dialog_snapshot") is True:
            allow_guidance = (
                "Allow restores the saved folder and notification state before changing policy."
            )
        else:
            allow_guidance = (
                "No saved dialog state is available. Allow moves the conversation to the main "
                "folder and enables notifications before changing policy."
            )
        archived = item.archived_at is not None
        if archived:
            secondary_action = self._action_form(
                item.sender_key, "unarchive", "Move to Needs Attention", base="cases"
            )
            if not item.has_open_actions:
                secondary_action += (
                    f"<a class='btn btn-block-outline' href='/cases/{item.sender_key}/forget'>"
                    "Release and Forget…</a>"
                )
        elif item.status == "suppressed" and item.suppressed_until is None:
            secondary_action = (
                f"<a class='btn' href='/cases/{item.sender_key}/archive'>"
                "Keep and Archive…</a>"
            )
        else:
            secondary_action = ""
        back = (
            ("/cases/archive", "Archived Restrictions")
            if archived
            else ("/cases", "Needs Attention")
        )
        status_label = self._human_label(item.status)
        tone = self._case_tone(item.status, archived=archived)
        meta = self._identity_meta(user_id)
        technical_panel = (
            "<section class='panel panel-quiet'><h2 class='panel-title'>Technical Details</h2>"
            f"{technical}"
            f"<details><summary>Structural Features</summary><pre>{html.escape(features)}</pre></details>"
            "</section>"
        )
        facts = self._key_values(
            [
                ("Restriction Cause", html.escape(self._human_label(item.reason))),
                ("Triggered", observed),
                ("Restriction", html.escape(self._remaining(item))),
                ("Evidence Expires", evidence_expiry),
            ]
        )
        content = (
            self._masthead("archive" if archived else "cases", csrf_token=self._csrf_token)
            + "<main class='page detail-page'>"
            + self._page_header(
                identity,
                meta=meta,
                back=back,
                aside=self._badge(
                    "Archived · " + status_label if archived else status_label, tone
                ),
            )
            + f"""
        <div class="detail-grid">
          <div class="evidence-column">
            <section class="panel">
              <div class="panel-head"><h2 class="panel-title">{evidence_heading}</h2>
                <p class="panel-note">{evidence_note}</p></div>
              {message_html}
            </section>
            {evidence_panels}
            <section class="panel"><h2 class="panel-title">Evidence Signals</h2>
              <div class="signal-breakdown">{signal_breakdown}</div></section>
            {technical_panel}
          </div>
          <aside class="decision-rail" aria-label="Decision">
            {self._change_notice()}
            <section class="rail-card decision-card"><h2 class="rail-title">Operator Action</h2>
              <p class="rail-help">{html.escape(allow_guidance)}</p>
              <div class="action-stack">{allow_action}{secondary_action}</div></section>
            {policy_panel}
            <section class="rail-card"><h2 class="rail-title">Restriction Details</h2>{facts}</section>
          </aside>
        </div></main>"""
        )
        return 200, {}, self._page(
            content,
            raw=True,
            page_title=f"Active Case · {status_label}",
            live_refresh="notice",
            page_version=await self._backend_page_version(f"/cases/{item.sender_key}"),
        )

    @staticmethod
    def _identity_meta(user_id: int | None, *, review_id: int | None = None) -> str:
        parts: list[str] = []
        if user_id is not None:
            parts.append(f"<span class='identity-id'>ID {user_id}</span>")
        if review_id is not None:
            parts.append(f"<span class='identity-id'>Review #{review_id}</span>")
        if user_id is not None:
            parts.append(
                f"<a class='telegram-link' href='tg://user?id={user_id}'>"
                "Open This Conversation in Telegram ↗</a>"
            )
        return f"<p class='page-meta'>{''.join(parts)}</p>" if parts else ""

    async def _show_review(
        self, item: Any | int
    ) -> tuple[int, dict[str, str], bytes]:
        review_id = item if isinstance(item, int) else item.id
        result = await self.backend.request(
            "reviews.detail", {"review_id": review_id}
        )
        item = SimpleNamespace(**result)
        identity_value = self._identity_from_value(result.get("identity"))
        identity = "Identity Unavailable"
        user_id: int | None = None
        if identity_value is not None:
            user_id = identity_value.user_id
            identity = identity_value.name or "Name Unavailable"
            if identity_value.username:
                identity += f" (@{identity_value.username})"
        recorded_signals = json.loads(item.signals)
        signals = self._signal_breakdown(recorded_signals)
        policy_panel = self._recomputed_policy_panel(recorded_signals)
        review_reason = self._human_label(item.classification)
        tone = self._review_tone(item.classification)
        features = json.dumps(json.loads(item.features), indent=2, sort_keys=True)
        observed_at = datetime.fromtimestamp(item.updated_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        text = result.get("message")
        facts_rows: list[tuple[str, str]] = []
        if text is not None and user_id is not None:
            facts_rows.append(("Telegram ID", f"<span class='mono'>{user_id}</span>"))
        facts_rows += [
            ("Messages Observed", str(item.message_count)),
            ("Last Observed", observed_at),
        ]
        facts = self._key_values(facts_rows)
        if text is None:
            message_panel = (
                "<section class='panel'><div class='panel-head'>"
                "<h2 class='panel-title'>Telegram Message Unavailable</h2></div>"
                "<div class='empty-state'><strong>The referenced message no longer exists.</strong>"
                "<p>The conversation may have been deleted in Telegram. This pending row is local "
                "review state and is not removed automatically.</p></div></section>"
            )
            decision = (
                "<section class='rail-card decision-card'>"
                "<h2 class='rail-title'>Dismiss Pending Reviews</h2>"
                "<p class='rail-help'>Remove this sender's pending review and cancel pending "
                "Gatekeeper deletion jobs. Telegram and trust state are unchanged.</p>"
                "<div class='action-stack'>"
                + self._action_form(item.id, "dismiss", "Dismiss & Cancel Jobs")
                + "</div></section>"
            )
            technical = ""
        else:
            message_panel = (
                "<section class='panel'><div class='panel-head'>"
                "<h2 class='panel-title'>Message</h2>"
                "<p class='panel-note'>Fetched from Telegram · Not Stored Locally</p></div>"
                f"<pre class='message'>{html.escape(str(text))}</pre></section>"
            )
            decision = (
                "<section class='rail-card decision-card'>"
                "<h2 class='rail-title'>Sender Decision</h2>"
                "<p class='rail-help'>This decision applies to all pending entries for this "
                "sender.</p><div class='action-stack'>"
                + self._action_form(item.id, "legitimate", "Allow Sender", tone="allow")
                + self._action_form(item.id, "spam", "Suppress and Delete", tone="block")
                + self._action_form(item.id, "dismiss", "Dismiss & Cancel Jobs")
                + "</div></section>"
            )
            technical = (
                "<section class='panel panel-quiet'><h2 class='panel-title'>Technical Details</h2>"
                f"<details><summary>Structural Features</summary><pre>{html.escape(features)}</pre>"
                "</details></section>"
            )
        content = (
            self._masthead("reviews", csrf_token=self._csrf_token)
            + "<main class='page detail-page'>"
            + self._page_header(
                identity,
                meta=self._identity_meta(
                    user_id if text is not None else None, review_id=item.id
                ),
                back=("/review", "Pending Reviews"),
                aside=self._badge(review_reason, tone),
            )
            + "<div class='detail-grid'><div class='evidence-column'>"
            + message_panel
            + "<section class='panel'><h2 class='panel-title'>Evidence Signals</h2>"
            + f"<div class='signal-breakdown'>{signals}</div></section>"
            + technical
            + "</div><aside class='decision-rail' aria-label='Decision'>"
            + self._change_notice()
            + decision
            + policy_panel
            + "<section class='rail-card'><h2 class='rail-title'>Review Details</h2>"
            + facts
            + "</section></aside></div></main>"
        )
        return 200, {}, self._page(
            content,
            raw=True,
            page_title=f"Review #{item.id}",
            live_refresh="notice",
            page_version=await self._backend_page_version(f"/review/{item.id}"),
        )

    async def _dashboard_page(self) -> bytes:
        result = await self.backend.request("overview", {})
        pending_reviews = int(result["pending_reviews"])
        active_stats = result["active_stats"]
        active_restrictions = active_stats["quarantined"] + active_stats["suppressed"]
        storage_stats = result.get("storage_stats")
        if not isinstance(storage_stats, dict):
            storage_stats = {
                "attention_cases": active_restrictions,
                "archived_restrictions": 0,
                "database_page_count": 0,
                "database_page_size": 0,
                "database_logical_bytes": 0,
                "database_freelist_count": 0,
                "database_freelist_percent": 0,
                "temporary_released": 0,
                "auto_forgotten": 0,
                "auto_forget_skipped": 0,
            }
        mode = str(result["mode"])

        def queue_card(href: str, title: str, note: str, count: int, tone: str) -> str:
            state = f"tone-{tone}" if count else "is-empty"
            return (
                f"<a class='queue-card {state}' href='{href}'>"
                f"<span class='queue-count'>{count}</span>"
                f"<strong>{title}</strong><span class='queue-note'>{note}</span></a>"
            )

        content = (
            self._masthead("overview", csrf_token=self._csrf_token)
            + "<main class='page'><div class='live-region' data-live-region='operations'>"
            + self._page_header(
                "Operations Dashboard",
                lede="Review restrictions, recover false positives, and resolve pending decisions.",
                aside=self._badge(
                    f"{mode.title()} Mode", "monitor" if mode == "monitor" else "allow"
                ),
            )
            + "<nav class='queue-grid' aria-label='Review areas'>"
            + queue_card(
                "/review", "Pending Reviews",
                "Resolve simulations and exception reviews.", pending_reviews, "monitor",
            )
            + queue_card(
                "/cases", "Active Cases · Needs Attention",
                "Review unresolved restrictions and failures.",
                int(storage_stats["attention_cases"]), "hold",
            )
            + queue_card(
                "/cases/archive", "Archived Restrictions",
                "Review or forget confirmed permanent restrictions.",
                int(storage_stats["archived_restrictions"]), "neutral",
            )
            + "</nav><dl class='stat-strip stat-strip-wide'>"
            f"<div><dt>Active Restrictions</dt><dd class='data-value'>{active_restrictions}</dd></div>"
            f"<div><dt>Reviewable Cases</dt><dd class='data-value'>{active_stats['reviewable']}</dd></div>"
            "</dl>"
            + self._policy_thresholds()
            + "<details class='context-note'><summary>Storage and Maintenance</summary>"
            f"<p>Needs attention: {storage_stats['attention_cases']} · "
            f"Archived: {storage_stats['archived_restrictions']} · "
            f"Database: {storage_stats['database_logical_bytes']} bytes "
            f"({storage_stats['database_page_count']} pages × "
            f"{storage_stats['database_page_size']} bytes) · "
            f"Free pages: {storage_stats['database_freelist_count']} "
            f"({storage_stats['database_freelist_percent']}%).</p>"
            f"<p>Last maintenance: released {storage_stats['temporary_released']} temporary restrictions, "
            f"forgot {storage_stats['auto_forgotten']} archived restrictions, "
            f"skipped {storage_stats['auto_forget_skipped']} with unfinished work.</p>"
            "</details></div></main>"
        )
        return self._page(
            content,
            raw=True,
            page_title="Operations Dashboard",
            live_refresh="replace",
            page_version=await self._backend_page_version("/"),
        )

    @staticmethod
    def _policy_thresholds() -> str:
        strict = PolicyEngine.STRICT_CHALLENGE_THRESHOLD
        permanent = PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD
        version = html.escape(PolicyEngine().decide(()).policy_version)
        return (
            "<section class='policy-thresholds' aria-label='Scoring policy thresholds'>"
            f"<h2>Scoring Policy <span class='policy-version'>{version}</span></h2>"
            "<ol class='threshold-scale'>"
            f"<li class='tone-allow'><b>0–{strict - 1}</b><span>Standard Challenge</span></li>"
            f"<li class='tone-hold'><b>{strict}+</b><span>Strict Challenge</span></li>"
            f"<li class='tone-block'><b>{permanent}+</b><span>Permanent Suppression, only with "
            "a non-quoted owner-denied domain or a corroborated repeated campaign</span></li>"
            "</ol></section>"
        )

    async def _review_queue_page(self, *, page: int = 1) -> bytes:
        result = await self.backend.request("reviews.list", {"page": page})
        total = int(result["total"])
        items = [SimpleNamespace(**value) for value in result["items"]]

        def row(item: SimpleNamespace) -> str:
            tone = self._review_tone(item.classification)
            identity = self._identity_cell(
                self._identity_from_value(item.identity), href=f"/review/{item.id}"
            )
            return (
                f"<tr class='tone-{tone}'>"
                f"<td data-label='Sender'>{identity}</td>"
                f"<td data-label='Review'>{self._badge(self._human_label(item.classification), tone)}"
                f"<span class='cell-note'>Review #{item.id}</span></td>"
                f"<td data-label='Signals'>{html.escape(self._signal_summary(json.loads(item.signals)))}</td>"
                f"<td data-label='Messages' class='numeric'>{item.message_count}</td>"
                f"<td data-label='Age' class='age'>{html.escape(self._relative_age(item.updated_at))}</td>"
                "</tr>"
            )

        rows = "".join(row(item) for item in items) or (
            "<tr class='empty-row'><td colspan='5'>No pending reviews.</td></tr>"
        )
        return self._page(
            self._masthead("reviews", csrf_token=self._csrf_token)
            + "<main class='page'><div class='live-region' data-live-region='pending-reviews'>"
            + self._page_header(
                "Pending Reviews",
                count=str(total),
                lede="Open a sender to fetch message content and make a decision.",
            )
            + "<details class='context-note'><summary>Review and Refresh Behavior</summary>"
            "<p>Identity is cached briefly in memory; message content is fetched only on the detail page. "
            "Deleted Telegram conversations leave their local review available for resolution. "
            "The list refreshes in place only when review state changes.</p></details>"
            "<div class='table-shell'><table class='data-table reviews-table'><thead><tr><th>Sender</th><th>Review</th>"
            "<th>Signals</th><th>Messages</th>"
            f"<th>Age</th></tr></thead><tbody>{rows}</tbody></table></div>"
            + self._pagination("/review", page, total)
            + "</div></main>",
            raw=True,
            page_title="Pending Reviews",
            live_refresh="replace",
            page_version=await self._backend_page_version(
                "/review" if page == 1 else f"/review?page={page}"
            ),
        )

    @staticmethod
    def _identity_cell(identity: LiveIdentity | None, *, href: str | None = None) -> str:
        if identity is None:
            label = "Identity Unavailable"
            identity_id = ""
        else:
            if identity.name is None:
                label = "Name Unavailable"
            else:
                label = identity.name + (
                    f" (@{identity.username})" if identity.username else ""
                )
            identity_id = f"<span class='identity-id'>ID {identity.user_id}</span>"
        name = html.escape(label)
        if href is not None:
            name = (
                f"<a class='identity-link row-link' href='{html.escape(href, quote=True)}'>"
                f"{name}</a>"
            )
        return f"<span class='identity-name'>{name}</span>{identity_id}"

    @staticmethod
    def _identity_from_value(value: object) -> LiveIdentity | None:
        if not isinstance(value, dict):
            return None
        user_id = value.get("user_id")
        name = value.get("name")
        username = value.get("username")
        if not isinstance(user_id, int):
            return None
        return LiveIdentity(
            user_id,
            name if isinstance(name, str) else None,
            username if isinstance(username, str) else None,
        )

    @staticmethod
    def _pagination(base: str, page: int, total: int) -> str:
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        if total_pages == 1:
            return ""
        separator = "&" if "?" in base else "?"
        previous = (
            f"<a href='{base}{separator}page={page - 1}'>← Previous</a>"
            if page > 1 else ""
        )
        following = (
            f"<a href='{base}{separator}page={page + 1}'>Next →</a>"
            if page < total_pages
            else ""
        )
        return (
            "<nav class='pagination' aria-label='Pagination'>"
            + previous
            + f"<span>Page {page} of {total_pages}</span>"
            + following
            + "</nav>"
        )

    NAVIGATION = (
        ("overview", "/", "Overview"),
        ("reviews", "/review", "Pending Reviews"),
        ("cases", "/cases", "Needs Attention"),
        ("archive", "/cases/archive", "Archived"),
    )

    @classmethod
    def _masthead(
        cls, active: str | None = None, *, csrf_token: str | None = None
    ) -> str:
        brand = (
            "<span class='brand-mark' aria-hidden='true'>TG</span>"
            "<span class='brand-name'>PM Gatekeeper</span>"
        )
        if csrf_token is None:
            return f"<header class='masthead'><div class='masthead-inner'><span class='brand'>{brand}</span></div></header>"
        current = " aria-current='page'"
        links = "".join(
            f"<a href='{href}'{current if key == active else ''}>{label}</a>"
            for key, href, label in cls.NAVIGATION
        )
        checked_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        return (
            "<header class='masthead'><div class='masthead-inner'>"
            f"<a class='brand' href='/'>{brand}</a>"
            "<nav class='primary-nav' aria-label='Dashboard sections' data-section-indicator>"
            f"{links}</nav>"
            "<div class='connection' data-connection data-state='connected'>"
            "<span class='live'><i aria-hidden='true'></i><span data-connection-label>Connected</span></span>"
            f"<small data-checked-at>Checked {checked_at}</small>"
            "<button class='refresh-control' type='button' data-dashboard-refresh "
            "aria-label='Check Now' title='Check Now'>↻</button></div>"
            "<button class='theme-toggle' type='button' data-theme-toggle "
            "aria-label='Change theme'>System</button>"
            "<form class='logout-form' method='post' action='/logout'>"
            f"<input type='hidden' name='token' value='{csrf_token}'>"
            "<button type='submit'>Sign Out</button></form>"
            "</div></header>"
        )

    @staticmethod
    def _change_notice() -> str:
        return (
            "<section class='live-change-notice' data-change-notice hidden>"
            "<strong>This record changed while you were viewing it.</strong> "
            "Actions are paused to prevent a stale decision. Check now to load the current state."
            "</section>"
        )

    def _action_form(
        self,
        review_id: int | str,
        action: str,
        label: str,
        *,
        tone: str | None = None,
        base: str = "review",
    ) -> str:
        button_class = f"btn btn-{tone}" if tone else "btn"
        return (
            f"<form method='post' action='/{base}/{review_id}'>"
            f"<input type='hidden' name='token' value='{self._csrf_token}'>"
            f"<input type='hidden' name='action' value='{action}'>"
            f"<button class='{button_class}' type='submit'>{html.escape(label)}</button></form>"
        )

    def _confirmation_page(
        self,
        *,
        nav: str,
        title: str,
        body: str,
        action: str,
        button: str,
        tone: str,
        cancel_href: str,
        page_title: str,
        hidden: dict[str, str] | None = None,
        warning: str | None = None,
        disabled: bool = False,
    ) -> bytes:
        hidden_inputs = "".join(
            f"<input type='hidden' name='{name}' value='{html.escape(value, quote=True)}'>"
            for name, value in (hidden or {}).items()
        )
        warning_badge = self._badge(warning, "block") if warning else ""
        content = (
            self._masthead(nav, csrf_token=self._csrf_token)
            + "<main class='page confirm-page'><section class='confirm-card"
            + (" confirm-danger" if tone == "block" else "")
            + f"'>{warning_badge}<h1>{html.escape(title)}</h1><p>{html.escape(body)}</p>"
            + "<div class='confirm-actions'>"
            + f"<form method='post' action='{action}'>"
            + f"<input type='hidden' name='token' value='{self._csrf_token}'>{hidden_inputs}"
            + f"<button class='btn btn-{tone}' type='submit'{' disabled' if disabled else ''}>"
            + f"{html.escape(button)}</button></form>"
            + f"<a class='btn' href='{cancel_href}'>Cancel</a></div></section></main>"
        )
        return self._page(content, raw=True, page_title=page_title)

    @staticmethod
    def _relative_age(created_at: int) -> str:
        seconds = max(0, int(time.time()) - created_at)
        if seconds < 3600:
            return f"{seconds // 60}m"
        if seconds < 86400:
            return f"{seconds // 3600}h"
        return f"{seconds // 86400}d"

    @staticmethod
    def _remaining(item: Any) -> str:
        if item.status == "quarantined":
            return "Manual review required"
        if item.suppressed_until is None:
            return "No automatic release"
        seconds = item.suppressed_until - int(time.time())
        if seconds <= 0:
            return "Release pending"
        if seconds < 3600:
            return f"{max(1, seconds // 60)}m remaining"
        if seconds < 86400:
            return f"{max(1, seconds // 3600)}h remaining"
        return f"{max(1, seconds // 86400)}d remaining"

    @staticmethod
    def _restriction_summary(item: Any) -> str:
        if item.status == "quarantined":
            return "Review needed"
        if item.suppressed_until is None:
            return "No automatic release"
        if item.suppressed_until <= int(time.time()):
            return "Awaiting next message"
        return DashboardHttpServer._remaining(item)

    @staticmethod
    def _list_reason_label(reason: str) -> str:
        labels = {
            "challenge_timeout": "Challenge timed out",
            "timeout_notice_failed": "Timeout warning failed",
            "warning_failed": "Failure warning failed",
            "manual_permanent_suppression": "Manual suppression",
            "attempts_exhausted": "Attempts exhausted",
        }
        return labels.get(reason, DashboardHttpServer._human_label(reason))

    @staticmethod
    def _reason_label(reason: str) -> str:
        return DashboardHttpServer._human_label(reason)

    @staticmethod
    def _human_label(value: str) -> str:
        labels = {
            "would_challenge": "Simulated Challenge · Monitor",
            "would_delete": "Planned Deletion · Monitor",
            "would_quarantine": "Simulated Quarantine · Monitor",
            "challenge_unavailable": "Challenge Unavailable · Protect",
            "challenge_unavailable_action_failed": "Challenge and Archive Failed · Protect",
            "restore_failed": "Restoration Failed · Protect",
            "warning_failed": "Failure Warning Not Delivered · Protect",
            "timeout_notice_failed": "Timeout Warning Not Delivered · Protect",
            "critical_rule": "Legacy Critical Rule Match",
            "permanent_suppression": "Permanent Suppression",
            "standard_challenge": "Standard Challenge",
            "strict_challenge": "Strict Challenge",
            "owner_denied_domain": "Owner Denied Domain",
            "corroborated_repeated_campaign": "Corroborated Repeated Campaign",
            "risk_score_requires_strict_challenge": "Risk Score Requires Strict Challenge",
            "risk_score_below_strict_threshold": "Risk Score Below Strict Threshold",
            "manual_operator_decision": "Manual Operator Decision",
            "manual_permanent_suppression": "Manual Permanent Suppression",
            "manual_spam": "Manual Spam Review",
            "attempts_exhausted": "Attempts Exhausted",
            "challenge_timeout": "Challenge Timeout",
            "challenge_pending": "Challenge Pending",
            "reference_unavailable": "Telegram Reference Unavailable",
            "reason_unavailable": "Reason Unavailable",
            "spam_candidate": "Spam Candidate",
            "legitimate_candidate": "Legitimate Candidate",
            "not recorded": "Not Recorded",
        }
        if value in labels:
            return labels[value]
        if value == "uncertain":
            return "Uncertain"
        if value.endswith("_action_failed"):
            action = value.removesuffix("_action_failed").replace("_", " ").title()
            return f"{action} Action Failed · Protect"
        prefix = ""
        body = value
        if value.startswith("HR-") and "_" in value:
            # HR rule codes predate adaptive scoring and survive only in old rows.
            prefix, body = value.split("_", 1)
            prefix = f"Legacy {prefix} · "
        label = body.replace("_", " ").strip().title()
        label = label.replace("Url", "URL").replace("Vpn", "VPN")
        label = label.replace("Webview", "WebView")
        return prefix + label

    @classmethod
    def _page(
        cls,
        content: str,
        *,
        raw: bool = False,
        page_title: str | None = None,
        live_refresh: str | None = None,
        page_version: str | None = None,
    ) -> bytes:
        if raw:
            # Keep the masthead mounted while navigating between dashboard pages.
            header, separator, page_content = content.partition("</header>")
            body = (
                header + separator
                + "<div data-dashboard-content>" + page_content + "</div>"
                if separator else content
            )
        else:
            guidance = {
                "Invalid Access Token": (
                    "This login link is invalid or has already been used. Run "
                    "the tunnel helper again to generate a new one-time link."
                ),
                "Not Found": (
                    "The requested page is unavailable. Check the address or return to the "
                    "dashboard."
                ),
                "Dashboard Access Missing": (
                    "This address does not contain a valid dashboard session. Run the tunnel "
                    "helper again and open its new one-time link in this browser."
                ),
                "Dashboard Signed Out": (
                    "This browser session has been revoked. Run the tunnel helper again when "
                    "you need to reopen the dashboard."
                ),
                "Request Failed": (
                    "The request could not be completed. No dashboard action was confirmed."
                ),
            }.get(content, "Check the request and return to the dashboard.")
            return_action = (
                ""
                if content
                in {
                    "Invalid Access Token",
                    "Dashboard Access Missing",
                    "Dashboard Signed Out",
                }
                else "<a class='btn' href='/'>Return to Dashboard</a>"
            )
            body = (
                cls._masthead()
                + "<main class='error-layout'><section class='error-card'>"
                + "<div class='error-content'>"
                + "<p class='error-kind'>Dashboard Error</p>"
                + f"<h1>{html.escape(content)}</h1>"
                + f"<p>{html.escape(guidance)}</p>"
                + "<p class='error-command'><code>scripts/dashboard-tunnel.sh SSH_TARGET</code></p>"
                + return_action
                + "</div></section></main>"
            )
        document_title = page_title or (
            "Gatekeeper Dashboard" if raw else f"Gatekeeper · {content}"
        )
        live_attributes = (
            f' data-live-refresh="{html.escape(live_refresh)}"'
            f' data-page-version="{html.escape(page_version)}"'
            f' data-poll-seconds="{DASHBOARD_POLL_SECONDS}"'
            if raw and live_refresh and page_version
            else ""
        )
        dashboard_script = (
            '<script src="/dashboard-theme.js"></script>'
            '<script src="/dashboard.js" defer></script>'
            if raw
            else ""
        )
        stylesheet = "/dashboard.css" if raw else "/dashboard-error.css"
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(document_title)}</title>
<link rel="stylesheet" href="{stylesheet}">
{dashboard_script}</head><body{' data-dashboard-page' if raw else ''}{live_attributes}>{body}</body></html>""".encode("utf-8")
