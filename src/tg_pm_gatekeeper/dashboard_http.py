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
from urllib.parse import parse_qs, urlsplit, urlunsplit

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
        if path in {"/dashboard.js", "/dashboard.css", "/dashboard-error.css"}:
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
        if path == "/enforcement" and method == "GET":
            return 303, {"Location": "/cases"}, b""
        if path.startswith("/enforcement/"):
            suffix = path.removeprefix("/enforcement/")
            return 303, {"Location": f"/cases/{suffix}"}, b""
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
            "use_active_case": (409, "Use Allow sender in Active Cases"),
            "telegram_action_failed": (
                500,
                "Telegram Action Failed; Item Was Not Changed",
            ),
            "restriction_release_failed": (500, "Restriction Release Failed"),
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
        self._session_last_seen_at = now
        self._on_authenticated_activity()
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
            f"<p class='eyebrow'>{html.escape(label)}</p>"
            f"<pre class='{css}'>{html.escape(value)}</pre>"
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
                "<span class='signal-index' aria-hidden='true'></span>"
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
    def _policy_decision_panel(cls, payload: dict[str, object]) -> str:
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
                f"evidence. The recorded decision was {action_label}."
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
        <section class="policy-map" aria-label="Policy decision explanation">
          <div class="policy-score-head">
            <div><span class="policy-kicker">Risk Score</span>
              <strong>{risk_score}</strong><small>additive points · not a probability</small></div>
            <span class="policy-version">{policy_version}</span>
          </div>
          <div class="risk-track" role="img" aria-label="Risk score {risk_score}; strict challenge starts at {PolicyEngine.STRICT_CHALLENGE_THRESHOLD} and permanent score condition starts at {PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD}">
            <meter class="risk-meter" min="0" max="100" value="{plotted_score}">{plotted_score}%</meter>
            <span class="risk-mark strict-mark"><i>{PolicyEngine.STRICT_CHALLENGE_THRESHOLD}</i><b>Strict</b></span>
            <span class="risk-mark permanent-mark"><i>{PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD}</i><b>Permanent score</b></span>
          </div>
          <p class="gate-formula">Permanent suppression requires <strong>both</strong> conditions:</p>
          <div class="gate-check {score_state}">
            <span class="gate-symbol" aria-hidden="true">{score_symbol}</span>
            <div><small>1 · Score condition</small>
              <strong>{risk_score} ≥ {PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD}</strong>
              <p>Risk score reaches the permanent-suppression score threshold.</p></div>
          </div>
          <div class="gate-check {gate_state}">
            <span class="gate-symbol" aria-hidden="true">{gate_symbol}</span>
            <div><small>2 · Destructive evidence</small>
              <strong>{html.escape(gate_label)}</strong>
              <p>Requires a non-quoted denied domain, or a corroborated repeated campaign.</p></div>
          </div>
          <div class="policy-outcome {action_class}">
            <small>Final policy decision</small><strong>{html.escape(action_label)}</strong>
            <p>{html.escape(outcome_copy)}</p>
          </div>
        </section>"""

    @staticmethod
    def _is_legacy_payload(payload: dict[str, object]) -> bool:
        try:
            schema_version = int(payload.get("schema_version", 0))
        except (TypeError, ValueError):
            schema_version = 0
        return schema_version < 5 or payload.get("policy_version") == "rules-v2"

    def _review_sections(self, payload: dict[str, object]) -> str:
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
                "<div class='notice'><strong>Limited Textual Evidence.</strong> "
                "No message text, quoted text, or webpage-preview text was retained. "
                "Review any available URLs, button text, evidence signals, and structural "
                "metadata before deciding whether to allow the sender or leave the "
                "restriction unchanged.</div>"
            )
        return (
            sections
            + f"<p class='content-label'>Button Text</p><pre>{html.escape(button_texts)}</pre>"
            + f"<p class='content-label'>Normalized Domains</p><pre>{html.escape(domains)}</pre>"
            + f"<p class='content-label'>Quoted-Context Domains</p><pre>{html.escape(quote_domains)}</pre>"
            + f"<details><summary>Full URLs</summary><pre>{urls}</pre></details>"
            + f"<details><summary>Quoted-Context URLs</summary><pre>{quote_urls}</pre></details>"
            + f"<details><summary>Link Shape</summary><pre>{url_shape}</pre></details>"
            + f"<details><summary>Quoted-Context Link Shape</summary><pre>{quote_url_shape}</pre></details>"
            + f"<details><summary>Full Decrypted Case Payload</summary><pre>{details}</pre></details>"
        )

    @staticmethod
    def _legacy_severity_label(payload: dict[str, object], reason: str) -> str:
        severity = str(payload.get("severity") or "").strip().casefold()
        if severity in {"none", "signal", "high", "critical"}:
            return severity.title()
        if severity == "manual":
            return "Manual Decision"
        if reason == "critical_rule":
            return "Critical"
        return "Not Recorded"

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

    async def _enforcement_index_page(self, *, page: int = 1) -> bytes:
        result = await self.backend.request("cases.list", {"page": page})
        total = int(result["total"])
        items = [SimpleNamespace(**value) for value in result["items"]]
        stats = result["stats"]
        rows = "".join(
            "<tr>"
            f"<td data-label='Sender'>{self._identity_cell(self._identity_from_value(item.identity), href=f'/cases/{item.sender_key}')}</td>"
            f"<td data-label='State'><span class='badge'>{html.escape(self._human_label(item.status))}</span>"
            f"<span class='cell-note'>{html.escape(self._restriction_summary(item))}</span></td>"
            f"<td data-label='Trigger'>{html.escape(self._list_reason_label(item.reason))}</td>"
            f"<td data-label='Evidence'><span class='availability{' availability-unavailable' if not item.has_evidence else ''}'>"
            f"{'Ready' if item.has_evidence else 'Unavailable'}</span></td>"
            f"<td data-label='Age' class='age'>{html.escape(self._relative_age(item.updated_at))}</td>"
            "</tr>"
            for item in items
        ) or "<tr class='empty-row'><td colspan='5'>No active restrictions.</td></tr>"
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
            f" {stats['unidentified']} legacy restriction"
            f"{'s' if stats['unidentified'] != 1 else ''} still require"
            f"{'s' if stats['unidentified'] == 1 else ''} manual ID recovery."
            if stats["unidentified"]
            else " Every active restriction has a retained encrypted control identity."
        )
        recovery = ""
        if stats["unidentified"]:
            recovery = (
                "<details class='advanced-recovery'><summary>Advanced recovery"
                f" <span>{stats['unidentified']} legacy</span></summary><div class='advanced-recovery-content'>"
                "<p class='eyebrow'>Legacy Recovery</p>"
                "<h2>Allow an unidentified restricted sender by Telegram User ID</h2>"
                "<p>Use this only for a legacy restriction created before encrypted control "
                "identities were retained. This removes the Gatekeeper restriction and cancels "
                "pending deletion jobs, but cannot restore saved Telegram folder or notification "
                "state without a peer reference. The entered ID is used only to derive the "
                "existing sender key and is not stored.</p>"
                "<form class='manual-release' method='post' action='/cases/release'>"
                f"<input type='hidden' name='token' value='{self._csrf_token}'>"
                "<label for='release-user-id'>Telegram User ID</label>"
                "<input id='release-user-id' name='user_id' type='text' inputmode='numeric' "
                "pattern='[0-9]+' autocomplete='off' required>"
                "<button class='danger' type='submit'>Allow without restore</button>"
                "</form></div></details>"
            )
        content = (
            self._masthead(
                "Active Cases", f"{total} Restrictions", csrf_token=self._csrf_token
            )
            + "<p class='back'><a href='/'>← Operations Dashboard</a> · <a href='/review'>Pending Reviews</a></p>"
            + "<main class='list-main' data-live-region='active-cases'><section class='queue-intro compact-intro'><p class='eyebrow'>Protect mode state</p>"
            + "<p class='lede'>Review every current restriction. Evidence availability is tracked separately; Telegram block is never used.</p>"
            + "<dl class='metric-grid'>"
            + f"<div><dt>Quarantined</dt><dd class='data-value'>{stats['quarantined']}</dd></div>"
            + f"<div><dt>Suppressed</dt><dd class='data-value'>{stats['suppressed']}</dd></div>"
            + f"<div><dt>Reviewable Evidence</dt><dd class='data-value'>{stats['reviewable']}</dd></div></dl>"
            + "<details class='context-note'><summary>Restriction context</summary>"
            + f"<p><strong>State reasons:</strong> {reasons}. {snapshot_note}{identity_note}</p></details></section>"
            + "<div class='table-shell'><table class='data-table cases-table'><thead><tr><th>Sender</th><th>State</th><th>Trigger</th><th>Evidence</th><th>Age</th></tr></thead>"
            + f"<tbody>{rows}</tbody></table></div>"
            + self._pagination("/cases", page, total)
            + "</main>"
            + "<section class='advanced-recovery-wrap' data-live-region='legacy-recovery'>"
            + recovery
            + "</section>"
        )
        return self._page(
            content,
            raw=True,
            page_title="Active Cases",
            live_refresh="replace",
            page_version=await self._backend_page_version(
                "/cases" if page == 1 else f"/cases?page={page}"
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
        identity = "Identity unavailable"
        telegram_link = ""
        user_id: int | None = None
        if identity_value is not None:
            user_id = identity_value.user_id
            identity = identity_value.name or "Name unavailable"
            if identity_value.username:
                identity += f" (@{identity_value.username})"
            telegram_link = (
                f"<a class='telegram-link' href='tg://user?id={user_id}'>"
                "Open this conversation in Telegram ↗</a>"
            )
        legacy_payload = self._is_legacy_payload(payload)
        if legacy_payload:
            signal_breakdown = self._signal_breakdown(payload.get("rule_codes", []))
            risk_label = self._legacy_severity_label(payload, item.reason)
            policy_decision = "Legacy decision retained"
            decision_basis = "Recorded under rules-v2; not recalculated."
            legacy_decision_rows = (
                f"<dt>Risk Score</dt><dd>{html.escape(risk_label)}</dd>"
                f"<dt>Policy Decision</dt><dd>{html.escape(policy_decision)}</dd>"
                f"<dt>Decision Basis</dt><dd>{html.escape(decision_basis)}</dd>"
            )
            policy_panel = ""
            legacy_notice = (
                "<div class='notice'><strong>Legacy HR Decision.</strong> "
                "Recorded under rules-v2; not recalculated and no new action was added.</div>"
            )
        else:
            signal_breakdown = self._signal_breakdown(payload.get("signals", []))
            legacy_decision_rows = ""
            policy_panel = self._policy_decision_panel(payload)
            legacy_notice = ""
        features = json.dumps(payload.get("features", {}), indent=2, sort_keys=True)
        observed_at = item.evidence_created_at or item.updated_at
        observed = datetime.fromtimestamp(observed_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        evidence_content = (
            self._review_sections(payload)
            if evidence_available
            else (
                "<div class='empty-state'><strong>Evidence expired or unavailable.</strong> "
                "The encrypted control identity is retained only so this restriction remains "
                "visible and reversible.</div>"
            )
        )
        evidence_expiry = (
            datetime.fromtimestamp(item.evidence_expires_at, timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
            if item.evidence_expires_at is not None
            else "Expired or unavailable"
        )
        evidence_heading = (
            "Decrypted Local Evidence"
            if evidence_available
            else "Restriction Control"
        )
        evidence_note = (
            "Encrypted at rest; decrypted only for this owner-only view."
            if evidence_available
            else unavailable_note + " Only the encrypted control identity remains available."
        )
        allow_action = (
            self._action_form(
                item.sender_key, "allow", "Allow sender", base="cases"
            )
            if user_id is not None
            else "<button type='button' disabled>Allow Unavailable</button>"
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
        keep_label = "Keep restriction"
        content = f"""
        {self._masthead("Active Cases", self._human_label(item.status), csrf_token=self._csrf_token)}
        <p class="back"><a href="/cases">← Active Cases</a></p>
        {self._change_notice()}
        <main class="review-grid"><section class="message-panel">
          <p class="eyebrow">{evidence_heading}</p>
          <h2>{html.escape(identity)}</h2>
          <p class="refresh-note">{evidence_note}</p>
          {legacy_notice}
          {evidence_content}
          {telegram_link}
        </section><aside class="case-file"><p class="eyebrow">Restriction Details</p>
          <dl><dt>Status</dt><dd><span class="badge">{html.escape(self._human_label(item.status))}</span></dd>
          <dt>Restriction Cause</dt><dd>{html.escape(self._human_label(item.reason))}</dd>
          {legacy_decision_rows}</dl>
          {policy_panel}
          <dl>
          <dt>Evidence Signals</dt><dd class="signal-breakdown">{signal_breakdown}</dd>
          <dt>Triggered</dt><dd>{observed}</dd><dt>Restriction</dt><dd>{html.escape(self._remaining(item))}</dd>
          <dt>Evidence Expires</dt><dd>{evidence_expiry}</dd></dl>
          <details><summary>Structural Features</summary><pre>{html.escape(features)}</pre></details>
        </aside></main><section class="decision-panel"><p class="eyebrow">Operator Action</p>
          <h2>{html.escape(allow_guidance)}</h2>
          <div class="actions two">
            {allow_action}
            {self._action_form(item.sender_key, "keep", keep_label, base="cases")}
          </div></section>"""
        return 200, {}, self._page(
            content,
            raw=True,
            page_title=f"Active Case · {self._human_label(item.status)}",
            live_refresh="notice",
            page_version=await self._backend_page_version(f"/cases/{item.sender_key}"),
        )

    async def _show_review(
        self, item: Any | int
    ) -> tuple[int, dict[str, str], bytes]:
        review_id = item if isinstance(item, int) else item.id
        result = await self.backend.request(
            "reviews.detail", {"review_id": review_id}
        )
        item = SimpleNamespace(**result)
        identity_value = self._identity_from_value(result.get("identity"))
        identity = "Identity unavailable"
        user_id: int | None = None
        if identity_value is not None:
            user_id = identity_value.user_id
            identity = identity_value.name or "Name unavailable"
            if identity_value.username:
                identity += f" (@{identity_value.username})"
        signals = self._signal_breakdown(json.loads(item.signals))
        review_reason = self._human_label(item.classification)
        features = json.dumps(json.loads(item.features), indent=2, sort_keys=True)
        observed_at = datetime.fromtimestamp(item.updated_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        text = result.get("message")
        if text is None:
            content = f"""
            {self._masthead("Review Item", f"Review #{item.id}", csrf_token=self._csrf_token)}
            <p class="back"><a href="/review">← Back to Pending Reviews</a></p>
            {self._change_notice()}
            <main class="review-grid">
              <section class="message-panel">
                <p class="eyebrow">Telegram Message Unavailable</p>
                <h2>{html.escape(identity)}</h2>
                <div class="empty-state"><strong>The referenced message no longer exists.</strong>
                <p>The conversation may have been deleted in Telegram. This pending row is local
                review state and is not removed automatically.</p></div>
              </section>
              <aside class="case-file"><p class="eyebrow">Review Details</p>
                <dl><dt>Review Reason</dt><dd><span class="badge">{html.escape(review_reason)}</span></dd>
                <dt>Evidence Signals</dt><dd class="signal-breakdown">{signals}</dd>
                <dt>Messages Observed</dt><dd>{item.message_count}</dd>
                <dt>Last Observed</dt><dd>{observed_at}</dd></dl>
              </aside>
            </main>
            <section class="decision-panel"><p class="eyebrow">Resolve Local Record</p>
              <h2>Remove this sender's pending review and cancel pending Gatekeeper deletion jobs. Telegram and trust state are unchanged.</h2>
              <div class="actions one">
                {self._action_form(item.id, "dismiss", "Dismiss & cancel jobs")}
              </div>
            </section>
            """
            return 200, {}, self._page(
                content,
                raw=True,
                page_title=f"Review #{item.id}",
                live_refresh="notice",
                page_version=await self._backend_page_version(f"/review/{item.id}"),
            )
        text = str(text)
        content = f"""
        {self._masthead("Review Item", f"Review #{item.id}", csrf_token=self._csrf_token)}
        <p class="back"><a href="/review">← Back to Pending Reviews</a></p>
        {self._change_notice()}
        <main class="review-grid">
          <section class="message-panel">
            <p class="eyebrow">Fetched from Telegram · Not Stored Locally</p>
            <h2>{html.escape(identity)}</h2>
            <pre class="message">{html.escape(text)}</pre>
            <a class="telegram-link" href="tg://user?id={user_id}">Open this conversation in Telegram ↗</a>
          </section>
          <aside class="case-file">
            <p class="eyebrow">Review Details</p>
            <dl><dt>Review Reason</dt><dd><span class="badge">{html.escape(review_reason)}</span></dd>
            <dt>Evidence Signals</dt><dd class="signal-breakdown">{signals}</dd>
            <dt>Telegram ID</dt><dd>{user_id}</dd>
            <dt>Messages Observed</dt><dd>{item.message_count}</dd>
            <dt>Last Observed</dt><dd>{observed_at}</dd></dl>
            <details><summary>Structural Features</summary><pre>{html.escape(features)}</pre></details>
          </aside>
        </main>
        <section class="decision-panel"><p class="eyebrow">Sender Decision</p>
          <h2>This decision applies to all pending entries for this sender.</h2>
          <div class="actions">
            {self._action_form(item.id, "legitimate", "Allow sender")}
            {self._action_form(item.id, "spam", "Suppress and delete", danger=True)}
            {self._action_form(item.id, "dismiss", "Dismiss & cancel jobs")}
          </div>
        </section>
        """
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
        mode = str(result["mode"])
        content = (
            self._masthead(
                "Operations Dashboard", mode.title(), csrf_token=self._csrf_token
            )
            + "<main class='list-main' data-live-region='operations'><section class='queue-intro compact-intro'><p class='eyebrow'>Operator overview</p>"
            "<p class='lede'>Review restrictions, recover false positives, and resolve pending decisions.</p>"
            "<dl class='metric-grid'>"
            f"<div><dt>Active Restrictions</dt><dd class='data-value'>{active_restrictions}</dd></div>"
            f"<div><dt>Reviewable Cases</dt><dd class='data-value'>{active_stats['reviewable']}</dd></div>"
            f"<div><dt>Pending Reviews</dt><dd class='data-value'>{pending_reviews}</dd></div>"
            "</dl></section>"
            "<nav class='area-grid' aria-label='Review areas'>"
            f"<a class='area-card' href='/cases'><span class='eyebrow'>Restrictions</span><strong>Active Cases</strong><span>Review and recover current restrictions.</span><b>{active_restrictions}</b></a>"
            f"<a class='area-card' href='/review'><span class='eyebrow'>Decisions</span><strong>Pending Reviews</strong><span>Resolve simulations and exception reviews.</span><b>{pending_reviews}</b></a>"
            "</nav></main>"
        )
        return self._page(
            content,
            raw=True,
            page_title="Operations Dashboard",
            live_refresh="replace",
            page_version=await self._backend_page_version("/"),
        )

    async def _review_queue_page(self, *, page: int = 1) -> bytes:
        result = await self.backend.request("reviews.list", {"page": page})
        total = int(result["total"])
        items = [SimpleNamespace(**value) for value in result["items"]]
        rows = "".join(
            "<tr>"
            f"<td data-label='Sender'>{self._identity_cell(self._identity_from_value(item.identity), href=f'/review/{item.id}')}</td>"
            f"<td data-label='Review'><span class='badge'>{html.escape(self._human_label(item.classification))}</span>"
            f"<span class='cell-note'>Review #{item.id}</span></td>"
            f"<td data-label='Signals'>{html.escape(self._signal_summary(json.loads(item.signals)))}</td>"
            f"<td data-label='Messages' class='numeric'>{item.message_count}</td>"
            f"<td data-label='Age' class='age'>{html.escape(self._relative_age(item.updated_at))}</td>"
            "</tr>"
            for item in items
        )
        if not rows:
            rows = "<tr class='empty-row'><td colspan='5'>No pending reviews.</td></tr>"
        return self._page(
            self._masthead(
                "Pending Reviews", f"{total} Pending", csrf_token=self._csrf_token
            )
            + "<p class='back'><a href='/'>← Operations Dashboard</a> · <a href='/cases'>Active Cases</a></p>"
            + "<main class='list-main' data-live-region='pending-reviews'><section class='queue-intro compact-intro'><p class='eyebrow'>Decision queue</p>"
            "<p class='lede'>Open a sender to fetch message content and make a decision.</p>"
            "<details class='context-note'><summary>Review and refresh behavior</summary>"
            "<p>Identity is cached briefly in memory; message content is fetched only on the detail page. "
            "Deleted Telegram conversations leave their local review available for resolution. "
            "The list refreshes in place only when review state changes.</p></details></section>"
            "<div class='table-shell'><table class='data-table reviews-table'><thead><tr><th>Sender</th><th>Review</th>"
            "<th>Signals</th><th>Messages</th>"
            f"<th>Age</th></tr></thead><tbody>{rows}</tbody></table></div>"
            + self._pagination("/review", page, total)
            + "</main>",
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
            label = "Identity unavailable"
            identity_id = ""
        else:
            if identity.name is None:
                label = "Name unavailable"
            else:
                label = identity.name + (
                    f" (@{identity.username})" if identity.username else ""
                )
            identity_id = f"<span class='identity-id'>ID {identity.user_id}</span>"
        name = html.escape(label)
        if href is not None:
            name = f"<a class='identity-link' href='{html.escape(href, quote=True)}'>{name}</a>"
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
        previous = (
            f"<a href='{base}?page={page - 1}'>← Previous</a>" if page > 1 else ""
        )
        following = (
            f"<a href='{base}?page={page + 1}'>Next →</a>"
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

    @staticmethod
    def _masthead(
        section: str, status: str, *, csrf_token: str | None = None
    ) -> str:
        checked_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        logout = (
            "<form class='logout-form' method='post' action='/logout'>"
            f"<input type='hidden' name='token' value='{csrf_token}'>"
            "<button type='submit'>Sign Out</button></form>"
            if csrf_token is not None
            else ""
        )
        return (
            "<header class='masthead'><div><span class='mark'>TG</span>"
            "<span class='product'>PM Gatekeeper</span></div>"
            f"<div class='section' data-section-indicator>{html.escape(section)}"
            f"<span>{html.escape(status)}</span></div>"
            "<div class='connection' data-connection data-state='connected'>"
            "<div><span class='live'><i></i><span data-connection-label>Connected</span></span>"
            f"<small data-checked-at>Checked {checked_at}</small></div>"
            "<button class='refresh-control' type='button' data-dashboard-refresh "
            "aria-label='Check now' title='Check now'>↻</button></div>"
            + logout
            + "</header>"
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
        danger: bool = False,
        base: str = "review",
    ) -> str:
        button_class = " class='danger'" if danger else ""
        return (
            f"<form method='post' action='/{base}/{review_id}'>"
            f"<input type='hidden' name='token' value='{self._csrf_token}'>"
            f"<input type='hidden' name='action' value='{action}'>"
            f"<button{button_class} type='submit'>{html.escape(label)}</button></form>"
        )

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
            "critical_rule": "Critical HR Match",
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
            prefix, body = value.split("_", 1)
            prefix += " · "
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
            body = content
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
                else "<a class='button-link' href='/'>Return to Dashboard</a>"
            )
            body = (
                cls._masthead("Error", "Request Not Completed")
                + "<main class='error-layout'><section class='error-card'>"
                + "<div class='error-content'>"
                + "<p class='eyebrow'>Dashboard Error</p>"
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
            '<script src="/dashboard.js" defer></script>' if live_attributes else ""
        )
        stylesheet = "/dashboard.css" if raw else "/dashboard-error.css"
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(document_title)}</title>
<link rel="stylesheet" href="{stylesheet}">
{dashboard_script}</head><body{live_attributes}>{body}</body></html>""".encode("utf-8")
