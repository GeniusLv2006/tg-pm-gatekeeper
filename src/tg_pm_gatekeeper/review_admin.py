# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import os
import secrets
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit, urlunsplit

from telethon import functions, types

from .message_facts import facts_from_message
from .policy import EvidenceSignal, PolicyEngine
from .restriction_actions import RestrictionActions, RestrictionReleaseResult
from .rules import url_evidence, url_shape
from .service import GatekeeperService
from .store import ActiveRestriction, DialogSnapshot, ReviewItem, StateStore

LOG = logging.getLogger("gatekeeper.review")
MAX_HEADER_BYTES = 16 * 1024
MAX_BODY_BYTES = 4 * 1024
IDENTITY_CACHE_SECONDS = 5 * 60
IDENTITY_FAILURE_CACHE_SECONDS = 30
IDENTITY_BATCH_SIZE = 100
IDENTITY_FETCH_TIMEOUT_SECONDS = 5
DASHBOARD_POLL_SECONDS = 15
DASHBOARD_SESSION_IDLE_SECONDS = 30 * 60
DASHBOARD_SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60
DASHBOARD_SESSION_COOKIE = "tg_pm_gatekeeper_session"
PAGE_SIZE = 50


DASHBOARD_SCRIPT = r"""(() => {
  const root = document.body;
  const mode = root.dataset.liveRefresh;
  let version = root.dataset.pageVersion;
  let timer;
  let checking = false;

  const connection = document.querySelector('[data-connection]');
  const connectionLabel = document.querySelector('[data-connection-label]');
  const checkedAt = document.querySelector('[data-checked-at]');
  const refreshButton = document.querySelector('[data-dashboard-refresh]');
  const changeNotice = document.querySelector('[data-change-notice]');

  if (!mode || !version || !connection || !connectionLabel || !checkedAt) return;

  const setConnection = (state, label, timestamp) => {
    connection.dataset.state = state;
    connectionLabel.textContent = label;
    if (timestamp) checkedAt.textContent = `Checked ${timestamp}`;
  };

  const replaceLiveRegions = async () => {
    const response = await fetch(location.pathname + location.search, {
      cache: 'no-store',
      credentials: 'same-origin',
      headers: {'X-Dashboard-Refresh': '1'},
    });
    if (!response.ok) throw new Error(`page refresh failed: ${response.status}`);
    const nextDocument = new DOMParser().parseFromString(await response.text(), 'text/html');
    const nextRegions = new Map(
      Array.from(nextDocument.querySelectorAll('[data-live-region]')).map(
        (region) => [region.dataset.liveRegion, region]
      )
    );
    document.querySelectorAll('[data-live-region]').forEach((region) => {
      const replacement = nextRegions.get(region.dataset.liveRegion);
      if (!replacement) return;
      region.querySelectorAll('input:not([type="hidden"]), textarea, select').forEach((control) => {
        const key = control.id || control.name;
        if (!key) return;
        const nextControl = Array.from(
          replacement.querySelectorAll('input:not([type="hidden"]), textarea, select')
        ).find((candidate) => (candidate.id || candidate.name) === key);
        if (nextControl) nextControl.value = control.value;
      });
      const active = region.contains(document.activeElement) ? document.activeElement : null;
      const activeKey = active && (active.id || active.name);
      region.replaceWith(replacement);
      if (activeKey) {
        const nextActive = Array.from(replacement.querySelectorAll('input, textarea, select, button, a'))
          .find((candidate) => (candidate.id || candidate.name) === activeKey);
        nextActive?.focus({preventScroll: true});
      }
    });
    const currentSection = document.querySelector('[data-section-indicator]');
    const nextSection = nextDocument.querySelector('[data-section-indicator]');
    if (currentSection && nextSection) currentSection.replaceWith(nextSection);
  };

  const markChanged = () => {
    if (!changeNotice) return;
    changeNotice.hidden = false;
    document.querySelectorAll('form:not(.logout-form) button').forEach((button) => {
      button.disabled = true;
    });
  };

  const check = async ({force = false} = {}) => {
    if (checking || (!force && document.visibilityState !== 'visible')) return;
    checking = true;
    if (refreshButton) refreshButton.disabled = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 4000);
    try {
      const capabilityRoot = `/${location.pathname.split('/')[1]}`;
      const logicalPath = location.pathname.slice(capabilityRoot.length) || '/';
      const logicalTarget = logicalPath + location.search;
      const response = await fetch(
        `${capabilityRoot}/dashboard/status?path=${encodeURIComponent(logicalTarget)}`,
        {cache: 'no-store', credentials: 'same-origin', signal: controller.signal}
      );
      if (!response.ok) throw new Error(`status check failed: ${response.status}`);
      const status = await response.json();
      setConnection('connected', 'Connected', status.checked_at);
      if (force || status.version !== version) {
        if (mode === 'replace') {
          await replaceLiveRegions();
          version = status.version;
          root.dataset.pageVersion = version;
        } else if (status.version !== version) {
          markChanged();
          version = status.version;
          root.dataset.pageVersion = version;
        }
      }
    } catch (_error) {
      setConnection('disconnected', 'Disconnected', 'retrying');
    } finally {
      window.clearTimeout(timeout);
      checking = false;
      if (refreshButton) refreshButton.disabled = false;
    }
  };

  const schedule = () => {
    window.clearInterval(timer);
    if (document.visibilityState === 'visible') {
      check();
      timer = window.setInterval(check, Number(root.dataset.pollSeconds) * 1000);
    }
  };

  refreshButton?.addEventListener('click', () => {
    if (mode === 'notice' && changeNotice && !changeNotice.hidden) {
      location.reload();
      return;
    }
    check({force: true});
  });
  document.addEventListener('visibilitychange', schedule);
  schedule();
})();
"""


@dataclass(frozen=True, slots=True)
class LiveIdentity:
    user_id: int
    name: str | None
    username: str | None


class ReviewAdminServer:
    def __init__(
        self,
        socket_path: Path,
        store: StateStore,
        service: GatekeeperService,
        telegram_client,
        *,
        mute_days: int,
        cancel_timeout: Callable[[str], None] = lambda _sender_key: None,
        schedule_dialog_deletion: Callable[[int, int], None] = (
            lambda _action_id, _delete_at: None
        ),
        restriction_actions: RestrictionActions | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.store = store
        self.service = service
        self.protector = service.protector
        self.telegram_client = telegram_client
        self.mute_days = mute_days
        self.cancel_timeout = cancel_timeout
        self.schedule_dialog_deletion = schedule_dialog_deletion
        self.restriction_actions = restriction_actions or RestrictionActions(
            store,
            service,
            telegram_client,
            cancel_timeout=cancel_timeout,
        )
        self._server: asyncio.AbstractServer | None = None
        self._csrf_token = secrets.token_urlsafe(32)
        self._access_token = secrets.token_urlsafe(32)
        self._capability_token = secrets.token_urlsafe(32)
        self._session_token: str | None = None
        self._session_started_at: float | None = None
        self._session_last_seen_at: float | None = None
        self.access_token_path = socket_path.with_suffix(".access-token")
        self._identity_cache: dict[str, tuple[float, str | None, str | None]] = {}

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
            await self._server.wait_closed()
            self._server = None
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        self.access_token_path.unlink(missing_ok=True)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            method, target, body, request_headers = await self._read_request(reader)
            status, headers, response = await self._dispatch(
                method, target, body, request_headers=request_headers
            )
        except (ValueError, asyncio.IncompleteReadError):
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
        }.get(status, "Internal Server Error")
        response_headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(response)),
            "Connection": "close",
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; "
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
        writer.close()
        await writer.wait_closed()

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
        if path == "/dashboard.js":
            if method != "GET":
                return 405, {"Allow": "GET"}, b""
            return (
                200,
                {"Content-Type": "text/javascript; charset=utf-8"},
                DASHBOARD_SCRIPT.encode("utf-8"),
            )
        if path == "/dashboard/status":
            if method != "GET":
                return 405, {"Allow": "GET"}, b""
            page_path = parse_qs(parsed.query).get("path", [""])[0]
            version = self._page_version(page_path)
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
            if page is None or not self._page_exists(
                page, self.store.pending_review_count()
            ):
                return 404, {}, self._page("Not Found")
            return 200, {}, await self._review_queue_page(page=page)
        if path == "/enforcement" and method == "GET":
            return 303, {"Location": "/cases"}, b""
        if path.startswith("/enforcement/"):
            suffix = path.removeprefix("/enforcement/")
            return 303, {"Location": f"/cases/{suffix}"}, b""
        if path == "/cases" and method == "GET":
            page = self._page_number(parsed.query)
            if page is None or not self._page_exists(
                page, self.store.active_restriction_count()
            ):
                return 404, {}, self._page("Not Found")
            return 200, {}, await self._enforcement_index_page(page=page)
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
        item = self.store.review_item(review_id)
        if item is None or (
            item.status == "pending" and item.expires_at <= int(time.time())
        ):
            return 404, {}, self._page("Review Item Not Found")
        if method == "GET":
            return await self._show_review(item)
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, self._page("Method Not Allowed")
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        token = values.get("token", [""])[0]
        action = values.get("action", [""])[0]
        if not secrets.compare_digest(token, self._csrf_token):
            return 400, {}, self._page("Invalid Action Token")
        async with self.service.sender_lock(item.sender_key):
            item = self.store.review_item(review_id)
            if item is None or item.status != "pending" or item.reference is None:
                return 409, {}, self._page("This Item Has Already Been Reviewed")
            state = self.store.sender(item.sender_key)
            if action == "legitimate":
                if state.status in {"challenged", "quarantined", "suppressed"}:
                    peer = self._peer_from_item(item)
                    if not await self._restore(peer, item.sender_key):
                        return (
                            500,
                            {},
                            self._page("Telegram Action Failed; Item Was Not Changed"),
                        )
                self.store.allow(item.sender_key)
                self.cancel_timeout(item.sender_key)
                self.store.decide_sender_reviews(item.sender_key, "legitimate")
            elif action == "spam":
                peer = self._peer_from_item(item)
                if state.status != "suppressed":
                    await self._capture_manual_enforcement(item, peer)
                if state.status not in {"challenged", "quarantined", "suppressed"}:
                    if not await self._archive_and_mute(peer, item.sender_key):
                        self.store.delete_enforcement_review(item.sender_key)
                        return (
                            500,
                            {},
                            self._page("Telegram Action Failed; Item Was Not Changed"),
                        )
                self.store.decide_sender_reviews(item.sender_key, "spam")
                suppressed = self.store.suppress(
                    item.sender_key,
                    "manual_permanent_suppression",
                    until=None,
                    reference=item.reference,
                    restriction_reference=self.service.restriction_reference(
                        item.reference
                    ),
                )
                self.store.activate_enforcement_review(
                    item.sender_key,
                    "manual_permanent_suppression",
                    int(time.time())
                    + self.service.active_case_retention_days * 86400,
                )
                now = int(time.time())
                action_id = self.store.schedule_action(
                    item.sender_key,
                    reason="manual_permanent_suppression",
                    reference=item.reference,
                    execute_at=now,
                    expected_revision=suppressed.revision,
                    mode_independent=True,
                    now=now,
                )
                self.schedule_dialog_deletion(action_id, now)
                self.cancel_timeout(item.sender_key)
            elif action == "dismiss":
                self.store.decide_sender_reviews(item.sender_key, "dismissed")
            else:
                return 400, {}, self._page("Unknown Action")
            self._identity_cache.pop(item.sender_key, None)
        return 303, {"Location": "/review"}, b""

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

    def _page_version(self, target: str) -> str | None:
        parsed = urlsplit(target)
        path = parsed.path
        page = self._page_number(parsed.query)
        if page is None:
            return None
        offset = (page - 1) * PAGE_SIZE
        now = int(time.time())
        payload: object
        if path == "/":
            payload = (
                self.store.get_mode(),
                sorted(self.store.enforcement_statistics(now=now).items()),
                self.store.active_restriction_count(),
                self.store.pending_review_count(now=now),
            )
        elif path == "/review":
            if not self._page_exists(page, self.store.pending_review_count(now=now)):
                return None
            payload = [
                (
                    item.id,
                    item.updated_at,
                    item.message_count,
                    item.classification,
                    item.signals,
                )
                for item in self.store.review_items(
                    limit=PAGE_SIZE, offset=offset, now=now
                )
            ]
        elif path == "/cases":
            if not self._page_exists(page, self.store.active_restriction_count()):
                return None
            payload = [
                self._active_version(item, now)
                for item in self.store.active_restrictions(
                    limit=PAGE_SIZE, offset=offset, now=now
                )
            ]
        elif path.startswith("/review/"):
            try:
                item = self.store.review_item(int(path.removeprefix("/review/")))
            except ValueError:
                return None
            payload = (
                None
                if item is None
                else (
                    item.id,
                    item.status,
                    item.updated_at,
                    item.message_count,
                    item.reference is not None,
                    item.expires_at > now,
                )
            )
        elif path.startswith("/cases/"):
            sender_key = path.removeprefix("/cases/")
            if not sender_key or "/" in sender_key:
                return None
            item = self.store.active_restriction(sender_key, now=now)
            payload = None if item is None else self._active_version(item, now)
        else:
            return None
        serialized = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(serialized.encode("ascii")).hexdigest()[:20]

    @staticmethod
    def _active_version(
        item: ActiveRestriction, now: int | None = None
    ) -> tuple[object, ...]:
        timestamp = int(time.time()) if now is None else now
        return (
            item.sender_key,
            item.status,
            item.reason,
            item.suppressed_until,
            item.updated_at,
            item.envelope is not None,
            item.evidence_expires_at,
            item.reference is not None,
            item.suppressed_until is not None and item.suppressed_until <= timestamp,
        )

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
            <span class="risk-fill" style="width:{plotted_score}%"></span>
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
        item = self.store.active_restriction(sender_key)
        if item is None:
            return 404, {}, self._page("Active Case Not Found")
        if method == "GET":
            return await self._show_enforcement(item)
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, self._page("Method Not Allowed")
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        if not secrets.compare_digest(values.get("token", [""])[0], self._csrf_token):
            return 400, {}, self._page("Invalid Action Token")
        action = values.get("action", [""])[0]
        if action == "keep":
            self.store.audit(sender_key, "OPERATOR_KEEP", "kept", int(time.time()))
            return 303, {"Location": "/cases"}, b""
        if action != "allow":
            return 400, {}, self._page("Unknown Action")
        result = await self.restriction_actions.allow(sender_key)
        if result == RestrictionReleaseResult.NOT_ACTIVE:
            return 409, {}, self._page("This Restriction Is No Longer Active")
        if result == RestrictionReleaseResult.IDENTITY_UNAVAILABLE:
            return 409, {}, self._page("Telegram Identity Is Unavailable")
        if result == RestrictionReleaseResult.TELEGRAM_ACTION_FAILED:
            return 500, {}, self._page("Telegram Action Failed; Item Was Not Changed")
        if result != RestrictionReleaseResult.ALLOWED:
            return 500, {}, self._page("Restriction Release Failed")
        self._identity_cache.pop(sender_key, None)
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
        sender_key = self.protector.sender_key(user_id)
        async with self.service.sender_lock(sender_key):
            state = self.store.sender(sender_key)
            if state.status not in {"quarantined", "suppressed"}:
                return 409, {}, self._page("Restricted Sender Not Found")
            if state.restriction_reference is not None:
                return 409, {}, self._page("Use Allow sender in Active Cases")
            self.store.allow(sender_key)
            self.store.clear_dialog_snapshot(sender_key)
            self.cancel_timeout(sender_key)
            self._identity_cache.pop(sender_key, None)
            self.store.audit(
                sender_key,
                "OPERATOR_ALLOW_WITHOUT_RESTORE",
                "allowed",
                int(time.time()),
            )
        return 303, {"Location": "/cases"}, b""

    async def _enforcement_index_page(self, *, page: int = 1) -> bytes:
        total = self.store.active_restriction_count()
        items = self.store.active_restrictions(
            limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE
        )
        identities = await self._live_enforcement_identities(items)
        stats = self.store.enforcement_statistics()
        rows = "".join(
            "<tr>"
            f"<td data-label='Sender'>{self._identity_cell(identities.get(item.sender_key), href=f'/cases/{item.sender_key}')}</td>"
            f"<td data-label='State'><span class='badge'>{html.escape(self._human_label(item.status))}</span>"
            f"<span class='cell-note'>{html.escape(self._restriction_summary(item))}</span></td>"
            f"<td data-label='Trigger'>{html.escape(self._list_reason_label(item.reason))}</td>"
            f"<td data-label='Evidence'><span class='availability{' availability-unavailable' if item.envelope is None else ''}'>"
            f"{'Ready' if item.envelope is not None else 'Unavailable'}</span></td>"
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
            page_version=self._page_version(
                "/cases" if page == 1 else f"/cases?page={page}"
            ),
        )

    async def _show_enforcement(
        self, item: ActiveRestriction
    ) -> tuple[int, dict[str, str], bytes]:
        payload: dict[str, object] = {}
        evidence_available = False
        unavailable_note = "No message evidence is retained."
        if item.envelope is not None:
            if self.service.active_case_protector is None:
                unavailable_note = "Encrypted evidence cannot be opened by this runtime."
            else:
                try:
                    payload = self.service.active_case_protector.open(item.envelope)
                    evidence_available = True
                except ValueError:
                    unavailable_note = "Encrypted evidence failed authentication and was not shown."
                    LOG.error(
                        "active_case_evidence_invalid",
                        extra={"sender_key": item.sender_key},
                    )
        identity = "Identity unavailable"
        telegram_link = ""
        user_id: int | None = None
        if item.reference is not None:
            try:
                user_id, access_hash = self.protector.open_restriction_reference(
                    item.reference
                )
                sender = await self.telegram_client.get_entity(
                    types.InputPeerUser(user_id=user_id, access_hash=access_hash)
                )
                name, username = self._sender_name(sender)
                identity = name + (f" (@{username})" if username else "")
                telegram_link = (
                    f"<a class='telegram-link' href='tg://user?id={user_id}'>"
                    "Open this conversation in Telegram ↗</a>"
                )
            except Exception:
                LOG.info(
                    "active_case_identity_lookup_failed",
                    extra={"sender_key": item.sender_key},
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
        snapshot = self.store.dialog_snapshot(item.sender_key)
        if snapshot is not None:
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
            page_version=self._page_version(f"/cases/{item.sender_key}"),
        )

    def _peer_from_item(self, item: ReviewItem) -> types.InputPeerUser:
        if item.reference is None:
            raise ValueError("review reference has expired")
        user_id, access_hash, _ = self.protector.open_review_reference(item.reference)
        return types.InputPeerUser(user_id=user_id, access_hash=access_hash)

    async def _capture_manual_enforcement(
        self, item: ReviewItem, peer: types.InputPeerUser
    ) -> None:
        if self.service.active_case_protector is None or item.reference is None:
            return
        try:
            _, _, message_id = self.protector.open_review_reference(item.reference)
            message = await self.telegram_client.get_messages(peer, ids=message_id)
            if message is None:
                return
            facts = facts_from_message(message)
            payload: dict[str, object] = {
                "schema_version": 5,
                "text": facts.text,
                "quote_text": facts.quote_text,
                "preview_text": facts.preview_text,
                "button_texts": list(facts.button_texts[:10]),
                "urls": url_evidence(
                    facts.urls,
                    button_urls=facts.button_urls,
                    preview_urls=facts.preview_urls,
                ),
                "quote_urls": url_evidence(facts.quote_urls),
                "domains": list(facts.domains[:3]),
                "quote_domains": list(facts.quote_domains[:3]),
                "url_shape": url_shape(facts.urls),
                "quote_url_shape": url_shape(facts.quote_urls),
                "signals": json.loads(item.signals),
                "risk_score": "Manual decision",
                "challenge_profile": None,
                "planned_action": "manual_permanent_suppression",
                "decision_basis": "manual_operator_decision",
                "policy_version": "manual-review-v1",
                "features": json.loads(item.features),
            }
            now = int(time.time())
            self.store.save_enforcement_review(
                item.sender_key,
                reference=item.reference,
                envelope=self.service.active_case_protector.seal(payload),
                reason="manual_spam",
                expires_at=now + self.service.active_case_retention_days * 86400,
                now=now,
            )
        except Exception:
            LOG.error("manual_enforcement_capture_failed")

    async def _show_review(self, item: ReviewItem) -> tuple[int, dict[str, str], bytes]:
        if item.status != "pending" or item.reference is None:
            return 409, {}, self._page("This Item Is No Longer Pending")
        user_id, access_hash, message_id = self.protector.open_review_reference(
            item.reference
        )
        peer = types.InputPeerUser(user_id=user_id, access_hash=access_hash)
        message = await self.telegram_client.get_messages(peer, ids=message_id)
        sender = await self.telegram_client.get_entity(peer)
        name, username = self._sender_name(sender)
        self._cache_identity(
            item.sender_key,
            name,
            username,
            IDENTITY_CACHE_SECONDS,
        )
        identity = name + (f" (@{username})" if username else "")
        signals = self._signal_breakdown(json.loads(item.signals))
        review_reason = self._human_label(item.classification)
        features = json.dumps(json.loads(item.features), indent=2, sort_keys=True)
        observed_at = datetime.fromtimestamp(item.updated_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        if message is None:
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
                page_version=self._page_version(f"/review/{item.id}"),
            )
        text = message.message or f"[Non-text message: {type(message.media).__name__}]"
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
            page_version=self._page_version(f"/review/{item.id}"),
        )

    async def _archive_and_mute(
        self, peer: types.InputPeerUser, sender_key: str
    ) -> bool:
        archive_applied = False
        try:
            if self.store.dialog_snapshot(sender_key) is None:
                dialogs = await self.telegram_client(
                    functions.messages.GetPeerDialogsRequest(
                        [types.InputDialogPeer(peer)]
                    )
                )
                if not dialogs.dialogs:
                    raise RuntimeError("dialog state unavailable")
                dialog = dialogs.dialogs[0]
                mute_until = getattr(dialog.notify_settings, "mute_until", None)
                self.store.save_dialog_snapshot(
                    sender_key,
                    DialogSnapshot(
                        folder_id=getattr(dialog, "folder_id", None) or 0,
                        silent=bool(getattr(dialog.notify_settings, "silent", False)),
                        mute_until=(
                            int(mute_until.timestamp())
                            if isinstance(mute_until, datetime)
                            else None
                        ),
                    ),
                )
            await self.telegram_client(
                functions.folders.EditPeerFoldersRequest(
                    [types.InputFolderPeer(peer=peer, folder_id=1)]
                )
            )
            archive_applied = True
            await self.telegram_client(
                functions.account.UpdateNotifySettingsRequest(
                    peer=types.InputNotifyPeer(peer),
                    settings=types.InputPeerNotifySettings(
                        silent=True,
                        mute_until=datetime.now(timezone.utc)
                        + timedelta(days=self.mute_days),
                    ),
                )
            )
            return True
        except Exception:
            if archive_applied:
                await self._restore(peer, sender_key)
            LOG.error("review_archive_failed")
            return False

    async def _restore(self, peer: types.InputPeerUser, sender_key: str) -> bool:
        return await self.restriction_actions.restore_dialog(peer, sender_key)

    async def _dashboard_page(self) -> bytes:
        pending_reviews = self.store.pending_review_count()
        active_stats = self.store.enforcement_statistics()
        active_restrictions = active_stats["quarantined"] + active_stats["suppressed"]
        mode = self.store.get_mode()
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
            page_version=self._page_version("/"),
        )

    async def _review_queue_page(self, *, page: int = 1) -> bytes:
        total = self.store.pending_review_count()
        items = self.store.review_items(
            limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE
        )
        identities = await self._live_identities(items)
        rows = "".join(
            "<tr>"
            f"<td data-label='Sender'>{self._identity_cell(identities.get(item.id), href=f'/review/{item.id}')}</td>"
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
            page_version=self._page_version(
                "/review" if page == 1 else f"/review?page={page}"
            ),
        )

    async def _live_identities(
        self, items: list[ReviewItem]
    ) -> dict[int, LiveIdentity]:
        identities: dict[int, LiveIdentity] = {}
        uncached: list[tuple[ReviewItem, types.InputPeerUser, int]] = []
        now = time.monotonic()
        self._identity_cache = {
            sender_key: cached
            for sender_key, cached in self._identity_cache.items()
            if cached[0] > now
        }
        for item in items:
            if item.reference is None:
                continue
            try:
                user_id, access_hash, _ = self.protector.open_review_reference(
                    item.reference
                )
            except ValueError:
                continue
            cached = self._identity_cache.get(item.sender_key)
            if cached and cached[0] > now:
                identities[item.id] = LiveIdentity(user_id, cached[1], cached[2])
                continue
            uncached.append(
                (
                    item,
                    types.InputPeerUser(user_id=user_id, access_hash=access_hash),
                    user_id,
                )
            )

        for start in range(0, len(uncached), IDENTITY_BATCH_SIZE):
            batch = uncached[start : start + IDENTITY_BATCH_SIZE]
            try:
                senders = await asyncio.wait_for(
                    self.telegram_client.get_entity([peer for _, peer, _ in batch]),
                    timeout=IDENTITY_FETCH_TIMEOUT_SECONDS,
                )
                if isinstance(senders, (list, tuple)):
                    senders = list(senders)
                else:
                    senders = [senders]
            except Exception:
                senders = []
            for (item, _, user_id), sender in zip(batch, senders, strict=False):
                name, username = self._sender_name(sender)
                identities[item.id] = LiveIdentity(user_id, name, username)
                self._cache_identity(
                    item.sender_key,
                    name,
                    username,
                    IDENTITY_CACHE_SECONDS,
                )
            for item, _, user_id in batch[len(senders) :]:
                identities[item.id] = LiveIdentity(user_id, None, None)
                self._cache_identity(
                    item.sender_key,
                    None,
                    None,
                    IDENTITY_FAILURE_CACHE_SECONDS,
                )
        return identities

    async def _live_enforcement_identities(
        self, items: list[ActiveRestriction]
    ) -> dict[str, LiveIdentity]:
        identities: dict[str, LiveIdentity] = {}
        uncached: list[tuple[ActiveRestriction, types.InputPeerUser, int]] = []
        now = time.monotonic()
        self._identity_cache = {
            sender_key: cached
            for sender_key, cached in self._identity_cache.items()
            if cached[0] > now
        }
        for item in items:
            if item.reference is None:
                continue
            try:
                user_id, access_hash = self.protector.open_restriction_reference(
                    item.reference
                )
                cached = self._identity_cache.get(item.sender_key)
                if cached and cached[0] > now:
                    identities[item.sender_key] = LiveIdentity(
                        user_id, cached[1], cached[2]
                    )
                    continue
                uncached.append(
                    (
                        item,
                        types.InputPeerUser(
                            user_id=user_id,
                            access_hash=access_hash,
                        ),
                        user_id,
                    )
                )
            except ValueError:
                LOG.info(
                    "active_case_identity_reference_invalid",
                    extra={"sender_key": item.sender_key},
                )

        for start in range(0, len(uncached), IDENTITY_BATCH_SIZE):
            batch = uncached[start : start + IDENTITY_BATCH_SIZE]
            try:
                senders = await asyncio.wait_for(
                    self.telegram_client.get_entity([peer for _, peer, _ in batch]),
                    timeout=IDENTITY_FETCH_TIMEOUT_SECONDS,
                )
                if isinstance(senders, (list, tuple)):
                    senders = list(senders)
                else:
                    senders = [senders]
            except Exception:
                senders = []
            for (item, _, user_id), sender in zip(batch, senders, strict=False):
                name, username = self._sender_name(sender)
                identities[item.sender_key] = LiveIdentity(user_id, name, username)
                self._cache_identity(
                    item.sender_key, name, username, IDENTITY_CACHE_SECONDS
                )
            for item, _, user_id in batch[len(senders) :]:
                identities[item.sender_key] = LiveIdentity(user_id, None, None)
                self._cache_identity(
                    item.sender_key,
                    None,
                    None,
                    IDENTITY_FAILURE_CACHE_SECONDS,
                )
                LOG.info(
                    "active_case_identity_lookup_failed",
                    extra={"sender_key": item.sender_key},
                )
        return identities

    def _cache_identity(
        self,
        sender_key: str,
        name: str | None,
        username: str | None,
        ttl_seconds: int,
    ) -> None:
        expires_at = time.monotonic() + ttl_seconds
        self._identity_cache[sender_key] = (expires_at, name, username)
        asyncio.get_running_loop().call_later(
            ttl_seconds, self._expire_identity, sender_key, expires_at
        )

    def _expire_identity(self, sender_key: str, expires_at: float) -> None:
        cached = self._identity_cache.get(sender_key)
        if cached and cached[0] == expires_at:
            self._identity_cache.pop(sender_key, None)

    @staticmethod
    def _sender_name(sender) -> tuple[str, str | None]:
        name = (
            " ".join(
                value
                for value in (
                    getattr(sender, "first_name", None),
                    getattr(sender, "last_name", None),
                )
                if value
            )
            or "Unnamed sender"
        )
        return name, getattr(sender, "username", None)

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
    def _remaining(item: ActiveRestriction) -> str:
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
    def _restriction_summary(item: ActiveRestriction) -> str:
        if item.status == "quarantined":
            return "Review needed"
        if item.suppressed_until is None:
            return "No automatic release"
        if item.suppressed_until <= int(time.time()):
            return "Awaiting next message"
        return ReviewAdminServer._remaining(item)

    @staticmethod
    def _list_reason_label(reason: str) -> str:
        labels = {
            "challenge_timeout": "Challenge timed out",
            "timeout_notice_failed": "Timeout warning failed",
            "warning_failed": "Failure warning failed",
            "manual_permanent_suppression": "Manual suppression",
            "attempts_exhausted": "Attempts exhausted",
        }
        return labels.get(reason, ReviewAdminServer._human_label(reason))

    @staticmethod
    def _reason_label(reason: str) -> str:
        return ReviewAdminServer._human_label(reason)

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
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(document_title)}</title><style>
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:wght@300;400;500;600;700&display=swap');
:root{{--bg-primary:#181818;--bg-secondary:#202020;--bg-tertiary:#2A2A2A;--text-primary:#F2F2F2;--text-secondary:#B8B8B8;--text-muted:#8A8A8A;--border:#4A4A4A;--accent-primary:#D4D4D4;--accent-live:#60A5FA;--accent-danger:#F87171;--accent-warning:#F59E0B;--accent-info:#93C5FD;--surface-elevated:#242424;--shadow-sm:0 1px 3px rgba(0,0,0,0.35);--shadow-md:0 4px 6px rgba(0,0,0,0.45);--shadow-lg:0 10px 15px rgba(0,0,0,0.55);--font-ui:"Fira Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--font-mono:"Fira Code",SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace}}
*{{box-sizing:border-box}}body{{margin:0;overflow-x:hidden;color:var(--text-primary);background:var(--bg-primary);font:15px/1.6 var(--font-ui);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}}
.masthead,main,.back{{position:relative;max-width:1280px;margin-left:auto;margin-right:auto}}
.masthead{{display:grid;grid-template-columns:1fr auto auto auto;gap:1.5rem;align-items:center;padding:1.25rem 1.25rem 1rem;border-bottom:2px solid var(--border);background:var(--bg-secondary)}}.masthead>div{{min-width:0}}
.mark{{display:inline-grid;place-items:center;width:2.5rem;height:2.5rem;margin-right:.8rem;color:var(--bg-primary);background:var(--accent-primary);font-weight:800;letter-spacing:-.08em;border-radius:4px}}
.product{{font-size:1.15rem;font-weight:700;letter-spacing:-.01em}}.section{{font:700 .72rem/1.4 var(--font-mono);letter-spacing:.08em;text-align:right;font-variant-numeric:tabular-nums slashed-zero;text-transform:uppercase}}
.section span{{display:block;color:var(--accent-primary);font-weight:800;margin-top:.25rem}}main{{padding:2rem 1.25rem 4rem}}
.logout-form{{margin:0}}.logout-form button{{min-height:2.5rem;padding:.5rem .8rem;font-size:.75rem;background:transparent;border:1px solid var(--border);color:var(--text-secondary);transition:all 200ms ease}}.logout-form button:hover{{background:var(--bg-tertiary);color:var(--text-primary);border-color:var(--text-secondary)}}
.connection{{display:flex;align-items:center;gap:.7rem;padding:.5rem .7rem;border:1px solid var(--border);background:var(--surface-elevated);border-radius:6px}}.connection small{{display:block;margin-top:.15rem;color:var(--text-muted);font:400 .65rem/1.3 var(--font-mono);letter-spacing:.02em;font-variant-numeric:tabular-nums slashed-zero}}
.live{{display:flex;align-items:center;gap:.5rem;color:var(--accent-live);font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em}}.live i{{width:.5rem;height:.5rem;border-radius:50%;background:var(--accent-live);box-shadow:0 0 0 3px rgba(96,165,250,.2);animation:pulse 2s infinite}}
.connection[data-state="disconnected"] .live{{color:var(--accent-danger)}}.connection[data-state="disconnected"] .live i{{background:var(--accent-danger);box-shadow:0 0 0 3px rgba(239,68,68,.2);animation:none}}
@keyframes pulse{{50%{{box-shadow:0 0 0 6px transparent}}}}.refresh-control{{display:none;width:2.25rem;min-height:2.25rem;padding:0;border:1px solid var(--border);background:transparent;color:var(--text-secondary);font:800 1rem/1 var(--font-mono);cursor:pointer;border-radius:4px;transition:all 200ms ease}}
body[data-live-refresh] .refresh-control{{display:inline-flex;align-items:center;justify-content:center}}.refresh-control:hover{{background:var(--bg-tertiary);color:var(--text-primary);border-color:var(--text-primary);transform:rotate(90deg)}}.refresh-control:disabled{{opacity:.4;cursor:not-allowed}}
.queue-intro{{max-width:none;margin-bottom:2rem}}h1,h2{{font-family:var(--font-ui);line-height:1.2;letter-spacing:-.02em;font-weight:700}}.queue-intro h2{{font-size:clamp(1.75rem,3vw,2.5rem);margin:.5rem 0 1rem}}
.queue-intro p{{max-width:none;color:var(--text-secondary)}}.refresh-note{{margin-top:1rem;padding-left:1rem;border-left:3px solid var(--accent-primary);font-size:.8rem;color:var(--text-secondary)}}.eyebrow{{margin:0;text-transform:uppercase;letter-spacing:.12em;font-size:.7rem;font-weight:800;color:var(--accent-warning)}}
.metric-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin:1.5rem 0 0}}.metric-grid>div{{min-width:0;padding:1rem;border:1px solid var(--border);background:var(--bg-secondary);border-radius:8px}}.metric-grid dt{{font-size:.7rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em}}.metric-grid dd{{margin:.4rem 0 0}}.data-value{{font:700 1.2rem/1.3 var(--font-mono);font-variant-numeric:tabular-nums slashed-zero;color:var(--text-primary)}}
.table-shell{{overflow-x:auto;border:1px solid var(--border);background:var(--bg-secondary);border-radius:8px;box-shadow:var(--shadow-md)}}table{{border-collapse:collapse;width:100%;min-width:860px}}
th,td{{padding:.9rem 1rem;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}}th{{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);font-weight:700;background:var(--surface-elevated)}}tbody tr:last-child td{{border-bottom:0}}tbody tr{{transition:background 150ms ease}}tbody tr:hover{{background:var(--bg-tertiary)}}a{{color:var(--accent-info);text-decoration:none;text-underline-offset:.25em;transition:color 150ms ease}}a:hover{{color:var(--accent-primary);text-decoration:underline}}td:first-child a{{font-weight:700;color:var(--accent-primary)}}td:first-child a:hover{{color:var(--accent-info)}}
.pagination{{display:flex;justify-content:center;align-items:center;gap:1.25rem;margin:2rem 0 0;font:700 .75rem/1.4 var(--font-mono)}}.pagination a{{font-weight:800;color:var(--accent-primary);transition:color 150ms ease}}.pagination a:hover{{color:var(--accent-info)}}
.identity-name,.identity-id{{display:block}}.identity-name{{font-size:.95rem;font-weight:700}}.identity-id{{margin-top:.15rem;color:var(--text-muted);font:400 .7rem/1.3 var(--font-mono);letter-spacing:.02em;font-variant-numeric:tabular-nums slashed-zero}}
.back{{padding:1rem 1.25rem 0;font-size:.85rem}}.back a{{color:var(--text-secondary)}}.back a:hover{{color:var(--accent-primary)}}.review-grid{{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(280px,.75fr);gap:1.25rem;padding-bottom:2rem}}
.message-panel,.case-file,.decision-panel{{min-width:0;border:1px solid var(--border);background:var(--bg-secondary);padding:1.5rem;border-radius:8px;box-shadow:var(--shadow-sm)}}.message-panel h2{{font-size:1.85rem;margin:.5rem 0 1.5rem;color:var(--text-primary);overflow-wrap:anywhere}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--font-mono);font-variant-numeric:tabular-nums slashed-zero;font-size:.9rem}}pre.message{{min-height:180px;margin:0 0 1.5rem;padding:1.2rem;background:var(--bg-tertiary);color:var(--text-primary);font:.95rem/1.6 var(--font-ui);border:1px solid var(--border);border-left:3px solid var(--accent-primary);border-radius:4px}}
.content-label{{margin:1.5rem 0 .5rem;color:var(--text-muted);font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em}}pre.message.quote{{min-height:96px;background:var(--surface-elevated);border-left-color:var(--accent-warning)}}
.telegram-link{{display:inline-block;max-width:100%;font-weight:700;color:var(--accent-info);overflow-wrap:anywhere;margin-top:1rem;transition:color 150ms ease}}.telegram-link:hover{{color:var(--accent-primary)}}
dt{{font-size:.68rem;text-transform:uppercase;letter-spacing:.09em;color:var(--text-muted);font-weight:700}}dd{{margin:.25rem 0 1rem;color:var(--text-secondary);overflow-wrap:anywhere}}
.badge{{display:inline-block;max-width:100%;padding:.25rem .5rem;background:var(--bg-tertiary);border:1px solid var(--accent-warning);color:var(--accent-warning);font-weight:700;font-size:.75rem;border-radius:4px;overflow-wrap:anywhere}}
.policy-map{{margin:.5rem 0 1.5rem;padding:1.2rem;border:1px solid var(--border);background:var(--surface-elevated);border-radius:8px;box-shadow:var(--shadow-sm)}}.policy-score-head{{display:flex;align-items:flex-start;justify-content:space-between;gap:.75rem}}.policy-score-head>div{{display:grid;grid-template-columns:auto 1fr;align-items:end;column-gap:.5rem}}.policy-kicker{{grid-column:1/-1;color:var(--text-muted);font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em}}.policy-score-head strong{{font:800 2.2rem/.95 var(--font-mono);letter-spacing:-.06em;color:var(--text-primary)}}.policy-score-head small{{padding-bottom:.15rem;color:var(--text-muted);font-size:.65rem}}.policy-version{{padding:.2rem .4rem;border:1px solid var(--border);background:var(--bg-tertiary);color:var(--text-muted);font:700 .6rem/1.3 var(--font-mono);letter-spacing:.04em;border-radius:4px}}
.risk-track{{position:relative;height:.8rem;margin:1rem 0 3rem;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:4px}}.risk-fill{{display:block;height:100%;background:var(--accent-warning);border-radius:4px}}.risk-mark{{position:absolute;top:-.3rem;width:2px;height:1.4rem;background:var(--text-secondary)}}.risk-mark i,.risk-mark b{{position:absolute;left:50%;transform:translateX(-50%);white-space:nowrap;font-family:var(--font-mono);font-style:normal}}.risk-mark i{{top:1.5rem;font-size:.65rem;font-weight:800;color:var(--text-primary)}}.risk-mark b{{top:2.4rem;color:var(--text-muted);font-size:.56rem;text-transform:uppercase;letter-spacing:.05em}}.strict-mark{{left:30%}}.permanent-mark{{left:70%;background:var(--accent-danger)}}.permanent-mark i{{color:var(--accent-danger)}}
.gate-formula{{margin:0 0 .75rem;color:var(--text-muted);font-size:.72rem}}.gate-check{{display:grid;grid-template-columns:1.8rem minmax(0,1fr);gap:.65rem;padding:.8rem;border:1px solid var(--border);background:var(--bg-tertiary);border-radius:6px}}.gate-check+.gate-check{{margin-top:.6rem}}.gate-symbol{{display:grid;place-items:center;width:1.8rem;height:1.8rem;border-radius:50%;font:900 .9rem/1 var(--font-mono)}}.gate-check small,.policy-outcome small{{display:block;color:var(--text-muted);font:700 .6rem/1.4 var(--font-mono);text-transform:uppercase;letter-spacing:.07em}}.gate-check strong{{display:block;margin:.2rem 0 0;font-size:.75rem;line-height:1.4;color:var(--text-primary)}}.gate-check p{{margin:.3rem 0 0;color:var(--text-secondary);font-size:.68rem;line-height:1.5}}
.gate-check.met{{border-left:3px solid var(--accent-primary)}}.gate-check.met .gate-symbol{{background:rgba(34,197,94,.2);color:var(--accent-primary)}}.gate-check.unmet{{border-left:3px solid var(--accent-danger)}}.gate-check.unmet .gate-symbol{{background:rgba(239,68,68,.2);color:var(--accent-danger)}}.policy-outcome{{margin-top:.8rem;padding:.9rem;border:1px solid var(--border);background:var(--bg-tertiary);border-radius:6px}}.policy-outcome strong{{display:block;margin:.2rem 0 0;font-size:1rem;color:var(--text-primary)}}.policy-outcome p{{margin:.4rem 0 0;color:var(--text-secondary);font-size:.72rem;line-height:1.5}}.policy-outcome.strict{{border-left:3px solid var(--accent-warning)}}.policy-outcome.permanent{{border-left:3px solid var(--accent-danger)}}.policy-outcome.standard{{border-left:3px solid var(--accent-primary)}}
.signal-breakdown{{margin-top:.6rem}}.signal-list{{display:grid;gap:.7rem;margin:0 0 1.25rem;padding:0;list-style:none;counter-reset:evidence-signal}}.signal-item{{counter-increment:evidence-signal;display:grid;grid-template-columns:2rem minmax(0,1fr);gap:.7rem;padding:.85rem;background:var(--bg-tertiary);border:1px solid var(--border);border-left:3px solid var(--accent-warning);border-radius:6px}}.signal-index{{display:grid;place-items:center;align-self:start;width:2rem;height:2rem;background:var(--surface-elevated);color:var(--text-primary);font:700 .68rem/1 var(--font-mono);border-radius:4px}}.signal-index:before{{content:counter(evidence-signal,decimal-leading-zero)}}.signal-copy{{min-width:0}}.signal-heading{{display:flex;align-items:flex-start;justify-content:space-between;gap:.6rem}}.signal-heading strong{{font-size:.85rem;line-height:1.4;color:var(--text-primary)}}.signal-score{{flex:0 0 auto;padding:.2rem .4rem;background:var(--accent-warning);color:var(--bg-primary);font:800 .7rem/1.2 var(--font-mono);font-variant-numeric:tabular-nums;border-radius:4px}}.signal-source{{display:inline-block;margin-top:.4rem;padding:.15rem .35rem;border:1px solid var(--border);background:var(--surface-elevated);color:var(--text-muted);font:700 .66rem/1.3 var(--font-mono);text-transform:uppercase;letter-spacing:.08em;border-radius:4px}}.signal-explanation{{margin:.5rem 0 0;color:var(--text-secondary);font-size:.78rem;line-height:1.5}}.empty-value{{color:var(--text-muted)}}
details{{border-top:1px solid var(--border);padding-top:1rem;margin-top:1rem}}summary{{cursor:pointer;font-weight:700;color:var(--text-secondary);transition:color 150ms ease}}summary:hover{{color:var(--text-primary)}}details pre{{font-size:.75rem;color:var(--text-secondary);background:var(--bg-tertiary);padding:.8rem;border-radius:4px;margin-top:.5rem}}
.decision-panel{{position:relative;width:calc(100% - 2.5rem);max-width:1080px;margin:0 auto 3rem;border:1px solid var(--border);border-top:3px solid var(--accent-primary);background:var(--bg-secondary);padding:1.5rem;border-radius:8px}}.decision-panel h2{{font-size:1.6rem;margin-bottom:.5rem;color:var(--text-primary)}}
.actions{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.8rem;margin-top:1.5rem}}.actions form{{display:flex;min-width:0}}button,.button-link{{display:inline-flex;align-items:center;justify-content:center;min-height:3rem;padding:.8rem 1rem;border:1px solid var(--border);background:var(--surface-elevated);color:var(--text-primary);font:700 .8rem/1.35 var(--font-ui);cursor:pointer;transition:all 200ms ease;white-space:normal;overflow-wrap:anywhere;border-radius:6px}}button{{width:100%}}button:hover,.button-link:hover{{background:var(--bg-tertiary);border-color:var(--accent-primary);color:var(--accent-primary);transform:translateY(-1px)}}button.danger{{background:var(--accent-danger);color:var(--text-primary);border-color:var(--accent-danger)}}button.danger:hover{{background:#DC2626;border-color:#DC2626}}
.actions>button{{width:100%}}button:disabled{{cursor:not-allowed;opacity:.4;border-color:var(--border);background:var(--bg-tertiary)}}.live-change-notice{{position:relative;max-width:1080px;margin:1rem auto 0;padding:1rem 1.25rem;border:1px solid var(--accent-warning);border-left:4px solid var(--accent-warning);background:var(--bg-secondary);color:var(--text-primary);border-radius:6px}}.live-change-notice[hidden]{{display:none}}
.actions.two{{grid-template-columns:repeat(2,minmax(0,1fr))}}.actions.one{{grid-template-columns:minmax(0,24rem)}}
.notice,.empty-state{{margin:1.5rem 0;padding:1.3rem;border:1px solid var(--border);border-left:4px solid var(--accent-warning);background:var(--bg-tertiary);border-radius:6px}}.notice strong,.empty-state strong{{color:var(--accent-warning)}}.empty-state p{{margin:.6rem 0 0;color:var(--text-secondary)}}
.manual-release{{display:grid;grid-template-columns:minmax(12rem,1fr) minmax(16rem,1.4fr);gap:.8rem;align-items:end;margin-top:1.5rem}}.manual-release label{{grid-column:1/-1;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text-muted)}}.manual-release input{{min-height:3rem;width:100%;padding:.8rem 1rem;border:1px solid var(--border);background:var(--bg-tertiary);color:var(--text-primary);font:700 .9rem/1.35 var(--font-mono);border-radius:6px;transition:border-color 200ms ease}}.manual-release input:focus{{border-color:var(--accent-primary);outline:none;box-shadow:0 0 0 3px rgba(34,197,94,.1)}}
.error-layout{{display:grid;place-items:center;min-height:calc(100vh - 8rem);padding-top:2rem}}.error-card{{width:min(100%,680px);padding:clamp(1.5rem,5vw,3rem);border:1px solid var(--border);border-top:4px solid var(--accent-danger);background:var(--bg-secondary);border-radius:8px;box-shadow:var(--shadow-lg)}}.error-content{{width:100%;text-align:left}}.error-card h1{{margin:.6rem 0 1rem;font-size:clamp(2rem,6vw,3.2rem);color:var(--text-primary)}}.error-content>p:not(.eyebrow){{color:var(--text-secondary)}}.error-command{{margin:1.5rem 0}}code{{padding:.25rem .45rem;background:var(--bg-tertiary);border:1px solid var(--border);font:600 .85rem/1.5 var(--font-mono);font-variant-numeric:tabular-nums slashed-zero;border-radius:4px;color:var(--accent-primary)}}.button-link{{margin-top:.75rem;text-decoration:none}}
.masthead,.back{{max-width:1280px}}main.list-main{{max-width:1280px}}.masthead{{gap:1.5rem;padding:1.25rem 1.25rem .9rem}}main{{padding:1.5rem 1.25rem 3rem}}
.queue-intro{{margin-bottom:1.25rem}}.compact-intro .lede{{margin:.45rem 0 0;color:var(--text-secondary);font-size:1rem}}.metric-grid{{gap:.7rem;margin-top:1.2rem}}.metric-grid>div{{padding:.8rem .9rem}}.metric-grid dd{{margin-top:.2rem}}
.context-note{{margin-top:.8rem;padding:.7rem .9rem;border:1px solid var(--border);background:var(--surface-elevated);border-radius:6px}}.context-note summary{{font-size:.76rem}}.context-note p{{margin:.6rem 0 0;font-size:.76rem;color:var(--text-secondary)}}
.table-shell{{box-shadow:var(--shadow-md)}} .data-table{{table-layout:fixed}}.data-table th,.data-table td{{padding:.7rem .85rem;vertical-align:middle}}.cases-table th:nth-child(1){{width:27%}}.cases-table th:nth-child(2){{width:19%}}.cases-table th:nth-child(3){{width:30%}}.cases-table th:nth-child(4){{width:15%}}.cases-table th:nth-child(5){{width:9%}}.reviews-table th:nth-child(1){{width:28%}}.reviews-table th:nth-child(2){{width:23%}}.reviews-table th:nth-child(3){{width:31%}}.reviews-table th:nth-child(4){{width:10%}}.reviews-table th:nth-child(5){{width:8%}}
.identity-link{{font-weight:800;color:var(--accent-primary)}}.identity-link:hover{{color:var(--accent-info)}}.identity-name,.identity-id,.cell-note{{display:block}}.identity-name{{font-size:.92rem;overflow-wrap:anywhere}}.identity-id,.cell-note{{margin-top:.12rem;color:var(--text-muted);font:400 .68rem/1.35 var(--font-mono);letter-spacing:.02em;font-variant-numeric:tabular-nums}}.cell-note{{line-height:1.25}}.age,.numeric{{font-family:var(--font-mono);font-variant-numeric:tabular-nums}}.availability{{font-weight:700}}.availability-unavailable{{color:var(--accent-danger)}}
.badge{{padding:.1rem .45rem;white-space:nowrap;overflow-wrap:normal}}.message-panel,.case-file,.decision-panel{{padding:clamp(1.2rem,3vw,1.8rem)}}.message-panel h2{{font-size:1.7rem;margin:.4rem 0 1.2rem}}.decision-panel{{margin-bottom:3rem}}.decision-panel h2{{font-size:1.35rem}}
.advanced-recovery-wrap{{position:relative;width:calc(100% - 2.5rem);max-width:1255px;margin:0 auto 3rem}}.advanced-recovery{{padding:.9rem 1rem;border:1px solid var(--border);background:var(--bg-secondary);border-radius:6px}}.advanced-recovery summary{{display:flex;justify-content:space-between;gap:1rem;font-size:.8rem}}.advanced-recovery summary span{{color:var(--accent-danger);font:700 .7rem/1.4 var(--font-mono)}}.advanced-recovery-content{{padding:1.2rem .25rem .25rem}}.advanced-recovery-content h2{{font-size:1.35rem;margin:.45rem 0 .7rem;color:var(--text-primary)}}.advanced-recovery-content p:not(.eyebrow){{color:var(--text-secondary)}}
.area-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}}.area-card{{position:relative;display:grid;gap:.5rem;min-height:10rem;padding:1.25rem 5rem 1.25rem 1.25rem;border:1px solid var(--border);background:var(--bg-secondary);text-decoration:none;border-radius:8px;transition:all 200ms ease}}.area-card strong{{font-size:1.35rem;color:var(--text-primary)}}.area-card>span:not(.eyebrow){{color:var(--text-secondary)}}.area-card b{{position:absolute;right:1.25rem;top:1.1rem;font:800 1.5rem/1 var(--font-mono);color:var(--accent-primary)}}.area-card:hover{{background:var(--bg-tertiary);border-color:var(--accent-primary);transform:translateY(-2px);box-shadow:var(--shadow-md)}}
button.danger{{border-color:var(--accent-danger)}}a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible{{outline:2px solid var(--accent-primary);outline-offset:3px;border-radius:4px}}
@media(max-width:760px){{.masthead{{grid-template-columns:1fr auto auto;gap:1rem}}.connection{{grid-column:1/-1;grid-row:2}}.logout-form{{grid-column:3;grid-row:1}}.review-grid{{grid-template-columns:1fr}}.section{{max-width:100%}}main{{padding-top:1.25rem}}.actions,.metric-grid,.manual-release,.area-grid{{grid-template-columns:1fr}}.table-shell{{overflow:visible;border:0;background:transparent;box-shadow:none}}.data-table{{display:block;min-width:0}}.data-table thead{{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}}.data-table tbody{{display:grid;gap:.75rem}}.data-table tr{{display:grid;border:1px solid var(--border);background:var(--bg-secondary);border-radius:6px}}.data-table td{{display:grid;grid-template-columns:minmax(6rem,.4fr) minmax(0,1fr);gap:.75rem;padding:.7rem .8rem;border-bottom:1px solid var(--border);overflow-wrap:anywhere}}.data-table td:before{{content:attr(data-label);color:var(--text-muted);font:700 .65rem/1.4 var(--font-mono);letter-spacing:.08em;text-transform:uppercase}}.data-table td:last-child{{border-bottom:0}}.data-table .empty-row td{{display:block}}.data-table .empty-row td:before{{display:none}}.area-card{{min-height:8rem;padding-right:1.25rem}}.area-card b{{position:static;display:block;margin-top:.5rem}}}}
button.danger{{color:var(--bg-primary)}}button.danger:hover{{background:#FCA5A5;border-color:#FCA5A5}}
/* Keep dense list rows neutral; reserve semantic colors for decisions and actions. */
.data-table .identity-link,.data-table td:first-child a{{color:var(--text-primary)}}
.data-table .identity-link:hover,.data-table td:first-child a:hover{{color:var(--accent-info)}}
.data-table .badge{{background:var(--surface-elevated);border-color:var(--border);color:var(--text-secondary)}}
.data-table .availability-unavailable{{color:var(--text-secondary)}}
.mark{{background:var(--surface-elevated);color:var(--text-primary);border:1px solid var(--border)}}
@media(prefers-reduced-motion:reduce){{*,*:before,*:after{{scroll-behavior:auto!important;animation-duration:0.01ms!important;animation-iteration-count:1!important;transition-duration:0.01ms!important}}button:hover,.button-link:hover,.area-card:hover{{transform:none}}.live i{{animation:none}}}}
</style>{dashboard_script}</head><body{live_attributes}>{body}</body></html>""".encode("utf-8")
