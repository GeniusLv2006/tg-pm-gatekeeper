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
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit, urlunsplit

from telethon import functions, types

from .message_facts import facts_from_message
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
    document.querySelectorAll('form button').forEach((button) => {
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
        restriction_actions: RestrictionActions | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.store = store
        self.service = service
        self.protector = service.protector
        self.telegram_client = telegram_client
        self.mute_days = mute_days
        self.cancel_timeout = cancel_timeout
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
        if parsed.path == "/login":
            token = parse_qs(parsed.query).get("token", [""])[0]
            if not secrets.compare_digest(token, self._access_token):
                return 400, {}, self._page("Invalid Access Token")
            self._access_token = secrets.token_urlsafe(32)
            self._capability_token = secrets.token_urlsafe(32)
            self._write_access_token()
            return 303, {"Location": f"/{self._capability_token}/"}, b""
        logical_path = self._logical_path(parsed.path)
        if logical_path is None:
            return 404, {}, self._page("Dashboard Access Missing")
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
                    self.store.quarantine(
                        item.sender_key,
                        restriction_reference=self.service.restriction_reference(
                            item.reference
                        ),
                    )
                elif state.status == "challenged":
                    self.store.quarantine(
                        item.sender_key,
                        restriction_reference=self.service.restriction_reference(
                            item.reference
                        ),
                    )
                if self.store.sender(item.sender_key).status == "quarantined":
                    self.store.activate_enforcement_review(
                        item.sender_key,
                        "manual_spam",
                        int(time.time())
                        + self.service.active_case_retention_days * 86400,
                    )
                self.cancel_timeout(item.sender_key)
                self.store.decide_sender_reviews(item.sender_key, "spam")
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
                    item.rule_codes,
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
                "Review any available URLs, button text, matched HR rules, and structural "
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
    def _severity_label(payload: dict[str, object], reason: str) -> str:
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
                return 409, {}, self._page("Use Active Case Allow Now")
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
            f"<tr><td><a href='/cases/{item.sender_key}'>Open</a></td>"
            f"<td>{self._identity_cell(identities.get(item.sender_key))}</td>"
            f"<td><span class='badge'>{html.escape(self._human_label(item.status))}</span></td>"
            f"<td>{html.escape(self._human_label(item.reason))}</td>"
            f"<td>{html.escape(self._remaining(item))}</td>"
            f"<td>{'Available' if item.envelope is not None else 'Expired or unavailable'}</td>"
            f"<td>{html.escape(self._relative_age(item.updated_at))}</td></tr>"
            for item in items
        ) or "<tr><td colspan='7'>No active restrictions.</td></tr>"
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
        content = (
            self._masthead("Active Cases", f"{total} Restrictions")
            + "<p class='back'><a href='/'>← Operations Dashboard</a> · <a href='/review'>Pending Reviews</a></p>"
            + "<main data-live-region='active-cases'><section class='queue-intro'><p class='eyebrow'>Protect Mode State</p>"
            + "<h2>Review Active Restrictions</h2>"
            + "<p>Every restriction remains manageable for its full lifetime. Encrypted evidence is retained separately for short-term review. Telegram block is not used.</p>"
            + "<dl class='metric-grid'>"
            + f"<div><dt>Quarantined</dt><dd class='data-value'>{stats['quarantined']}</dd></div>"
            + f"<div><dt>Suppressed</dt><dd class='data-value'>{stats['suppressed']}</dd></div>"
            + f"<div><dt>Reviewable Evidence</dt><dd class='data-value'>{stats['reviewable']}</dd></div></dl>"
            + f"<p class='refresh-note'><strong>State Reasons:</strong> {reasons}. {snapshot_note}{identity_note}</p></section>"
            + "<div class='table-shell'><table><thead><tr><th>Case</th><th>Sender</th><th>Status</th><th>Reason</th><th>Restriction</th><th>Evidence</th><th>Updated</th></tr></thead>"
            + f"<tbody>{rows}</tbody></table></div>"
            + self._pagination("/cases", page, total)
            + "</main>"
            + "<section class='decision-panel' data-live-region='legacy-recovery'><p class='eyebrow'>Legacy Recovery</p>"
            + "<h2>Allow an unidentified restricted sender by Telegram User ID</h2>"
            + "<p>Use this only for a legacy restriction created before encrypted control "
            + "identities were retained. This removes the "
            + "Gatekeeper restriction and cancels pending deletion jobs, but cannot restore "
            + "saved Telegram folder or notification state without a peer reference. "
            + "The entered ID is used only to "
            + "derive the existing sender key and is not stored.</p>"
            + "<form class='manual-release' method='post' action='/cases/release'>"
            + f"<input type='hidden' name='token' value='{self._csrf_token}'>"
            + "<label for='release-user-id'>Telegram User ID</label>"
            + "<input id='release-user-id' name='user_id' type='text' inputmode='numeric' "
            + "pattern='[0-9]+' autocomplete='off' required>"
            + "<button class='danger' type='submit'>Allow Future Messages Without Restore</button>"
            + "</form></section>"
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
        rules = ", ".join(
            self._human_label(str(value)) for value in payload.get("rule_codes", [])
        ) or "—"
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
                item.sender_key, "allow", "Allow Now", base="cases"
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
        release_pending = (
            item.status == "suppressed"
            and item.suppressed_until is not None
            and item.suppressed_until <= int(time.time())
        )
        keep_label = (
            "Record Without Extending Restriction"
            if release_pending
            else "Leave Restriction Unchanged"
        )
        content = f"""
        {self._masthead("Active Cases", self._human_label(item.status))}
        <p class="back"><a href="/cases">← Active Cases</a></p>
        {self._change_notice()}
        <main class="review-grid"><section class="message-panel">
          <p class="eyebrow">{evidence_heading}</p>
          <h2>{html.escape(identity)}</h2>
          <p class="refresh-note">{evidence_note}</p>
          {evidence_content}
          {telegram_link}
        </section><aside class="case-file"><p class="eyebrow">Restriction Details</p>
          <dl><dt>Status</dt><dd><span class="badge">{html.escape(self._human_label(item.status))}</span></dd>
          <dt>Restriction Cause</dt><dd>{html.escape(self._human_label(item.reason))}</dd>
          <dt>Severity</dt><dd>{html.escape(self._severity_label(payload, item.reason))}</dd>
          <dt>Matched HR Rules</dt><dd>{html.escape(rules)}</dd>
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
                "schema_version": 4,
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
                "severity": "manual",
                "policy": "manual_review",
                "rule_codes": json.loads(item.rule_codes),
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
        rules = ", ".join(
            self._human_label(value) for value in json.loads(item.rule_codes)
        ) or "Ordinary Unknown Sender"
        review_reason = self._human_label(item.classification)
        features = json.dumps(json.loads(item.features), indent=2, sort_keys=True)
        observed_at = datetime.fromtimestamp(item.updated_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        if message is None:
            content = f"""
            {self._masthead("Review Item", f"Review #{item.id}")}
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
                <dt>Matched HR Rules</dt><dd>{html.escape(rules)}</dd>
                <dt>Messages Observed</dt><dd>{item.message_count}</dd>
                <dt>Last Observed</dt><dd>{observed_at}</dd></dl>
              </aside>
            </main>
            <section class="decision-panel"><p class="eyebrow">Resolve Local Record</p>
              <h2>Remove this sender's pending review and cancel pending Gatekeeper deletion jobs. Telegram and trust state are unchanged.</h2>
              <div class="actions one">
                {self._action_form(item.id, "dismiss", "Resolve and Cancel Pending Jobs")}
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
        {self._masthead("Review Item", f"Review #{item.id}")}
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
            <dt>Matched HR Rules</dt><dd>{html.escape(rules)}</dd>
            <dt>Telegram ID</dt><dd>{user_id}</dd>
            <dt>Messages Observed</dt><dd>{item.message_count}</dd>
            <dt>Last Observed</dt><dd>{observed_at}</dd></dl>
            <details><summary>Structural Features</summary><pre>{html.escape(features)}</pre></details>
          </aside>
        </main>
        <section class="decision-panel"><p class="eyebrow">Sender Decision</p>
          <h2>This decision applies to all pending entries for this sender.</h2>
          <div class="actions">
            {self._action_form(item.id, "legitimate", "Legitimate · Allow Sender")}
            {self._action_form(item.id, "spam", "Spam · Archive and Mute", danger=True)}
            {self._action_form(item.id, "dismiss", "Dismiss and Cancel Pending Jobs")}
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
            LOG.error("review_quarantine_failed")
            return False

    async def _restore(self, peer: types.InputPeerUser, sender_key: str) -> bool:
        return await self.restriction_actions.restore_dialog(peer, sender_key)

    async def _dashboard_page(self) -> bytes:
        pending_reviews = self.store.pending_review_count()
        active_stats = self.store.enforcement_statistics()
        active_restrictions = active_stats["quarantined"] + active_stats["suppressed"]
        mode = self.store.get_mode()
        content = (
            self._masthead("Operations Dashboard", mode.title())
            + "<main data-live-region='operations'><section class='queue-intro'><p class='eyebrow'>Operator Overview</p>"
            "<h2>Operations Dashboard</h2>"
            "<p>Use Active Cases for recovery after a possible false positive. "
            "Pending Reviews cover monitor-mode simulations and protect-mode exceptions.</p>"
            "<dl class='metric-grid'>"
            f"<div><dt>Active Restrictions</dt><dd class='data-value'>{active_restrictions}</dd></div>"
            f"<div><dt>Reviewable Cases</dt><dd class='data-value'>{active_stats['reviewable']}</dd></div>"
            f"<div><dt>Pending Reviews</dt><dd class='data-value'>{pending_reviews}</dd></div>"
            "</dl></section>"
            "<div class='table-shell'><table><thead><tr><th>Area</th><th>Purpose</th><th>Open</th></tr></thead><tbody>"
            "<tr><td>Active Cases</td><td>Review every current restriction; evidence availability is shown separately.</td><td><a href='/cases'>Open</a></td></tr>"
            "<tr><td>Pending Reviews</td><td>Resolve monitor-mode simulations and protect-mode exception reviews.</td><td><a href='/review'>Open</a></td></tr>"
            "</tbody></table></div></main>"
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
            f"<tr><td><a href='/review/{item.id}'>#{item.id}</a></td>"
            f"<td>{self._identity_cell(identities.get(item.id))}</td>"
            f"<td>{html.escape(self._human_label(item.classification))}</td>"
            f"<td>{html.escape(', '.join(self._human_label(value) for value in json.loads(item.rule_codes)) or '—')}</td>"
            f"<td>{item.message_count}</td>"
            f"<td>{html.escape(self._relative_age(item.updated_at))}</td></tr>"
            for item in items
        )
        if not rows:
            rows = "<tr><td colspan='6'>No pending reviews.</td></tr>"
        return self._page(
            self._masthead("Pending Reviews", f"{total} Pending")
            + "<p class='back'><a href='/'>← Operations Dashboard</a> · <a href='/cases'>Active Cases</a></p>"
            + "<main data-live-region='pending-reviews'><section class='queue-intro'><p class='eyebrow'>Pending Reviews</p>"
            "<h2>Review Pending Senders</h2>"
            "<p>Sender identity is fetched from Telegram and cached briefly in memory. "
            "Message content is fetched only when a review item is opened.</p>"
            "<p>Deleting a conversation in Telegram does not remove its local pending review. "
            "Open the row and resolve it when the referenced message is unavailable.</p>"
            "<p class='refresh-note'>Connection health is checked quietly while this tab is visible. "
            "The table updates in place only when review state changes.</p></section>"
            "<div class='table-shell'><table><thead><tr><th>Case</th><th>Sender</th><th>Review Reason</th>"
            "<th>Matched HR Rules</th><th>Messages</th>"
            f"<th>Last Seen</th></tr></thead><tbody>{rows}</tbody></table></div>"
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
    def _identity_cell(identity: LiveIdentity | None) -> str:
        if identity is None:
            return "<span class='identity-name'>Identity unavailable</span>"
        if identity.name is None:
            label = "Name unavailable"
        else:
            label = identity.name + (
                f" (@{identity.username})" if identity.username else ""
            )
        return (
            f"<span class='identity-name'>{html.escape(label)}</span>"
            f"<span class='identity-id'>ID {identity.user_id}</span>"
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
    def _masthead(section: str, status: str) -> str:
        checked_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
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
            "</header>"
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
                    "This address does not contain a valid dashboard capability. Run the "
                    "tunnel helper again and open its new one-time link."
                ),
                "Request Failed": (
                    "The request could not be completed. No dashboard action was confirmed."
                ),
            }.get(content, "Check the request and return to the dashboard.")
            return_action = (
                ""
                if content in {"Invalid Access Token", "Dashboard Access Missing"}
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
:root{{--ink:#17211d;--muted:#68726c;--paper:#f3efe5;--panel:#fffdf7;--line:#c9c3b5;--signal:#d84a28;--safe:#1e6b52;--font-ui:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--font-data:SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace}}
*{{box-sizing:border-box}}body{{margin:0;color:var(--ink);background:var(--paper);font:15px/1.55 var(--font-ui)}}
body:before{{content:"";position:fixed;inset:0;pointer-events:none;opacity:.18;background-image:repeating-linear-gradient(90deg,transparent 0 47px,#8f8878 48px),repeating-linear-gradient(0deg,transparent 0 47px,#8f8878 48px)}}
.masthead,main,.back{{position:relative;max-width:1120px;margin-left:auto;margin-right:auto}}
.masthead{{display:grid;grid-template-columns:1fr auto auto;gap:2.5rem;align-items:center;padding:2rem 1.25rem 1.1rem;border-bottom:2px solid var(--ink)}}.masthead>div{{min-width:0}}
.mark{{display:inline-grid;place-items:center;width:2.5rem;height:2.5rem;margin-right:.8rem;color:var(--paper);background:var(--ink);font-weight:800;letter-spacing:-.08em}}
.product{{font-size:1.15rem;font-weight:750;letter-spacing:-.01em}}.section{{text-transform:uppercase;font:700 .72rem/1.4 var(--font-data);letter-spacing:.08em;text-align:right;font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}
.section span{{display:block;color:var(--signal);font-weight:800;margin-top:.25rem}}main{{padding:3rem 1.25rem 5rem}}
.connection{{display:flex;align-items:center;gap:.7rem;padding:.5rem .55rem .5rem .75rem;border:1px solid var(--line);background:var(--panel)}}.connection small{{display:block;margin-top:.2rem;color:var(--muted);font:400 .65rem/1.4 var(--font-data);letter-spacing:.03em;font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}.live{{display:flex;align-items:center;gap:.5rem;color:var(--safe);font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em}}.live i{{width:.55rem;height:.55rem;border-radius:50%;background:#2cab76;box-shadow:0 0 0 4px #d8f0e6;animation:pulse 2s infinite}}.connection[data-state="disconnected"] .live{{color:var(--signal)}}.connection[data-state="disconnected"] .live i{{background:var(--signal);box-shadow:0 0 0 4px #f7d8cf;animation:none}}@keyframes pulse{{50%{{box-shadow:0 0 0 7px transparent}}}}.refresh-control{{display:none;width:2rem;min-height:2rem;padding:0;border-color:var(--line);box-shadow:none;font:800 1rem/1 var(--font-data)}}body[data-live-refresh] .refresh-control{{display:inline-flex}}.refresh-control:hover{{transform:none;box-shadow:none;border-color:var(--ink)}}.refresh-control:disabled{{opacity:.45}}
.queue-intro{{max-width:none;margin-bottom:2.5rem}}h1,h2{{font-family:var(--font-ui);line-height:1.12;letter-spacing:-.025em}}.queue-intro h2{{font-size:clamp(1.85rem,3.6vw,3rem);font-weight:720;margin:.55rem 0 1rem}}
.queue-intro p{{max-width:none;color:var(--muted)}}.refresh-note{{margin-top:1.2rem;padding-left:1rem;border-left:3px solid var(--safe);font-size:.78rem}}.eyebrow{{margin:0;text-transform:uppercase;letter-spacing:.13em;font-size:.7rem;font-weight:800;color:var(--signal)}}
.metric-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin:2rem 0 0}}.metric-grid>div{{min-width:0;padding:1rem;border:1px solid var(--line);background:rgba(255,253,247,.72)}}.metric-grid dd{{margin:.45rem 0 0}}.data-value{{font:700 1.15rem/1.35 var(--font-data);font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}
.table-shell{{overflow-x:auto;border:1px solid var(--line);background:var(--panel);box-shadow:8px 8px 0 var(--ink)}}table{{border-collapse:collapse;width:100%;min-width:860px}}
th,td{{padding:1rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}}tbody tr:last-child td{{border-bottom:0}}tbody tr:hover{{background:#f8e9d8}}a{{color:var(--ink);text-underline-offset:.22em}}td:first-child a{{font-weight:900;color:var(--signal)}}
.pagination{{display:flex;justify-content:center;align-items:center;gap:1.25rem;margin:2rem 0 0;font:700 .75rem/1.4 var(--font-data)}}.pagination a{{font-weight:800}}
.identity-name,.identity-id{{display:block}}.identity-name{{font-size:1rem;font-weight:700}}.identity-id{{margin-top:.2rem;color:var(--muted);font:400 .7rem/1.4 var(--font-data);letter-spacing:.02em;font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}
.back{{padding:1.25rem 1.25rem 0}}.review-grid{{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(280px,.75fr);gap:1.5rem;padding-bottom:2rem}}
.message-panel,.case-file,.decision-panel{{min-width:0;border:1px solid var(--line);background:var(--panel);padding:clamp(1.25rem,4vw,2.4rem)}}.message-panel h2{{font-size:2rem;margin:.5rem 0 1.8rem;overflow-wrap:anywhere}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--font-data);font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}pre.message{{min-height:180px;margin:0 0 1.5rem;padding:1.4rem;background:var(--ink);color:#f7f1df;font:1rem/1.65 var(--font-ui);border-left:5px solid var(--signal)}}
.content-label{{margin:1.5rem 0 .55rem;color:var(--muted);font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.09em}}pre.message.quote{{min-height:96px;background:#27332e;border-left-color:#b88836}}
.telegram-link{{display:inline-block;max-width:100%;font-weight:800;overflow-wrap:anywhere}}dt{{font-size:.66rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}}dd{{margin:.2rem 0 1.2rem;overflow-wrap:anywhere}}.badge{{display:inline-block;max-width:100%;padding:.2rem .45rem;background:#f8e9d8;border:1px solid var(--signal);color:#9d3118;font-weight:800;overflow-wrap:anywhere}}
details{{border-top:1px solid var(--line);padding-top:1rem}}summary{{cursor:pointer;font-weight:800}}details pre{{font-size:.75rem;color:var(--muted)}}.decision-panel{{position:relative;width:calc(100% - 2.5rem);max-width:1080px;margin:0 auto 4rem;border-top:5px solid var(--ink)}}.decision-panel h2{{font-size:1.7rem;margin-bottom:0}}
.actions{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin-top:1.5rem}}.actions form{{display:flex;min-width:0}}button,.button-link{{display:inline-flex;align-items:center;justify-content:center;min-height:3.25rem;padding:.8rem 1rem;border:1px solid var(--ink);background:transparent;color:var(--ink);font:700 .78rem/1.35 var(--font-ui);cursor:pointer;box-shadow:3px 3px 0 var(--ink);transition:transform .12s,box-shadow .12s;white-space:normal;overflow-wrap:anywhere}}button{{width:100%}}button:hover,.button-link:hover{{transform:translate(2px,2px);box-shadow:1px 1px 0 var(--ink)}}button.danger{{background:var(--signal);color:#fff;border-color:#9d3118}}
.actions>button{{width:100%}}button:disabled{{cursor:not-allowed;color:var(--muted);border-color:var(--line);box-shadow:none}}.live-change-notice{{position:relative;max-width:1080px;margin:1.25rem auto 0;padding:1rem 1.25rem;border:1px solid var(--signal);border-left:5px solid var(--signal);background:#f8e9d8;color:var(--ink)}}.live-change-notice[hidden]{{display:none}}
.actions.two{{grid-template-columns:repeat(2,minmax(0,1fr))}}
.actions.one{{grid-template-columns:minmax(0,24rem)}}.notice,.empty-state{{margin:1.5rem 0;padding:1.4rem;border:1px solid var(--line);border-left:5px solid var(--signal);background:#f8e9d8}}.empty-state p{{margin:.55rem 0 0;color:var(--muted)}}
.manual-release{{display:grid;grid-template-columns:minmax(12rem,1fr) minmax(16rem,1.4fr);gap:.75rem;align-items:end;margin-top:1.5rem}}.manual-release label{{grid-column:1/-1;font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}}.manual-release input{{min-height:3.25rem;width:100%;padding:.8rem 1rem;border:1px solid var(--ink);background:var(--panel);color:var(--ink);font:700 .9rem/1.35 var(--font-data)}}
.error-layout{{display:grid;place-items:center;min-height:calc(100vh - 8rem);padding-top:2rem}}.error-card{{width:min(100%,680px);padding:clamp(1.5rem,5vw,3rem);border:1px solid var(--line);border-top:5px solid var(--signal);background:var(--panel);box-shadow:10px 10px 0 var(--ink)}}.error-content{{width:100%;text-align:left}}.error-card h1{{margin:.65rem 0 1rem;font-size:clamp(2rem,6vw,3.5rem)}}.error-content>p:not(.eyebrow){{color:var(--muted)}}.error-command{{margin:1.5rem 0}}code{{padding:.2rem .4rem;background:#ece7da;font:600 .82rem/1.5 var(--font-data);font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}.button-link{{margin-top:.5rem;text-decoration:none}}
@media(max-width:760px){{.masthead{{grid-template-columns:1fr auto;gap:1rem}}.connection{{grid-column:1/-1;grid-row:2}}.review-grid{{grid-template-columns:1fr}}.section{{max-width:100%}}main{{padding-top:2rem}}.actions,.metric-grid,.manual-release{{grid-template-columns:1fr}}}}
</style>{dashboard_script}</head><body{live_attributes}>{body}</body></html>""".encode("utf-8")
