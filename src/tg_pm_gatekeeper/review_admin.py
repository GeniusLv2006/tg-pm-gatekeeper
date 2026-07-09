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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from telethon import functions, types

from .evidence import EvidenceStore
from .rules import URL_RE, normalized_domain, url_evidence, url_shape
from .service import GatekeeperService
from .store import DialogSnapshot, EnforcementReview, ReviewItem, StateStore


LOG = logging.getLogger("gatekeeper.review")
MAX_HEADER_BYTES = 16 * 1024
MAX_BODY_BYTES = 4 * 1024
IDENTITY_CACHE_SECONDS = 5 * 60
IDENTITY_FAILURE_CACHE_SECONDS = 30
IDENTITY_BATCH_SIZE = 100
IDENTITY_FETCH_TIMEOUT_SECONDS = 5


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
        evidence_store: EvidenceStore | None = None,
        evidence_collection: bool = False,
        evidence_retention_days: int = 7,
        evidence_max_records_per_sender: int = 3,
    ) -> None:
        self.socket_path = socket_path
        self.store = store
        self.service = service
        self.protector = service.protector
        self.telegram_client = telegram_client
        self.mute_days = mute_days
        self.cancel_timeout = cancel_timeout
        self.evidence_store = evidence_store
        self.evidence_collection = evidence_collection
        self.evidence_retention_days = evidence_retention_days
        self.evidence_max_records_per_sender = evidence_max_records_per_sender
        self._server: asyncio.AbstractServer | None = None
        self._csrf_token = secrets.token_urlsafe(32)
        self._access_token = secrets.token_urlsafe(32)
        self._session_token = secrets.token_urlsafe(32)
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
                "default-src 'none'; style-src 'unsafe-inline'; "
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
        path = parsed.path
        if request_headers is not None:
            host = request_headers.get("host", "")
            if not (host.startswith("127.0.0.1:") or host.startswith("localhost:")):
                return 400, {}, self._page("Invalid Host")
            if path == "/login":
                token = parse_qs(parsed.query).get("token", [""])[0]
                if not secrets.compare_digest(token, self._access_token):
                    return 400, {}, self._page("Invalid Access Token")
                self._access_token = secrets.token_urlsafe(32)
                self._write_access_token()
                return (
                    303,
                    {
                        "Location": "/",
                        "Set-Cookie": (
                            f"gatekeeper_session={self._session_token}; HttpOnly; "
                            "SameSite=Strict; Path=/"
                        ),
                    },
                    b"",
                )
            cookie = request_headers.get("cookie", "")
            if not secrets.compare_digest(
                self._cookie_value(cookie, "gatekeeper_session"), self._session_token
            ):
                return 404, {}, self._page("Not Found")
        if path == "/" and method == "GET":
            return 200, {}, await self._dashboard_page()
        if path == "/review" and method == "GET":
            return 200, {}, await self._review_queue_page()
        if path == "/dataset" and method == "GET":
            return 303, {"Location": "/evidence"}, b""
        if path.startswith("/dataset/"):
            suffix = path.removeprefix("/dataset/")
            return 303, {"Location": f"/evidence/{suffix}"}, b""
        if path == "/evidence" and method == "GET":
            try:
                page = max(1, int(parse_qs(parsed.query).get("page", ["1"])[0]))
            except ValueError:
                return 400, {}, self._page("Invalid Page")
            return 200, {}, self._evidence_index_page(page)
        if path.startswith("/evidence/"):
            return self._dispatch_evidence(method, path, body)
        if path == "/enforcement" and method == "GET":
            return 303, {"Location": "/cases"}, b""
        if path.startswith("/enforcement/"):
            suffix = path.removeprefix("/enforcement/")
            return 303, {"Location": f"/cases/{suffix}"}, b""
        if path == "/cases" and method == "GET":
            return 200, {}, await self._enforcement_index_page()
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
                    self.store.quarantine(item.sender_key)
                elif state.status == "challenged":
                    self.store.quarantine(item.sender_key)
                if self.store.sender(item.sender_key).status == "quarantined":
                    self.store.activate_enforcement_review(
                        item.sender_key,
                        "manual_spam",
                        int(time.time()) + self.service.review_retention_days * 86400,
                    )
                self.cancel_timeout(item.sender_key)
                self.store.decide_sender_reviews(item.sender_key, "spam")
            elif action == "dismiss":
                self.store.decide_sender_reviews(item.sender_key, "dismissed")
            else:
                return 400, {}, self._page("Unknown Action")
            self._identity_cache.pop(item.sender_key, None)
        return 303, {"Location": "/review"}, b""

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
    def _cookie_value(header: str, name: str) -> str:
        for item in header.split(";"):
            key, separator, value = item.strip().partition("=")
            if separator and key == name:
                return value
        return ""

    def _evidence_index_page(self, page: int = 1) -> bytes:
        if self.evidence_store is None:
            return self._page("Evidence Collection Is Disabled")
        stats = self.evidence_store.statistics(
            retention_days=self.evidence_retention_days
        )
        records = self.evidence_store.summaries(limit=101, offset=(page - 1) * 100)
        has_next = len(records) > 100
        groups: dict[str, str] = {}
        for record in records[:100]:
            groups.setdefault(record.sender_token, f"Sender {len(groups) + 1}")
        rows = (
            "".join(
                f"<tr><td><a href='/evidence/{record.id}'>#{record.id}</a></td>"
                f"<td>{html.escape(groups[record.sender_token])}</td>"
                f"<td>{html.escape(record.automatic_hint)}</td>"
                f"<td>{html.escape(self._evidence_outcome_label(record.review_outcome))}</td>"
                f"<td>{html.escape(self._relative_age(record.created_at))}</td></tr>"
                for record in records[:100]
            )
            or "<tr><td colspan='5'>No retained evidence records.</td></tr>"
        )
        navigation = "<p class='back'>"
        if page > 1:
            navigation += f"<a href='/evidence?page={page - 1}'>← Newer</a> "
        if has_next:
            navigation += f"<a href='/evidence?page={page + 1}'>Older →</a>"
        navigation += "</p>"
        labeled = sum(
            stats.get(label, 0)
            for label in ("correct", "false_positive", "insufficient")
        )
        overview = (
            "<dl class='metric-grid'>"
            f"<div><dt>Total Evidence Records</dt><dd class='data-value'>{stats.get('total', 0)}</dd></div>"
            f"<div><dt>Operator Reviewed</dt><dd class='data-value'>{labeled}</dd></div>"
            f"<div><dt>Correct / False Positive / Insufficient</dt><dd class='data-value'>"
            f"{stats.get('correct', 0)} / {stats.get('false_positive', 0)} / "
            f"{stats.get('insufficient', 0)}</dd></div>"
            f"<div><dt>Automatic Hints</dt><dd class='data-value'>"
            f"{stats.get('hint_spam_candidate', 0)} / "
            f"{stats.get('hint_legitimate_candidate', 0)} / "
            f"{stats.get('hint_uncertain', 0)}</dd></div>"
            f"<div><dt>Expiring within 24 hours</dt><dd class='data-value'>"
            f"{stats.get('expiring_24h', 0)}</dd></div>"
            f"<div><dt>Retention Window</dt><dd class='data-value'>"
            f"{self.evidence_retention_days}d</dd></div>"
            "</dl>"
        )
        activity = (
            "<h3>Collection Activity</h3><p class='refresh-note'>"
            f"UTC calendar-day totals within the current {self.evidence_retention_days}-day retention window.</p>"
            "<dl class='metric-grid'>"
            f"<div><dt>Content Evidence</dt><dd class='data-value'>{stats.get('collection_collected_content', 0)}</dd></div>"
            f"<div><dt>Structural-Only Evidence</dt><dd class='data-value'>{stats.get('collection_collected_structural', 0)}</dd></div>"
            f"<div><dt>Skipped: No Usable Signal</dt><dd class='data-value'>{stats.get('collection_skipped_no_signal', 0)}</dd></div>"
            f"<div><dt>Skipped: Duplicate</dt><dd class='data-value'>{stats.get('collection_skipped_duplicate', 0)}</dd></div>"
            f"<div><dt>Skipped: Sender Cap</dt><dd class='data-value'>{stats.get('collection_skipped_sender_cap', 0)}</dd></div>"
            "</dl>"
        )
        content = (
            self._masthead("Evidence Log", f"{stats.get('total', 0)} records")
            + "<p class='back'><a href='/'>← Operations Dashboard</a> · <a href='/cases'>Active Cases</a> · <a href='/review'>Pending Reviews</a></p><main>"
            + "<section class='queue-intro'><p class='eyebrow'>Short-Lived Audit Evidence</p>"
            + "<h2>Evidence Log</h2>"
            + f"<p>Collection {'enabled' if self.evidence_collection else 'disabled'} · "
            + f"{self.evidence_retention_days}-day retention · "
            + f"up to {self.evidence_max_records_per_sender} records per sender.</p>"
            + "<p>Evidence is retained for short-term review and rule auditing, not model training. Eligible unknown-sender messages contain text, quoted text, Telegram preview text, or a detector signal.</p>"
            + overview
            + activity
            + "</section>"
            + "<div class='table-shell'><table><thead><tr><th>Evidence</th><th>Sender Group</th>"
            + "<th>Automatic Hint</th><th>Review Outcome</th><th>Age</th></tr></thead>"
            + f"<tbody>{rows}</tbody></table></div>{navigation}</main>"
        )
        return self._page(content, raw=True)

    def _dispatch_evidence(
        self, method: str, path: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        if self.evidence_store is None:
            return 404, {}, self._page("Evidence Collection Is Disabled")
        try:
            record_id = int(path.rsplit("/", 1)[-1])
        except ValueError:
            return 404, {}, self._page("Evidence Record Not Found")
        record = self.evidence_store.record(record_id)
        if record is None:
            return 404, {}, self._page("Evidence Record Not Found")
        if method == "POST":
            values = parse_qs(body.decode("utf-8"), strict_parsing=True)
            if not secrets.compare_digest(
                values.get("token", [""])[0], self._csrf_token
            ):
                return 400, {}, self._page("Invalid Action Token")
            action = values.get("action", [""])[0]
            if action == "delete":
                self.evidence_store.delete(record_id)
            elif action in {"correct", "false_positive", "insufficient"}:
                self.evidence_store.review(record_id, action)
            else:
                return 400, {}, self._page("Unknown Action")
            return 303, {"Location": "/evidence"}, b""
        if method != "GET":
            return 405, {"Allow": "GET, POST"}, self._page("Method Not Allowed")
        payload = record.payload
        actions = "".join(
            self._action_form(record_id, label, display, base="evidence")
            for label, display in (
                ("correct", "Correct enforcement"),
                ("false_positive", "False positive"),
                ("insufficient", "Insufficient evidence"),
            )
        ) + self._action_form(
            record_id, "delete", "Delete evidence", danger=True, base="evidence"
        )
        content = (
            self._masthead("Evidence Record", f"#{record.id}")
            + "<p class='back'><a href='/evidence'>← Evidence Log</a></p>"
            + "<main><section class='message-panel'>"
            + self._evidence_sections(payload)
            + f"<div class='actions'>{actions}</div></section></main>"
        )
        return 200, {}, self._page(content, raw=True)

    @staticmethod
    def _evidence_outcome_label(outcome: str | None) -> str:
        return {
            "correct": "Correct Enforcement",
            "false_positive": "False Positive",
            "insufficient": "Insufficient Evidence",
        }.get(outcome or "", "Unreviewed")

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

    def _evidence_sections(self, payload: dict[str, object]) -> str:
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
            self._text_block("Message Text Or Caption", text)
            + self._text_block("Quoted Context", quote_text, quote=True)
            + self._text_block("Telegram Webpage Preview", preview_text, quote=True)
        )
        if structural_only:
            sections += (
                "<div class='notice'><strong>Structural-Only Evidence.</strong> "
                "No message, quoted, or preview text was retained. Review the detector "
                "signals and structural metadata; choose Insufficient evidence when the "
                "record is not enough.</div>"
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
            + f"<details><summary>Encrypted Evidence Payload</summary><pre>{details}</pre></details>"
        )

    async def _dispatch_enforcement(
        self, method: str, path: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        sender_key = path.rsplit("/", 1)[-1]
        if len(sender_key) != 64 or any(char not in "0123456789abcdef" for char in sender_key):
            return 404, {}, self._page("Active Case Not Found")
        item = self.store.enforcement_review(sender_key)
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
        async with self.service.sender_lock(sender_key):
            item = self.store.enforcement_review(sender_key)
            if item is None:
                return 409, {}, self._page("This Active Case Has Expired")
            if item.reference is None:
                return 409, {}, self._page("Telegram Identity Is Unavailable")
            try:
                user_id, access_hash, _ = self.protector.open_review_reference(
                    item.reference
                )
            except ValueError:
                return 409, {}, self._page("Telegram Identity Is Unavailable")
            peer = types.InputPeerUser(user_id=user_id, access_hash=access_hash)
            if not await self._restore(peer, sender_key):
                return 500, {}, self._page("Telegram Action Failed; Item Was Not Changed")
            self.store.allow(sender_key)
            self.cancel_timeout(sender_key)
            self._identity_cache.pop(sender_key, None)
        return 303, {"Location": "/cases"}, b""

    async def _enforcement_index_page(self) -> bytes:
        items = self.store.enforcement_reviews()
        identities = await self._live_enforcement_identities(items)
        stats = self.store.enforcement_statistics()
        rows = "".join(
            f"<tr><td><a href='/cases/{item.sender_key}'>Open</a></td>"
            f"<td>{self._identity_cell(identities.get(item.sender_key))}</td>"
            f"<td><span class='badge'>{html.escape(item.status)}</span></td>"
            f"<td>{html.escape(item.reason)}</td>"
            f"<td>{html.escape(self._remaining(item))}</td>"
            f"<td>{html.escape(self._relative_age(item.updated_at))}</td></tr>"
            for item in items
        ) or "<tr><td colspan='6'>No active cases.</td></tr>"
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
            f"{stats['unreviewable']} active case"
            f"{'s' if stats['unreviewable'] != 1 else ''} "
            f"{'have' if stats['unreviewable'] != 1 else 'has'} no encrypted snapshot "
            "and cannot be opened here. Such states may predate evidence capture."
            if stats["unreviewable"]
            else "Every active case currently has reviewable evidence."
        )
        content = (
            self._masthead("Active Cases", f"{len(items)} reviewable")
            + "<p class='back'><a href='/'>← Operations Dashboard</a> · <a href='/review'>Pending Reviews</a> · <a href='/evidence'>Evidence Log</a></p>"
            + "<main><section class='queue-intro'><p class='eyebrow'>Protect Mode State</p>"
            + "<h2>Review Active Cases</h2>"
            + "<p>Encrypted evidence preserves the triggering message, links, buttons, and quoted context for short-term operator review. Telegram block is not used.</p>"
            + "<dl class='metric-grid'>"
            + f"<div><dt>Quarantined</dt><dd class='data-value'>{stats['quarantined']}</dd></div>"
            + f"<div><dt>Suppressed</dt><dd class='data-value'>{stats['suppressed']}</dd></div>"
            + f"<div><dt>Reviewable Evidence</dt><dd class='data-value'>{stats['reviewable']}</dd></div></dl>"
            + f"<p class='refresh-note'><strong>State Reasons:</strong> {reasons}. {snapshot_note}</p></section>"
            + "<div class='table-shell'><table><thead><tr><th>Case</th><th>Sender</th><th>Status</th><th>Reason</th><th>Restriction</th><th>Updated</th></tr></thead>"
            + f"<tbody>{rows}</tbody></table></div></main>"
        )
        return self._page(content, raw=True, refresh_seconds=10)

    async def _show_enforcement(
        self, item: EnforcementReview
    ) -> tuple[int, dict[str, str], bytes]:
        if self.service.review_content_protector is None:
            return 500, {}, self._page("Encrypted Review Content Is Unavailable")
        try:
            payload = self.service.review_content_protector.open_enforcement(
                item.envelope
            )
        except ValueError:
            return 500, {}, self._page("Encrypted Review Content Is Unavailable")
        identity = "Identity unavailable"
        telegram_link = ""
        user_id: int | None = None
        if item.reference is not None:
            try:
                user_id, access_hash, _ = self.protector.open_review_reference(
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
                pass
        rules = ", ".join(str(value) for value in payload.get("rule_codes", [])) or "—"
        features = json.dumps(payload.get("features", {}), indent=2, sort_keys=True)
        observed = datetime.fromtimestamp(item.created_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        allow_action = (
            self._action_form(
                item.sender_key, "allow", "Allow now", base="cases"
            )
            if user_id is not None
            else "<button type='button' disabled>Allow unavailable</button>"
        )
        content = f"""
        {self._masthead("Active Cases", item.status)}
        <p class="back"><a href="/cases">← Active Cases</a></p>
        <main class="review-grid"><section class="message-panel">
          <p class="eyebrow">Encrypted Local Evidence</p>
          <h2>{html.escape(identity)}</h2>
          {self._evidence_sections(payload)}
          {telegram_link}
        </section><aside class="case-file"><p class="eyebrow">Restriction Details</p>
          <dl><dt>Status</dt><dd><span class="badge">{html.escape(item.status)}</span></dd>
          <dt>Reason</dt><dd>{html.escape(item.reason)}</dd><dt>Rules</dt><dd>{html.escape(rules)}</dd>
          <dt>Triggered</dt><dd>{observed}</dd><dt>Restriction</dt><dd>{html.escape(self._remaining(item))}</dd>
          <dt>Evidence Expires</dt><dd>{datetime.fromtimestamp(item.expires_at, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</dd></dl>
          <details><summary>Structural Features</summary><pre>{html.escape(features)}</pre></details>
        </aside></main><section class="decision-panel"><p class="eyebrow">Operator Action</p>
          <h2>Allow restores the saved folder and notification state before changing policy.</h2>
          <div class="actions two">
            {allow_action}
            {self._action_form(item.sender_key, "keep", "Keep current restriction", base="cases")}
          </div></section>"""
        return 200, {}, self._page(content, raw=True)

    def _peer_from_item(self, item: ReviewItem) -> types.InputPeerUser:
        if item.reference is None:
            raise ValueError("review reference has expired")
        user_id, access_hash, _ = self.protector.open_review_reference(item.reference)
        return types.InputPeerUser(user_id=user_id, access_hash=access_hash)

    async def _capture_manual_enforcement(
        self, item: ReviewItem, peer: types.InputPeerUser
    ) -> None:
        if self.service.review_content_protector is None or item.reference is None:
            return
        try:
            _, _, message_id = self.protector.open_review_reference(item.reference)
            message = await self.telegram_client.get_messages(peer, ids=message_id)
            if message is None:
                return
            text = getattr(message, "message", None) or ""
            reply_header = getattr(message, "reply_to", None)
            quote_text = getattr(reply_header, "quote_text", None) or ""
            quote_urls = tuple(sorted(set(URL_RE.findall(quote_text))))
            urls = set(URL_RE.findall(text))
            button_texts: set[str] = set()
            button_urls: set[str] = set()
            markup = getattr(message, "reply_markup", None)
            for row in getattr(markup, "rows", ()) or ():
                for button in getattr(row, "buttons", ()) or ():
                    text_value = getattr(button, "text", None)
                    if isinstance(text_value, str) and text_value.strip():
                        button_texts.add(text_value.strip())
                    url_value = getattr(button, "url", None)
                    if isinstance(url_value, str) and url_value.strip():
                        urls.add(url_value.strip())
                        button_urls.add(url_value.strip())
            webpage = getattr(getattr(message, "media", None), "webpage", None)
            webpage_url = getattr(webpage, "url", None)
            preview_urls: set[str] = set()
            if isinstance(webpage_url, str) and webpage_url.strip():
                urls.add(webpage_url.strip())
                preview_urls.add(webpage_url.strip())
            preview_text = "\n".join(
                value
                for attribute in ("site_name", "title", "description", "author")
                if isinstance(value := getattr(webpage, attribute, None), str)
                and value.strip()
            )
            url_values = tuple(sorted(urls))
            domains = tuple(
                sorted({domain for url in url_values if (domain := normalized_domain(url))})
            )
            quote_domains = tuple(
                sorted({domain for url in quote_urls if (domain := normalized_domain(url))})
            )
            payload: dict[str, object] = {
                "schema_version": 4,
                "text": text,
                "quote_text": quote_text,
                "preview_text": preview_text,
                "button_texts": list(sorted(button_texts))[:10],
                "urls": url_evidence(
                    url_values,
                    button_urls=tuple(sorted(button_urls)),
                    preview_urls=tuple(sorted(preview_urls)),
                ),
                "quote_urls": url_evidence(quote_urls),
                "domains": list(domains[:3]),
                "quote_domains": list(quote_domains[:3]),
                "url_shape": url_shape(url_values),
                "quote_url_shape": url_shape(quote_urls),
                "signals": [],
                "severity": "high",
                "score": None,
                "model_version": None,
                "planned_action": "manual_spam",
                "actual_action": "active_case",
                "policy": "manual_review",
                "rule_codes": json.loads(item.rule_codes),
                "features": json.loads(item.features),
            }
            now = int(time.time())
            self.store.save_enforcement_review(
                item.sender_key,
                reference=item.reference,
                envelope=self.service.review_content_protector.seal_enforcement(
                    payload
                ),
                reason="manual_spam",
                expires_at=now + self.service.review_retention_days * 86400,
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
        rules = ", ".join(json.loads(item.rule_codes)) or "ordinary unknown sender"
        features = json.dumps(json.loads(item.features), indent=2, sort_keys=True)
        observed_at = datetime.fromtimestamp(item.updated_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        if message is None:
            content = f"""
            {self._masthead("Review item", f"Review #{item.id}")}
            <p class="back"><a href="/">← Back to pending queue</a></p>
            <main class="review-grid">
              <section class="message-panel">
                <p class="eyebrow">Telegram message unavailable</p>
                <h2>{html.escape(identity)}</h2>
                <div class="empty-state"><strong>The referenced message no longer exists.</strong>
                <p>The conversation may have been deleted in Telegram. This pending row is local
                review state and is not removed automatically.</p></div>
              </section>
              <aside class="case-file"><p class="eyebrow">Review details</p>
                <dl><dt>Simulated decision</dt><dd><span class="badge">{html.escape(item.classification)}</span></dd>
                <dt>Rules</dt><dd>{html.escape(rules)}</dd>
                <dt>Messages observed</dt><dd>{item.message_count}</dd>
                <dt>Last observed</dt><dd>{observed_at}</dd></dl>
              </aside>
            </main>
            <section class="decision-panel"><p class="eyebrow">Resolve local record</p>
              <h2>Remove this sender's pending review without changing Telegram or trust state.</h2>
              <div class="actions one">
                {self._action_form(item.id, "dismiss", "Resolve deleted conversation")}
              </div>
            </section>
            """
            return 200, {}, self._page(content, raw=True)
        text = message.message or f"[Non-text message: {type(message.media).__name__}]"
        content = f"""
        {self._masthead("Review item", f"Review #{item.id}")}
        <p class="back"><a href="/">← Back to pending queue</a></p>
        <main class="review-grid">
          <section class="message-panel">
            <p class="eyebrow">Fetched from Telegram · not stored locally</p>
            <h2>{html.escape(identity)}</h2>
            <pre class="message">{html.escape(text)}</pre>
            <a class="telegram-link" href="tg://user?id={user_id}">Open this conversation in Telegram ↗</a>
          </section>
          <aside class="case-file">
            <p class="eyebrow">Review details</p>
            <dl><dt>Simulated decision</dt><dd><span class="badge">{html.escape(item.classification)}</span></dd>
            <dt>Rules</dt><dd>{html.escape(rules)}</dd>
            <dt>Telegram ID</dt><dd>{user_id}</dd>
            <dt>Messages observed</dt><dd>{item.message_count}</dd>
            <dt>Last observed</dt><dd>{observed_at}</dd></dl>
            <details><summary>Structural features</summary><pre>{html.escape(features)}</pre></details>
          </aside>
        </main>
        <section class="decision-panel"><p class="eyebrow">Sender decision</p>
          <h2>This decision applies to all pending entries for this sender.</h2>
          <div class="actions">
            {self._action_form(item.id, "legitimate", "Legitimate · allow sender")}
            {self._action_form(item.id, "spam", "Spam · archive and mute", danger=True)}
            {self._action_form(item.id, "dismiss", "Dismiss without action")}
          </div>
        </section>
        """
        return 200, {}, self._page(content, raw=True, refresh_seconds=30)

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
        try:
            snapshot = self.store.dialog_snapshot(sender_key)
            folder_id = snapshot.folder_id if snapshot is not None else 0
            silent = snapshot.silent if snapshot is not None else False
            mute_until = (
                datetime.fromtimestamp(snapshot.mute_until, timezone.utc)
                if snapshot is not None and snapshot.mute_until is not None
                else datetime.now(timezone.utc)
            )
            await self.telegram_client(
                functions.folders.EditPeerFoldersRequest(
                    [types.InputFolderPeer(peer=peer, folder_id=folder_id)]
                )
            )
            await self.telegram_client(
                functions.account.UpdateNotifySettingsRequest(
                    peer=types.InputNotifyPeer(peer),
                    settings=types.InputPeerNotifySettings(
                        silent=silent,
                        mute_until=mute_until,
                    ),
                )
            )
            self.store.clear_dialog_snapshot(sender_key)
            return True
        except Exception:
            LOG.error("review_restore_failed")
            return False

    async def _dashboard_page(self) -> bytes:
        review_items = self.store.review_items()
        active_cases = self.store.enforcement_reviews()
        evidence_total = 0
        if self.evidence_store is not None:
            evidence_total = self.evidence_store.statistics(
                retention_days=self.evidence_retention_days
            ).get("total", 0)
        mode = self.store.get_mode()
        content = (
            self._masthead("Operations Dashboard", mode.title())
            + "<main><section class='queue-intro'><p class='eyebrow'>Operator Overview</p>"
            "<h2>Operations Dashboard</h2>"
            "<p>Use Active Cases for recovery after a possible false positive. "
            "Pending Reviews cover monitor-mode sender decisions. Evidence Log is short-lived encrypted audit evidence.</p>"
            "<dl class='metric-grid'>"
            f"<div><dt>Active Cases</dt><dd class='data-value'>{len(active_cases)}</dd></div>"
            f"<div><dt>Pending Reviews</dt><dd class='data-value'>{len(review_items)}</dd></div>"
            f"<div><dt>Evidence Records</dt><dd class='data-value'>{evidence_total}</dd></div>"
            "</dl></section>"
            "<div class='table-shell'><table><thead><tr><th>Area</th><th>Purpose</th><th>Open</th></tr></thead><tbody>"
            "<tr><td>Active Cases</td><td>Restore or keep current quarantines and suppressions.</td><td><a href='/cases'>Open</a></td></tr>"
            "<tr><td>Pending Reviews</td><td>Resolve monitor-mode or ordinary sender review items.</td><td><a href='/review'>Open</a></td></tr>"
            "<tr><td>Evidence Log</td><td>Review short-lived encrypted evidence for rule audits and false-positive analysis.</td><td><a href='/evidence'>Open</a></td></tr>"
            "</tbody></table></div></main>"
        )
        return self._page(content, raw=True, refresh_seconds=10)

    async def _review_queue_page(self) -> bytes:
        items = self.store.review_items()
        identities = await self._live_identities(items)
        rows = "".join(
            f"<tr><td><a href='/review/{item.id}'>#{item.id}</a></td>"
            f"<td>{self._identity_cell(identities.get(item.id))}</td>"
            f"<td>{html.escape(item.classification)}</td>"
            f"<td>{html.escape(', '.join(json.loads(item.rule_codes)) or '—')}</td>"
            f"<td>{item.message_count}</td>"
            f"<td>{html.escape(self._relative_age(item.updated_at))}</td></tr>"
            for item in items
        )
        if not rows:
            rows = "<tr><td colspan='6'>No pending reviews.</td></tr>"
        return self._page(
            self._masthead("Pending Reviews", f"{len(items)} pending")
            + "<p class='back'><a href='/'>← Operations Dashboard</a> · <a href='/cases'>Active Cases</a> · <a href='/evidence'>Evidence Log</a></p>"
            + "<main><section class='queue-intro'><p class='eyebrow'>Pending Reviews</p>"
            "<h2>Review Pending Senders</h2>"
            "<p>Sender identity is fetched from Telegram and cached briefly in memory. "
            "Message content is fetched only when a review item is opened.</p>"
            "<p>Deleting a conversation in Telegram does not remove its local pending review. "
            "Open the row and resolve it when the referenced message is unavailable.</p>"
            "<p class='refresh-note'>This page checks the connection every 10 seconds and shows "
            "an error when the SSH tunnel is unavailable.</p></section>"
            "<div class='table-shell'><table><thead><tr><th>Case</th><th>Sender</th><th>Simulation</th>"
            "<th>Rules</th><th>Messages</th>"
            f"<th>Last Seen</th></tr></thead><tbody>{rows}</tbody></table></div></main>",
            raw=True,
            refresh_seconds=10,
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
        self, items: list[EnforcementReview]
    ) -> dict[str, LiveIdentity]:
        identities: dict[str, LiveIdentity] = {}
        for item in items:
            if item.reference is None:
                continue
            try:
                user_id, access_hash, _ = self.protector.open_review_reference(
                    item.reference
                )
                cached = self._identity_cache.get(item.sender_key)
                if cached and cached[0] > time.monotonic():
                    identities[item.sender_key] = LiveIdentity(
                        user_id, cached[1], cached[2]
                    )
                    continue
                sender = await asyncio.wait_for(
                    self.telegram_client.get_entity(
                        types.InputPeerUser(user_id=user_id, access_hash=access_hash)
                    ),
                    timeout=IDENTITY_FETCH_TIMEOUT_SECONDS,
                )
                name, username = self._sender_name(sender)
                identities[item.sender_key] = LiveIdentity(user_id, name, username)
                self._cache_identity(
                    item.sender_key, name, username, IDENTITY_CACHE_SECONDS
                )
            except Exception:
                continue
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
    def _masthead(section: str, status: str) -> str:
        checked_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        return (
            "<header class='masthead'><div><span class='mark'>TG</span>"
            "<span class='product'>PM Gatekeeper</span></div>"
            "<div class='connection'><span class='live'><i></i>Connected</span>"
            f"<small>Updated {checked_at}</small></div>"
            f"<div class='section'>{html.escape(section)}<span>{html.escape(status)}</span></div>"
            "</header>"
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
    def _remaining(item: EnforcementReview) -> str:
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
        return reason.replace("_", " ")

    @classmethod
    def _page(
        cls, content: str, *, raw: bool = False, refresh_seconds: int | None = None
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
                    "The page is unavailable or the dashboard session is missing. "
                    "Open the one-time link printed by the tunnel helper."
                ),
                "Request Failed": (
                    "The request could not be completed. No dashboard action was confirmed."
                ),
            }.get(content, "Check the request and return to the dashboard.")
            body = (
                cls._masthead("Error", "Request Not Completed")
                + "<main class='error-layout'><section class='error-card'>"
                + "<div class='error-content'>"
                + "<p class='eyebrow'>Dashboard Error</p>"
                + f"<h1>{html.escape(content)}</h1>"
                + f"<p>{html.escape(guidance)}</p>"
                + "<p class='error-command'><code>scripts/dashboard-tunnel.sh SSH_TARGET</code></p>"
                + "<a class='button-link' href='/'>Return to dashboard</a>"
                + "</div></section></main>"
            )
        refresh = (
            f'<meta http-equiv="refresh" content="{refresh_seconds}">'
            if refresh_seconds is not None
            else ""
        )
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{refresh}<title>Gatekeeper Review</title><style>
:root{{--ink:#17211d;--muted:#68726c;--paper:#f3efe5;--panel:#fffdf7;--line:#c9c3b5;--signal:#d84a28;--safe:#1e6b52;--font-ui:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--font-data:SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace}}
*{{box-sizing:border-box}}body{{margin:0;color:var(--ink);background:var(--paper);font:15px/1.55 var(--font-ui)}}
body:before{{content:"";position:fixed;inset:0;pointer-events:none;opacity:.18;background-image:repeating-linear-gradient(90deg,transparent 0 47px,#8f8878 48px),repeating-linear-gradient(0deg,transparent 0 47px,#8f8878 48px)}}
.masthead,main,.back{{position:relative;max-width:1120px;margin-left:auto;margin-right:auto}}
.masthead{{display:grid;grid-template-columns:1fr auto auto;gap:2.5rem;align-items:center;padding:2rem 1.25rem 1.1rem;border-bottom:2px solid var(--ink)}}.masthead>div{{min-width:0}}
.mark{{display:inline-grid;place-items:center;width:2.5rem;height:2.5rem;margin-right:.8rem;color:var(--paper);background:var(--ink);font-weight:800;letter-spacing:-.08em}}
.product{{font-size:1.15rem;font-weight:750;letter-spacing:-.01em}}.section{{text-transform:uppercase;font:700 .72rem/1.4 var(--font-data);letter-spacing:.08em;text-align:right;font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}
.section span{{display:block;color:var(--signal);font-weight:800;margin-top:.25rem}}main{{padding:3rem 1.25rem 5rem}}
.connection{{padding:.5rem .75rem;border:1px solid var(--line);background:var(--panel)}}.connection small{{display:block;margin-top:.2rem;color:var(--muted);font:400 .65rem/1.4 var(--font-data);letter-spacing:.03em;font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}.live{{display:flex;align-items:center;gap:.5rem;color:var(--safe);font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em}}.live i{{width:.55rem;height:.55rem;border-radius:50%;background:#2cab76;box-shadow:0 0 0 4px #d8f0e6;animation:pulse 2s infinite}}@keyframes pulse{{50%{{box-shadow:0 0 0 7px transparent}}}}
.queue-intro{{max-width:none;margin-bottom:2.5rem}}h1,h2{{font-family:var(--font-ui);line-height:1.12;letter-spacing:-.025em}}.queue-intro h2{{font-size:clamp(1.85rem,3.6vw,3rem);font-weight:720;margin:.55rem 0 1rem}}
.queue-intro p{{max-width:none;color:var(--muted)}}.refresh-note{{margin-top:1.2rem;padding-left:1rem;border-left:3px solid var(--safe);font-size:.78rem}}.eyebrow{{margin:0;text-transform:uppercase;letter-spacing:.13em;font-size:.7rem;font-weight:800;color:var(--signal)}}
.metric-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin:2rem 0 0}}.metric-grid>div{{min-width:0;padding:1rem;border:1px solid var(--line);background:rgba(255,253,247,.72)}}.metric-grid dd{{margin:.45rem 0 0}}.data-value{{font:700 1.15rem/1.35 var(--font-data);font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}
.table-shell{{overflow-x:auto;border:1px solid var(--line);background:var(--panel);box-shadow:8px 8px 0 var(--ink)}}table{{border-collapse:collapse;width:100%;min-width:860px}}
th,td{{padding:1rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}}tbody tr:last-child td{{border-bottom:0}}tbody tr:hover{{background:#f8e9d8}}a{{color:var(--ink);text-underline-offset:.22em}}td:first-child a{{font-weight:900;color:var(--signal)}}
.identity-name,.identity-id{{display:block}}.identity-name{{font-size:1rem;font-weight:700}}.identity-id{{margin-top:.2rem;color:var(--muted);font:400 .7rem/1.4 var(--font-data);letter-spacing:.02em;font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}
.back{{padding:1.25rem 1.25rem 0}}.review-grid{{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(280px,.75fr);gap:1.5rem;padding-bottom:2rem}}
.message-panel,.case-file,.decision-panel{{min-width:0;border:1px solid var(--line);background:var(--panel);padding:clamp(1.25rem,4vw,2.4rem)}}.message-panel h2{{font-size:2rem;margin:.5rem 0 1.8rem;overflow-wrap:anywhere}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--font-data);font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}pre.message{{min-height:180px;margin:0 0 1.5rem;padding:1.4rem;background:var(--ink);color:#f7f1df;font:1rem/1.65 var(--font-ui);border-left:5px solid var(--signal)}}
.content-label{{margin:1.5rem 0 .55rem;color:var(--muted);font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.09em}}pre.message.quote{{min-height:96px;background:#27332e;border-left-color:#b88836}}
.telegram-link{{display:inline-block;max-width:100%;font-weight:800;overflow-wrap:anywhere}}dt{{font-size:.66rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}}dd{{margin:.2rem 0 1.2rem;overflow-wrap:anywhere}}.badge{{display:inline-block;max-width:100%;padding:.2rem .45rem;background:#f8e9d8;border:1px solid var(--signal);color:#9d3118;font-weight:800;overflow-wrap:anywhere}}
details{{border-top:1px solid var(--line);padding-top:1rem}}summary{{cursor:pointer;font-weight:800}}details pre{{font-size:.75rem;color:var(--muted)}}.decision-panel{{position:relative;width:calc(100% - 2.5rem);max-width:1080px;margin:0 auto 4rem;border-top:5px solid var(--ink)}}.decision-panel h2{{font-size:1.7rem;margin-bottom:0}}
.actions{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin-top:1.5rem}}.actions form{{display:flex;min-width:0}}button,.button-link{{display:inline-flex;align-items:center;justify-content:center;min-height:3.25rem;padding:.8rem 1rem;border:1px solid var(--ink);background:transparent;color:var(--ink);font:700 .78rem/1.35 var(--font-ui);cursor:pointer;box-shadow:3px 3px 0 var(--ink);transition:transform .12s,box-shadow .12s;white-space:normal;overflow-wrap:anywhere}}button{{width:100%}}button:hover,.button-link:hover{{transform:translate(2px,2px);box-shadow:1px 1px 0 var(--ink)}}button.danger{{background:var(--signal);color:#fff;border-color:#9d3118}}
.actions>button{{width:100%}}button:disabled{{cursor:not-allowed;color:var(--muted);border-color:var(--line);box-shadow:none}}
.actions.two{{grid-template-columns:repeat(2,minmax(0,1fr))}}
.actions.one{{grid-template-columns:minmax(0,24rem)}}.notice,.empty-state{{margin:1.5rem 0;padding:1.4rem;border:1px solid var(--line);border-left:5px solid var(--signal);background:#f8e9d8}}.empty-state p{{margin:.55rem 0 0;color:var(--muted)}}
.error-layout{{display:grid;place-items:center;min-height:calc(100vh - 8rem);padding-top:2rem}}.error-card{{width:min(100%,680px);padding:clamp(1.5rem,5vw,3rem);border:1px solid var(--line);border-top:5px solid var(--signal);background:var(--panel);box-shadow:10px 10px 0 var(--ink)}}.error-content{{width:100%;text-align:left}}.error-card h1{{margin:.65rem 0 1rem;font-size:clamp(2rem,6vw,3.5rem)}}.error-content>p:not(.eyebrow){{color:var(--muted)}}.error-command{{margin:1.5rem 0}}code{{padding:.2rem .4rem;background:#ece7da;font:600 .82rem/1.5 var(--font-data);font-variant-numeric:tabular-nums slashed-zero;font-feature-settings:"tnum" 1,"zero" 1}}.button-link{{margin-top:.5rem;text-decoration:none}}
@media(max-width:760px){{.masthead{{grid-template-columns:1fr auto;gap:1rem}}.connection{{grid-column:1/-1;grid-row:2}}.review-grid{{grid-template-columns:1fr}}.section{{max-width:100%}}main{{padding-top:2rem}}.actions,.metric-grid{{grid-template-columns:1fr}}}}
</style></head><body>{body}</body></html>""".encode("utf-8")
