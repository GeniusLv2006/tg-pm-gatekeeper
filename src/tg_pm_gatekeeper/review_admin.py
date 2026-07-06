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

from .dataset import TrainingStore
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
        training_store: TrainingStore | None = None,
        dataset_collection: bool = False,
        dataset_retention_days: int = 30,
        dataset_max_messages_per_sender: int = 3,
    ) -> None:
        self.socket_path = socket_path
        self.store = store
        self.service = service
        self.protector = service.protector
        self.telegram_client = telegram_client
        self.mute_days = mute_days
        self.cancel_timeout = cancel_timeout
        self.training_store = training_store
        self.dataset_collection = dataset_collection
        self.dataset_retention_days = dataset_retention_days
        self.dataset_max_messages_per_sender = dataset_max_messages_per_sender
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
            status, headers, response = 400, {}, self._page("Invalid request")
        except Exception:
            LOG.error("review_request_failed")
            status, headers, response = 500, {}, self._page("Request failed")
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
                return 400, {}, self._page("Invalid host")
            if path == "/login":
                token = parse_qs(parsed.query).get("token", [""])[0]
                if not secrets.compare_digest(token, self._access_token):
                    return 400, {}, self._page("Invalid access token")
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
                return 404, {}, self._page("Not found")
        if path == "/" and method == "GET":
            return 200, {}, await self._index_page()
        if path == "/dataset" and method == "GET":
            try:
                page = max(1, int(parse_qs(parsed.query).get("page", ["1"])[0]))
            except ValueError:
                return 400, {}, self._page("Invalid page")
            return 200, {}, self._dataset_index_page(page)
        if path.startswith("/dataset/"):
            return self._dispatch_dataset(method, path, body)
        if path == "/enforcement" and method == "GET":
            return 200, {}, await self._enforcement_index_page()
        if path.startswith("/enforcement/"):
            return await self._dispatch_enforcement(method, path, body)
        if not path.startswith("/review/"):
            return 404, {}, self._page("Not found")
        try:
            review_id = int(path.removeprefix("/review/"))
        except ValueError:
            return 404, {}, self._page("Not found")
        item = self.store.review_item(review_id)
        if item is None or (
            item.status == "pending" and item.expires_at <= int(time.time())
        ):
            return 404, {}, self._page("Review item not found")
        if method == "GET":
            return await self._show_review(item)
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, self._page("Method not allowed")
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        token = values.get("token", [""])[0]
        action = values.get("action", [""])[0]
        if not secrets.compare_digest(token, self._csrf_token):
            return 400, {}, self._page("Invalid action token")
        async with self.service.sender_lock(item.sender_key):
            item = self.store.review_item(review_id)
            if item is None or item.status != "pending" or item.reference is None:
                return 409, {}, self._page("This item has already been reviewed")
            state = self.store.sender(item.sender_key)
            if action == "legitimate":
                if state.status in {"challenged", "quarantined", "suppressed"}:
                    peer = self._peer_from_item(item)
                    if not await self._restore(peer, item.sender_key):
                        return (
                            500,
                            {},
                            self._page("Telegram action failed; item was not changed"),
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
                            self._page("Telegram action failed; item was not changed"),
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
                return 400, {}, self._page("Unknown action")
            self._identity_cache.pop(item.sender_key, None)
        return 303, {"Location": "/"}, b""

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

    def _dataset_index_page(self, page: int = 1) -> bytes:
        if self.training_store is None:
            return self._page("Dataset collection is disabled")
        stats = self.training_store.statistics(
            retention_days=self.dataset_retention_days
        )
        samples = self.training_store.summaries(limit=101, offset=(page - 1) * 100)
        has_next = len(samples) > 100
        groups: dict[str, str] = {}
        for sample in samples[:100]:
            groups.setdefault(sample.sender_token, f"Sender {len(groups) + 1}")
        rows = (
            "".join(
                f"<tr><td><a href='/dataset/{sample.id}'>#{sample.id}</a></td>"
                f"<td>{html.escape(groups[sample.sender_token])}</td>"
                f"<td>{html.escape(sample.weak_label)}</td>"
                f"<td>{html.escape(sample.manual_label or 'Unlabeled')}</td>"
                f"<td>{html.escape(self._relative_age(sample.created_at))}</td></tr>"
                for sample in samples[:100]
            )
            or "<tr><td colspan='5'>No unexpired samples.</td></tr>"
        )
        navigation = "<p class='back'>"
        if page > 1:
            navigation += f"<a href='/dataset?page={page - 1}'>← Newer</a> "
        if has_next:
            navigation += f"<a href='/dataset?page={page + 1}'>Older →</a>"
        navigation += "</p>"
        labeled = sum(
            stats.get(label, 0) for label in ("spam", "legitimate", "uncertain")
        )
        overview = (
            "<dl class='metric-grid'>"
            f"<div><dt>Total samples</dt><dd class='data-value'>{stats.get('total', 0)}</dd></div>"
            f"<div><dt>Manually labeled</dt><dd class='data-value'>{labeled}</dd></div>"
            f"<div><dt>Spam / Legitimate / Uncertain</dt><dd class='data-value'>"
            f"{stats.get('spam', 0)} / {stats.get('legitimate', 0)} / "
            f"{stats.get('uncertain', 0)}</dd></div>"
            f"<div><dt>Weak spam / legitimate / uncertain</dt><dd class='data-value'>"
            f"{stats.get('weak_spam_candidate', 0)} / "
            f"{stats.get('weak_legitimate_candidate', 0)} / "
            f"{stats.get('weak_uncertain', 0)}</dd></div>"
            f"<div><dt>Expiring within 24 hours</dt><dd class='data-value'>"
            f"{stats.get('expiring_24h', 0)}</dd></div>"
            f"<div><dt>Exportable manual labels</dt><dd class='data-value'>"
            f"{stats.get('exportable_gold', 0)}</dd></div>"
            "</dl>"
        )
        activity = (
            "<h3>Collection activity</h3><p class='refresh-note'>"
            f"UTC calendar-day totals within the current {self.dataset_retention_days}-day retention window.</p>"
            "<dl class='metric-grid'>"
            f"<div><dt>Content samples</dt><dd class='data-value'>{stats.get('collection_collected_content', 0)}</dd></div>"
            f"<div><dt>Structural-only samples</dt><dd class='data-value'>{stats.get('collection_collected_structural', 0)}</dd></div>"
            f"<div><dt>Skipped: no usable signal</dt><dd class='data-value'>{stats.get('collection_skipped_no_signal', 0)}</dd></div>"
            f"<div><dt>Skipped: duplicate</dt><dd class='data-value'>{stats.get('collection_skipped_duplicate', 0)}</dd></div>"
            f"<div><dt>Skipped: sender cap</dt><dd class='data-value'>{stats.get('collection_skipped_sender_cap', 0)}</dd></div>"
            "</dl>"
        )
        content = (
            self._masthead("Dataset", f"{stats.get('total', 0)} samples")
            + "<p class='back'><a href='/'>← Review queue</a> · <a href='/enforcement'>Active enforcement</a></p><main>"
            + "<section class='queue-intro'><p class='eyebrow'>Dataset status</p>"
            + "<h2>Dataset overview</h2>"
            + f"<p>Collection {'enabled' if self.dataset_collection else 'disabled'} · "
            + f"{self.dataset_retention_days}-day retention · "
            + f"up to {self.dataset_max_messages_per_sender} messages per sender.</p>"
            + "<p>Eligible unknown-sender messages contain text, quoted text, Telegram preview text, or a detector signal. Collection-disabled traffic is not counted.</p>"
            + overview
            + activity
            + "</section>"
            + "<div class='table-shell'><table><thead><tr><th>Sample</th><th>Sender group</th>"
            + "<th>Weak label</th><th>Manual label</th><th>Age</th></tr></thead>"
            + f"<tbody>{rows}</tbody></table></div>{navigation}</main>"
        )
        return self._page(content, raw=True)

    def _dispatch_dataset(
        self, method: str, path: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        if self.training_store is None:
            return 404, {}, self._page("Dataset collection is disabled")
        try:
            sample_id = int(path.removeprefix("/dataset/"))
        except ValueError:
            return 404, {}, self._page("Sample not found")
        sample = self.training_store.sample(sample_id)
        if sample is None:
            return 404, {}, self._page("Sample not found")
        if method == "POST":
            values = parse_qs(body.decode("utf-8"), strict_parsing=True)
            if not secrets.compare_digest(
                values.get("token", [""])[0], self._csrf_token
            ):
                return 400, {}, self._page("Invalid action token")
            action = values.get("action", [""])[0]
            if action == "delete":
                self.training_store.delete(sample_id)
            elif action in {"spam", "legitimate", "uncertain"}:
                self.training_store.label(sample_id, action)
            else:
                return 400, {}, self._page("Unknown action")
            return 303, {"Location": "/dataset"}, b""
        if method != "GET":
            return 405, {"Allow": "GET, POST"}, self._page("Method not allowed")
        payload = sample.payload
        text = str(payload.get("text", ""))
        quote_text = str(payload.get("quote_text", ""))
        preview_text = str(payload.get("preview_text", ""))
        domains = ", ".join(str(value) for value in payload.get("domains", [])) or "—"
        quote_domains = (
            ", ".join(str(value) for value in payload.get("quote_domains", [])) or "—"
        )
        url_shape = json.dumps(payload.get("url_shape", {}), indent=2, sort_keys=True)
        quote_url_shape = json.dumps(
            payload.get("quote_url_shape", {}), indent=2, sort_keys=True
        )
        structural_only = not (
            text.strip() or quote_text.strip() or preview_text.strip()
        )
        details = html.escape(json.dumps(payload, ensure_ascii=False, indent=2))
        actions = "".join(
            self._action_form(sample_id, label, label.title(), base="dataset")
            for label in ("spam", "legitimate", "uncertain")
        ) + self._action_form(
            sample_id, "delete", "Delete sample", danger=True, base="dataset"
        )
        content = (
            self._masthead("Dataset sample", f"#{sample.id}")
            + "<p class='back'><a href='/dataset'>← Dataset</a></p>"
            + "<main><section class='message-panel'><p class='eyebrow'>Message text or caption</p>"
            + (f"<pre class='message'>{html.escape(text)}</pre>" if text else "")
            + (
                f"<p class='eyebrow'>Quoted context</p><pre class='message quote'>"
                f"{html.escape(quote_text)}</pre>"
                if quote_text
                else ""
            )
            + (
                f"<p class='eyebrow'>Telegram webpage preview</p><pre class='message quote'>"
                f"{html.escape(preview_text)}</pre>"
                if preview_text
                else ""
            )
            + (
                "<div class='notice'><strong>Structural-only sample.</strong> No message, quoted, or preview text was retained. Review the detector signals and structural metadata; choose Uncertain when the evidence is insufficient.</div>"
                if structural_only
                else ""
            )
            + f"<p class='content-label'>Normalized domains</p><pre>{html.escape(domains)}</pre>"
            + f"<p class='content-label'>Quoted-context domains</p><pre>{html.escape(quote_domains)}</pre>"
            + f"<details><summary>Link shape</summary><pre>{html.escape(url_shape)}</pre></details>"
            + f"<details><summary>Quoted-context link shape</summary><pre>{html.escape(quote_url_shape)}</pre></details>"
            + f"<details><summary>Encrypted payload metadata</summary><pre>{details}</pre></details>"
            + f"<div class='actions'>{actions}</div></section></main>"
        )
        return 200, {}, self._page(content, raw=True)

    async def _dispatch_enforcement(
        self, method: str, path: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        sender_key = path.removeprefix("/enforcement/")
        if len(sender_key) != 64 or any(char not in "0123456789abcdef" for char in sender_key):
            return 404, {}, self._page("Enforcement record not found")
        item = self.store.enforcement_review(sender_key)
        if item is None:
            return 404, {}, self._page("Enforcement record not found")
        if method == "GET":
            return await self._show_enforcement(item)
        if method != "POST":
            return 405, {"Allow": "GET, POST"}, self._page("Method not allowed")
        values = parse_qs(body.decode("utf-8"), strict_parsing=True)
        if not secrets.compare_digest(values.get("token", [""])[0], self._csrf_token):
            return 400, {}, self._page("Invalid action token")
        action = values.get("action", [""])[0]
        if action == "keep":
            return 303, {"Location": "/enforcement"}, b""
        if action != "allow":
            return 400, {}, self._page("Unknown action")
        async with self.service.sender_lock(sender_key):
            item = self.store.enforcement_review(sender_key)
            if item is None:
                return 409, {}, self._page("This enforcement record has expired")
            if item.reference is None:
                return 409, {}, self._page("Telegram identity is unavailable")
            try:
                user_id, access_hash, _ = self.protector.open_review_reference(
                    item.reference
                )
            except ValueError:
                return 409, {}, self._page("Telegram identity is unavailable")
            peer = types.InputPeerUser(user_id=user_id, access_hash=access_hash)
            if not await self._restore(peer, sender_key):
                return 500, {}, self._page("Telegram action failed; item was not changed")
            self.store.allow(sender_key)
            self.cancel_timeout(sender_key)
            self._identity_cache.pop(sender_key, None)
        return 303, {"Location": "/enforcement"}, b""

    async def _enforcement_index_page(self) -> bytes:
        items = self.store.enforcement_reviews()
        identities = await self._live_enforcement_identities(items)
        stats = self.store.enforcement_statistics()
        rows = "".join(
            f"<tr><td><a href='/enforcement/{item.sender_key}'>Open</a></td>"
            f"<td>{self._identity_cell(identities.get(item.sender_key))}</td>"
            f"<td><span class='badge'>{html.escape(item.status)}</span></td>"
            f"<td>{html.escape(item.reason)}</td>"
            f"<td>{html.escape(self._remaining(item))}</td>"
            f"<td>{html.escape(self._relative_age(item.updated_at))}</td></tr>"
            for item in items
        ) or "<tr><td colspan='6'>No reviewable active restrictions.</td></tr>"
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
            f"{stats['unreviewable']} active restriction"
            f"{'s' if stats['unreviewable'] != 1 else ''} "
            f"{'have' if stats['unreviewable'] != 1 else 'has'} no encrypted snapshot "
            "and cannot be opened here. Such states may predate snapshot collection."
            if stats["unreviewable"]
            else "Every active restriction currently has a reviewable snapshot."
        )
        content = (
            self._masthead("Active enforcement", f"{len(items)} reviewable")
            + "<p class='back'><a href='/'>← Review queue</a> · <a href='/dataset'>Dataset</a></p>"
            + "<main><section class='queue-intro'><p class='eyebrow'>Protect mode state</p>"
            + "<h2>Review active restrictions</h2>"
            + "<p>Encrypted snapshots preserve the original triggering message and quoted context for up to seven days. Telegram block is not used.</p>"
            + "<dl class='metric-grid'>"
            + f"<div><dt>Quarantined</dt><dd class='data-value'>{stats['quarantined']}</dd></div>"
            + f"<div><dt>Suppressed</dt><dd class='data-value'>{stats['suppressed']}</dd></div>"
            + f"<div><dt>Reviewable snapshots</dt><dd class='data-value'>{stats['reviewable']}</dd></div></dl>"
            + f"<p class='refresh-note'><strong>State reasons:</strong> {reasons}. {snapshot_note}</p></section>"
            + "<div class='table-shell'><table><thead><tr><th>Case</th><th>Sender</th><th>Status</th><th>Reason</th><th>Restriction</th><th>Updated</th></tr></thead>"
            + f"<tbody>{rows}</tbody></table></div></main>"
        )
        return self._page(content, raw=True, refresh_seconds=10)

    async def _show_enforcement(
        self, item: EnforcementReview
    ) -> tuple[int, dict[str, str], bytes]:
        if self.service.review_content_protector is None:
            return 500, {}, self._page("Encrypted review content is unavailable")
        try:
            payload = self.service.review_content_protector.open_enforcement(
                item.envelope
            )
        except ValueError:
            return 500, {}, self._page("Encrypted review content is unavailable")
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
        text = str(payload.get("text", "")) or "[No text or caption]"
        quote_text = str(payload.get("quote_text", ""))
        rules = ", ".join(str(value) for value in payload.get("rule_codes", [])) or "—"
        features = json.dumps(payload.get("features", {}), indent=2, sort_keys=True)
        observed = datetime.fromtimestamp(item.created_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        allow_action = (
            self._action_form(
                item.sender_key, "allow", "Allow now", base="enforcement"
            )
            if user_id is not None
            else "<button type='button' disabled>Allow unavailable</button>"
        )
        content = f"""
        {self._masthead("Active enforcement", item.status)}
        <p class="back"><a href="/enforcement">← Active enforcement</a></p>
        <main class="review-grid"><section class="message-panel">
          <p class="eyebrow">Encrypted local review snapshot</p>
          <h2>{html.escape(identity)}</h2>
          <p class="content-label">Original message or caption</p>
          <pre class="message">{html.escape(text)}</pre>
          {f'<p class="content-label">Quoted context</p><pre class="message quote">{html.escape(quote_text)}</pre>' if quote_text else ''}
          {telegram_link}
        </section><aside class="case-file"><p class="eyebrow">Restriction details</p>
          <dl><dt>Status</dt><dd><span class="badge">{html.escape(item.status)}</span></dd>
          <dt>Reason</dt><dd>{html.escape(item.reason)}</dd><dt>Rules</dt><dd>{html.escape(rules)}</dd>
          <dt>Triggered</dt><dd>{observed}</dd><dt>Restriction</dt><dd>{html.escape(self._remaining(item))}</dd>
          <dt>Snapshot expires</dt><dd>{datetime.fromtimestamp(item.expires_at, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</dd></dl>
          <details><summary>Structural features</summary><pre>{html.escape(features)}</pre></details>
        </aside></main><section class="decision-panel"><p class="eyebrow">Sender decision</p>
          <h2>Allow restores the saved folder and notification state before changing policy.</h2>
          <div class="actions two">
            {allow_action}
            {self._action_form(item.sender_key, "keep", "Keep current restriction", base="enforcement")}
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
            reply_header = getattr(message, "reply_to", None)
            payload: dict[str, object] = {
                "schema_version": 1,
                "text": getattr(message, "message", None) or "",
                "quote_text": getattr(reply_header, "quote_text", None) or "",
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
            return 409, {}, self._page("This item is no longer pending")
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

    async def _index_page(self) -> bytes:
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
            self._masthead("Review queue", f"{len(items)} pending")
            + "<p class='back'><a href='/enforcement'>Active enforcement</a> · <a href='/dataset'>Dataset</a></p>"
            + "<main><section class='queue-intro'><p class='eyebrow'>Pending reviews</p>"
            "<h2>Review pending senders</h2>"
            "<p>Sender identity is fetched from Telegram and cached briefly in memory. "
            "Message content is fetched only when a review item is opened.</p>"
            "<p>Deleting a conversation in Telegram does not remove its local pending review. "
            "Open the row and resolve it when the referenced message is unavailable.</p>"
            "<p class='refresh-note'>This page checks the connection every 10 seconds and shows "
            "an error when the SSH tunnel is unavailable.</p></section>"
            "<div class='table-shell'><table><thead><tr><th>Case</th><th>Sender</th><th>Simulation</th>"
            "<th>Rules</th><th>Messages</th>"
            f"<th>Last seen</th></tr></thead><tbody>{rows}</tbody></table></div></main>",
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
                "Invalid access token": (
                    "This login link is invalid or has already been used. Run "
                    "the tunnel helper again to generate a new one-time link."
                ),
                "Not found": (
                    "The page is unavailable or the dashboard session is missing. "
                    "Open the one-time link printed by the tunnel helper."
                ),
                "Request failed": (
                    "The request could not be completed. No dashboard action was confirmed."
                ),
            }.get(content, "Check the request and return to the dashboard.")
            body = (
                cls._masthead("Error", "Request not completed")
                + "<main class='error-layout'><section class='error-card'>"
                + "<div class='error-content'>"
                + "<p class='eyebrow'>Dashboard error</p>"
                + f"<h1>{html.escape(content)}</h1>"
                + f"<p>{html.escape(guidance)}</p>"
                + "<p class='error-command'><code>scripts/review-tunnel.sh SSH_TARGET</code></p>"
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
{refresh}<title>Gatekeeper review</title><style>
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
