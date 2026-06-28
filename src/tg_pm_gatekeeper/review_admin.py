from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import secrets
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from telethon import functions, types

from .crypto import IdentifierProtector
from .store import ReviewItem, StateStore


LOG = logging.getLogger("gatekeeper.review")
MAX_HEADER_BYTES = 16 * 1024
MAX_BODY_BYTES = 4 * 1024


class ReviewAdminServer:
    def __init__(
        self,
        socket_path: Path,
        store: StateStore,
        protector: IdentifierProtector,
        telegram_client,
        *,
        mute_days: int,
    ) -> None:
        self.socket_path = socket_path
        self.store = store
        self.protector = protector
        self.telegram_client = telegram_client
        self.mute_days = mute_days
        self._server: asyncio.AbstractServer | None = None
        self._csrf_token = secrets.token_urlsafe(32)

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

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            method, target, body = await self._read_request(reader)
            status, headers, response = await self._dispatch(method, target, body)
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
    ) -> tuple[str, str, bytes]:
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
        return parts[0], parts[1], await reader.readexactly(content_length)

    async def _dispatch(
        self, method: str, target: str, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        path = urlsplit(target).path
        if path == "/" and method == "GET":
            return 200, {}, self._index_page()
        if not path.startswith("/review/"):
            return 404, {}, self._page("Not found")
        try:
            review_id = int(path.removeprefix("/review/"))
        except ValueError:
            return 404, {}, self._page("Not found")
        item = self.store.review_item(review_id)
        if item is None:
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
        if item.status != "pending" or item.reference is None:
            return 409, {}, self._page("This item has already been reviewed")
        if action == "legitimate":
            self.store.allow(item.sender_key)
            self.store.decide_sender_reviews(item.sender_key, "legitimate")
        elif action == "spam":
            peer = self._peer_from_item(item)
            if not await self._archive_and_mute(peer):
                return 500, {}, self._page("Telegram action failed; item was not changed")
            self.store.quarantine(item.sender_key)
            self.store.decide_sender_reviews(item.sender_key, "spam")
        elif action == "dismiss":
            self.store.decide_sender_reviews(item.sender_key, "dismissed")
        else:
            return 400, {}, self._page("Unknown action")
        return 303, {"Location": "/"}, b""

    def _peer_from_item(self, item: ReviewItem) -> types.InputPeerUser:
        if item.reference is None:
            raise ValueError("review reference has expired")
        user_id, access_hash, _ = self.protector.open_review_reference(item.reference)
        return types.InputPeerUser(user_id=user_id, access_hash=access_hash)

    async def _show_review(
        self, item: ReviewItem
    ) -> tuple[int, dict[str, str], bytes]:
        if item.status != "pending" or item.reference is None:
            return 409, {}, self._page("This item is no longer pending")
        user_id, access_hash, message_id = self.protector.open_review_reference(
            item.reference
        )
        peer = types.InputPeerUser(user_id=user_id, access_hash=access_hash)
        message = await self.telegram_client.get_messages(peer, ids=message_id)
        sender = await self.telegram_client.get_entity(peer)
        if message is None:
            return 404, {}, self._page("The Telegram message is no longer available")
        name = " ".join(
            value
            for value in (
                getattr(sender, "first_name", None),
                getattr(sender, "last_name", None),
            )
            if value
        ) or "Unnamed sender"
        username = getattr(sender, "username", None)
        identity = name + (f" (@{username})" if username else "")
        text = message.message or f"[Non-text message: {type(message.media).__name__}]"
        rules = ", ".join(json.loads(item.rule_codes)) or "ordinary unknown sender"
        features = json.dumps(json.loads(item.features), indent=2, sort_keys=True)
        observed_at = datetime.fromtimestamp(item.updated_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        content = f"""
        {self._masthead("Decision desk", f"Review #{item.id}")}
        <p class="back"><a href="/">← Back to pending queue</a></p>
        <main class="review-grid">
          <section class="message-panel">
            <p class="eyebrow">Live from Telegram · not stored locally</p>
            <h2>{html.escape(identity)}</h2>
            <pre class="message">{html.escape(text)}</pre>
            <a class="telegram-link" href="tg://user?id={user_id}">Open this conversation in Telegram ↗</a>
          </section>
          <aside class="case-file">
            <p class="eyebrow">Case file</p>
            <dl><dt>Simulated decision</dt><dd><span class="badge">{html.escape(item.classification)}</span></dd>
            <dt>Rules</dt><dd>{html.escape(rules)}</dd>
            <dt>Messages observed</dt><dd>{item.message_count}</dd>
            <dt>Last observed</dt><dd>{observed_at}</dd></dl>
            <details><summary>Structural features</summary><pre>{html.escape(features)}</pre></details>
          </aside>
        </main>
        <section class="decision-panel"><p class="eyebrow">Resolve this sender</p>
          <h2>One decision clears every pending item for this conversation.</h2>
          <div class="actions">
            {self._action_form(item.id, "legitimate", "Legitimate · allow sender")}
            {self._action_form(item.id, "spam", "Spam · archive and mute", danger=True)}
            {self._action_form(item.id, "dismiss", "Dismiss without action")}
          </div>
        </section>
        """
        return 200, {}, self._page(content, raw=True, refresh_seconds=30)

    async def _archive_and_mute(self, peer: types.InputPeerUser) -> bool:
        try:
            await self.telegram_client(
                functions.folders.EditPeerFoldersRequest(
                    [types.InputFolderPeer(peer=peer, folder_id=1)]
                )
            )
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
            LOG.error("review_quarantine_failed")
            return False

    def _index_page(self) -> bytes:
        items = self.store.review_items()
        rows = "".join(
            f"<tr><td><a href='/review/{item.id}'>#{item.id}</a></td>"
            f"<td>{html.escape(item.classification)}</td>"
            f"<td>{html.escape(', '.join(json.loads(item.rule_codes)) or '—')}</td>"
            f"<td>{item.message_count}</td>"
            f"<td>{html.escape(self._relative_age(item.updated_at))}</td></tr>"
            for item in items
        )
        if not rows:
            rows = "<tr><td colspan='5'>No pending reviews.</td></tr>"
        return self._page(
            self._masthead("Observation desk", f"{len(items)} pending")
            + "<main><section class='queue-intro'><p class='eyebrow'>Private review channel</p>"
            "<h2>Decisions waiting for a human signal.</h2>"
            "<p>Queue rows contain only rules and structural facts. Message content is fetched "
            "live from Telegram when you open a case.</p>"
            "<p class='refresh-note'>Connection check repeats every 10 seconds. If the tunnel "
            "closes, the next check will replace this page with a connection error.</p></section>"
            "<div class='table-shell'><table><thead><tr><th>Case</th><th>Simulation</th>"
            "<th>Rules</th><th>Messages</th>"
            f"<th>Last seen</th></tr></thead><tbody>{rows}</tbody></table></div></main>",
            raw=True,
            refresh_seconds=10,
        )

    @staticmethod
    def _masthead(section: str, status: str) -> str:
        checked_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        return (
            "<header class='masthead'><div><span class='mark'>TG</span>"
            "<span class='product'>PM Gatekeeper</span></div>"
            "<div class='connection'><span class='live'><i></i>Live connection</span>"
            f"<small>Response {checked_at}</small></div>"
            f"<div class='section'>{html.escape(section)}<span>{html.escape(status)}</span></div>"
            "</header>"
        )

    def _action_form(
        self, review_id: int, action: str, label: str, *, danger: bool = False
    ) -> str:
        button_class = " class='danger'" if danger else ""
        return (
            f"<form method='post' action='/review/{review_id}'>"
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
    def _page(
        content: str, *, raw: bool = False, refresh_seconds: int | None = None
    ) -> bytes:
        body = content if raw else f"<h1>{html.escape(content)}</h1>"
        refresh = (
            f'<meta http-equiv="refresh" content="{refresh_seconds}">'
            if refresh_seconds is not None
            else ""
        )
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{refresh}<title>Gatekeeper review</title><style>
:root{{--ink:#17211d;--muted:#68726c;--paper:#f3efe5;--panel:#fffdf7;--line:#c9c3b5;--signal:#e2532f;--safe:#1e6b52}}
*{{box-sizing:border-box}}body{{margin:0;color:var(--ink);background:var(--paper);font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}}
body:before{{content:"";position:fixed;inset:0;pointer-events:none;opacity:.18;background-image:repeating-linear-gradient(90deg,transparent 0 47px,#8f8878 48px),repeating-linear-gradient(0deg,transparent 0 47px,#8f8878 48px)}}
.masthead,main,.back,.decision-panel{{position:relative;max-width:1120px;margin-left:auto;margin-right:auto}}
.masthead{{display:grid;grid-template-columns:1fr auto auto;gap:2.5rem;align-items:center;padding:2rem 1.25rem 1.1rem;border-bottom:2px solid var(--ink)}}
.mark{{display:inline-grid;place-items:center;width:2.5rem;height:2.5rem;margin-right:.8rem;color:var(--paper);background:var(--ink);font-weight:800;letter-spacing:-.08em}}
.product{{font:700 1.15rem Georgia,serif;letter-spacing:.03em}}.section{{text-transform:uppercase;font-size:.72rem;letter-spacing:.12em;text-align:right}}
.section span{{display:block;color:var(--signal);font-weight:800;margin-top:.25rem}}main{{padding:3rem 1.25rem 5rem}}
.connection{{padding:.5rem .75rem;border:1px solid var(--line);background:var(--panel)}}.connection small{{display:block;margin-top:.2rem;color:var(--muted);font-size:.62rem;letter-spacing:.05em}}.live{{display:flex;align-items:center;gap:.5rem;color:var(--safe);font-size:.68rem;font-weight:900;text-transform:uppercase;letter-spacing:.1em}}.live i{{width:.55rem;height:.55rem;border-radius:50%;background:#2cab76;box-shadow:0 0 0 4px #d8f0e6;animation:pulse 2s infinite}}@keyframes pulse{{50%{{box-shadow:0 0 0 7px transparent}}}}
.queue-intro{{max-width:960px;margin-bottom:2.5rem}}h1,h2{{font-family:Georgia,serif;line-height:1.1}}.queue-intro h2{{font-size:clamp(1.85rem,3.6vw,3rem);font-weight:400;letter-spacing:-.03em;margin:.55rem 0 1.3rem}}
.queue-intro p{{max-width:none;color:var(--muted)}}.refresh-note{{margin-top:1.2rem;padding-left:1rem;border-left:3px solid var(--safe);font-size:.78rem}}.eyebrow{{margin:0;text-transform:uppercase;letter-spacing:.13em;font-size:.7rem;font-weight:800;color:var(--signal)}}
.table-shell{{overflow-x:auto;border:1px solid var(--line);background:var(--panel);box-shadow:8px 8px 0 var(--ink)}}table{{border-collapse:collapse;width:100%;min-width:720px}}
th,td{{padding:1rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}}tbody tr:last-child td{{border-bottom:0}}tbody tr:hover{{background:#f8e9d8}}a{{color:var(--ink);text-underline-offset:.22em}}td:first-child a{{font-weight:900;color:var(--signal)}}
.back{{padding:1.25rem 1.25rem 0}}.review-grid{{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(280px,.75fr);gap:1.5rem;padding-bottom:2rem}}
.message-panel,.case-file,.decision-panel{{border:1px solid var(--line);background:var(--panel);padding:clamp(1.25rem,4vw,2.4rem)}}.message-panel h2{{font-size:2rem;margin:.5rem 0 1.8rem}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere}}pre.message{{min-height:180px;margin:0 0 1.5rem;padding:1.4rem;background:var(--ink);color:#f7f1df;font:1rem/1.65 Georgia,serif;border-left:5px solid var(--signal)}}
.telegram-link{{font-weight:800}}dt{{font-size:.66rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}}dd{{margin:.2rem 0 1.2rem}}.badge{{display:inline-block;padding:.2rem .45rem;background:#f8e9d8;border:1px solid var(--signal);color:#9d3118;font-weight:800}}
details{{border-top:1px solid var(--line);padding-top:1rem}}summary{{cursor:pointer;font-weight:800}}details pre{{font-size:.75rem;color:var(--muted)}}.decision-panel{{margin-bottom:4rem;border-top:5px solid var(--ink)}}.decision-panel h2{{max-width:680px;font-size:1.7rem}}
.actions{{display:flex;gap:.75rem;flex-wrap:wrap;margin-top:1.5rem}}button{{padding:.8rem 1rem;border:1px solid var(--ink);background:transparent;color:var(--ink);font:700 .78rem ui-monospace,monospace;cursor:pointer;box-shadow:3px 3px 0 var(--ink);transition:transform .12s,box-shadow .12s}}button:hover{{transform:translate(2px,2px);box-shadow:1px 1px 0 var(--ink)}}button.danger{{background:var(--signal);color:#fff;border-color:#9d3118}}
@media(max-width:760px){{.masthead{{grid-template-columns:1fr auto;gap:1rem}}.connection{{grid-column:1/-1;grid-row:2}}.review-grid{{grid-template-columns:1fr}}.section{{max-width:100%}}main{{padding-top:2rem}}}}
</style></head><body>{body}</body></html>""".encode("utf-8")
