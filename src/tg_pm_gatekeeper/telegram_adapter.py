from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from telethon import TelegramClient, events, functions, types
from telethon.sessions import StringSession

from .config import Settings, read_private_file
from .rules import MessageFacts, URL_RE, normalized_domain
from .service import GatekeeperService, IncomingMessage
from .store import StateStore


LOG = logging.getLogger("gatekeeper.telegram")
SERVICE_USER_IDS = {777000, 42777}
HEARTBEAT_PATH = Path("/tmp/gatekeeper-heartbeat")
PRUNE_INTERVAL_SECONDS = 12 * 60 * 60
LINK_BUTTON_TYPES = (
    types.KeyboardButtonUrl,
    types.KeyboardButtonUrlAuth,
    types.KeyboardButtonWebView,
    types.KeyboardButtonSimpleWebView,
)
GATEKEEPER_MESSAGE_PREFIXES = (
    "To filter spam,",
    "Incorrect answer.",
    "Verification passed.",
)


def load_denylist(path: Path | None) -> frozenset[str]:
    if path is None or not path.exists():
        return frozenset()
    values: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip().casefold().rstrip(".")
        if value and not value.startswith("#") and "/" not in value:
            values.add(value)
    return frozenset(values)


def _entity_text(text: str, offset: int, length: int) -> str:
    encoded = text.encode("utf-16-le")
    start = offset * 2
    end = (offset + length) * 2
    return encoded[start:end].decode("utf-16-le", errors="ignore")


def facts_from_message(message: types.Message) -> MessageFacts:
    text = message.message or ""
    urls = set(URL_RE.findall(text))
    for entity in message.entities or []:
        if isinstance(entity, types.MessageEntityTextUrl):
            urls.add(entity.url)
        elif isinstance(entity, types.MessageEntityUrl):
            urls.add(_entity_text(text, entity.offset, entity.length))

    has_link_button = False
    has_any_button = False
    markup = message.reply_markup
    for row in getattr(markup, "rows", ()) or ():
        for button in getattr(row, "buttons", ()) or ():
            has_any_button = True
            if isinstance(button, LINK_BUTTON_TYPES):
                has_link_button = True
                url = getattr(button, "url", None)
                if url:
                    urls.add(url)

    webpage = getattr(message.media, "webpage", None)
    webpage_url = getattr(webpage, "url", None)
    if webpage_url:
        urls.add(webpage_url)
    domains = tuple(
        sorted({domain for url in urls if (domain := normalized_domain(url))})
    )
    return MessageFacts(
        text=text,
        urls=tuple(sorted(urls)),
        domains=domains,
        has_link_button=has_link_button,
        has_any_button=has_any_button,
        is_forwarded=message.fwd_from is not None,
        via_bot=message.via_bot_id is not None,
    )


def write_runtime_heartbeat(path: Path, timestamp: int) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(str(timestamp), encoding="ascii")
    os.replace(temporary, path)


class EventActions:
    def __init__(self, adapter: "TelegramAdapter", event, sender_key: str) -> None:
        self.adapter = adapter
        self.event = event
        self.sender_key = sender_key

    async def send_text(self, text: str) -> None:
        await self.adapter.client.send_message(
            self.event.input_chat, text, link_preview=False
        )

    async def archive_and_mute(self) -> bool:
        try:
            peer = self.event.input_chat
            await self.adapter.client(
                functions.folders.EditPeerFoldersRequest(
                    [types.InputFolderPeer(peer=peer, folder_id=1)]
                )
            )
            await self.adapter.client(
                functions.account.UpdateNotifySettingsRequest(
                    peer=types.InputNotifyPeer(peer),
                    settings=types.InputPeerNotifySettings(
                        silent=True,
                        mute_until=datetime.now(timezone.utc)
                        + timedelta(days=self.adapter.settings.mute_days),
                    ),
                )
            )
            return True
        except Exception:
            LOG.error("quarantine_action_failed")
            return False

    async def restore_from_pending(self) -> bool:
        try:
            peer = self.event.input_chat
            await self.adapter.client(
                functions.folders.EditPeerFoldersRequest(
                    [types.InputFolderPeer(peer=peer, folder_id=0)]
                )
            )
            await self.adapter.client(
                functions.account.UpdateNotifySettingsRequest(
                    peer=types.InputNotifyPeer(peer),
                    settings=types.InputPeerNotifySettings(
                        silent=False,
                        mute_until=datetime.now(timezone.utc),
                    ),
                )
            )
            return True
        except Exception:
            LOG.error("restore_action_failed")
            return False

    def schedule_timeout(self, sender_key: str, expires_at: int) -> None:
        self.adapter.schedule_timeout(sender_key, expires_at, self)

    def cancel_timeout(self, sender_key: str) -> None:
        self.adapter.cancel_timeout(sender_key)


class TelegramAdapter:
    def __init__(
        self, settings: Settings, store: StateStore, service: GatekeeperService
    ) -> None:
        self.settings = settings
        self.store = store
        self.service = service
        session = read_private_file(
            settings.session_file, minimum_bytes=64, strip=True
        ).decode("ascii")
        self.client = TelegramClient(
            StringSession(session),
            settings.api_id,
            settings.api_hash,
            flood_sleep_threshold=60,
            auto_reconnect=True,
            receive_updates=True,
        )
        self._timeout_tasks: dict[str, asyncio.Task] = {}
        self._heartbeat_task: asyncio.Task | None = None

    async def run(self) -> None:
        await self.client.connect()
        if not await self.client.is_user_authorized():
            raise RuntimeError("telegram session is not authorized")
        await self.client.get_me()
        self.client.add_event_handler(
            self._on_message, events.NewMessage(incoming=True)
        )
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        LOG.info("service_started")
        try:
            await self.client.run_until_disconnected()
        finally:
            if self._heartbeat_task:
                self._heartbeat_task.cancel()
            for task in self._timeout_tasks.values():
                task.cancel()
            await self.client.disconnect()

    async def _heartbeat_loop(self) -> None:
        next_prune = 0
        while True:
            now = int(time.time())
            self.store.heartbeat(now)
            write_runtime_heartbeat(HEARTBEAT_PATH, now)
            if now >= next_prune:
                self.store.prune(self.settings.audit_retention_days, now)
                next_prune = now + PRUNE_INTERVAL_SECONDS
            await asyncio.sleep(60)

    async def _on_message(self, event) -> None:
        try:
            if not event.is_private or not isinstance(event.message, types.Message):
                return
            sender = await event.get_sender()
            sender_id = getattr(sender, "id", None)
            if not isinstance(sender_id, int):
                return
            sender_key = self.service.protector.sender_key(sender_id)
            trusted_history = False
            if (
                self.store.sender(sender_key).status == "unknown"
                and not getattr(sender, "bot", False)
                and not getattr(sender, "contact", False)
                and sender_id not in SERVICE_USER_IDS
            ):
                trusted_history = await self._has_prior_outgoing(event)
            incoming = IncomingMessage(
                sender_id=sender_id,
                message_id=event.message.id,
                text=event.message.message or "",
                facts=facts_from_message(event.message),
                is_contact=bool(getattr(sender, "contact", False)),
                is_bot=bool(getattr(sender, "bot", False)),
                is_service=sender_id in SERVICE_USER_IDS,
                has_trusted_history=trusted_history,
            )
            actions = EventActions(self, event, sender_key)
            outcome = await self.service.handle(incoming, actions)
            LOG.info(f"message_handled:{outcome}")
        except Exception:
            LOG.error("event_handler_failed")

    async def _has_prior_outgoing(self, event) -> bool:
        async for message in self.client.iter_messages(event.input_chat, limit=50):
            text = message.message or ""
            generated_by_gatekeeper = text.startswith(GATEKEEPER_MESSAGE_PREFIXES)
            if (
                message.id != event.message.id
                and message.out
                and not generated_by_gatekeeper
            ):
                return True
        return False

    def schedule_timeout(
        self, sender_key: str, expires_at: int, actions: EventActions
    ) -> None:
        self.cancel_timeout(sender_key)
        self._timeout_tasks[sender_key] = asyncio.create_task(
            self._timeout_worker(sender_key, expires_at, actions)
        )

    def cancel_timeout(self, sender_key: str) -> None:
        task = self._timeout_tasks.pop(sender_key, None)
        if task and task is not asyncio.current_task():
            task.cancel()

    async def _timeout_worker(
        self, sender_key: str, expires_at: int, actions: EventActions
    ) -> None:
        try:
            await asyncio.sleep(max(0, expires_at - int(time.time())))
            state = self.store.sender(sender_key)
            if (
                self.store.get_mode() == "enforce"
                and state.status == "challenged"
                and state.challenge_expires_at == expires_at
            ):
                if await actions.archive_and_mute():
                    self.store.quarantine(sender_key)
                    self.store.audit(sender_key, "CHALLENGE_TIMEOUT", "archived_muted")
        except asyncio.CancelledError:
            pass
        except Exception:
            LOG.error("timeout_action_failed")
        finally:
            if self._timeout_tasks.get(sender_key) is asyncio.current_task():
                self._timeout_tasks.pop(sender_key, None)
