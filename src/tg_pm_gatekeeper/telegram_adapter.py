from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from telethon import TelegramClient, events, functions, types
from telethon.sessions import StringSession

from .config import ConfigurationError, Settings, read_private_file
from .rules import MessageFacts, URL_RE, normalized_domain
from .review_admin import ReviewAdminServer
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
    "Verification required",
    "Please use Telegram's Reply action",
    "Reply with digits only.",
    "Incorrect answer.",
    "Verification passed.",
)


def load_denylist(path: Path | None) -> frozenset[str]:
    if path is None:
        return frozenset()
    if not path.is_file():
        raise ConfigurationError("configured denylist file is missing or invalid")
    values: set[str] = set()
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if "/" in value or ":" in value:
            raise ConfigurationError(f"invalid denylist entry on line {line_number}")
        domain = normalized_domain(value)
        if domain is None:
            raise ConfigurationError(f"invalid denylist entry on line {line_number}")
        values.add(domain)
    return frozenset(values)


def _entity_text(text: str, offset: int, length: int) -> str:
    encoded = text.encode("utf-16-le")
    start = offset * 2
    end = (offset + length) * 2
    return encoded[start:end].decode("utf-16-le", errors="ignore")


def _urls_from_text_and_entities(text: str, entities) -> set[str]:
    urls = set(URL_RE.findall(text))
    for entity in entities or []:
        if isinstance(entity, types.MessageEntityTextUrl):
            urls.add(entity.url)
        elif isinstance(entity, types.MessageEntityUrl):
            urls.add(_entity_text(text, entity.offset, entity.length))
    return urls


def facts_from_message(message: types.Message) -> MessageFacts:
    text = message.message or ""
    urls = _urls_from_text_and_entities(text, message.entities)
    reply_header = getattr(message, "reply_to", None)
    quote_text = getattr(reply_header, "quote_text", None) or ""
    quote_entities = getattr(reply_header, "quote_entities", None) or ()
    quote_urls = _urls_from_text_and_entities(quote_text, quote_entities)

    has_link_button = False
    link_button_count = 0
    has_any_button = False
    markup = message.reply_markup
    for row in getattr(markup, "rows", ()) or ():
        for button in getattr(row, "buttons", ()) or ():
            has_any_button = True
            if isinstance(button, LINK_BUTTON_TYPES):
                has_link_button = True
                link_button_count += 1
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
    quote_domains = tuple(
        sorted(
            {domain for url in quote_urls if (domain := normalized_domain(url))}
        )
    )
    return MessageFacts(
        text=text,
        quote_text=quote_text,
        urls=tuple(sorted(urls)),
        domains=domains,
        quote_urls=tuple(sorted(quote_urls)),
        quote_domains=quote_domains,
        has_link_button=has_link_button,
        link_button_count=link_button_count,
        has_any_button=has_any_button,
        is_forwarded=message.fwd_from is not None,
        via_bot=message.via_bot_id is not None,
    )


def reply_to_message_id(message: types.Message) -> int | None:
    reply_header = getattr(message, "reply_to", None)
    value = getattr(reply_header, "reply_to_msg_id", None)
    return value if isinstance(value, int) else None


def message_timestamp(message: types.Message, *, fallback: int) -> int:
    date = getattr(message, "date", None)
    return int(date.timestamp()) if date is not None else fallback


def write_runtime_heartbeat(path: Path, timestamp: int) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(str(timestamp), encoding="ascii")
    os.replace(temporary, path)


class TelegramActions:
    def __init__(self, adapter: "TelegramAdapter", peer, sender_key: str) -> None:
        self.adapter = adapter
        self.peer = peer
        self.sender_key = sender_key

    async def send_text(
        self, text: str, *, reply_to_message_id: int | None = None
    ) -> int:
        message = await self.adapter.client.send_message(
            self.peer,
            text,
            reply_to=reply_to_message_id,
            link_preview=False,
        )
        return int(message.id)

    async def archive_and_mute(self) -> bool:
        archive_applied = False
        try:
            peer = self.peer
            await self.adapter.client(
                functions.folders.EditPeerFoldersRequest(
                    [types.InputFolderPeer(peer=peer, folder_id=1)]
                )
            )
            archive_applied = True
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
            if archive_applied:
                await self.restore_from_pending()
            LOG.error("quarantine_action_failed")
            return False

    async def restore_from_pending(self) -> bool:
        try:
            peer = self.peer
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

    def schedule_timeout(
        self, sender_key: str, expires_at: int, *, grace_seconds: int = 5
    ) -> None:
        self.adapter.schedule_timeout(sender_key, expires_at, grace_seconds=grace_seconds)

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
        self._review_admin = ReviewAdminServer(
            settings.review_socket_path,
            store,
            service,
            self.client,
            mute_days=settings.mute_days,
            cancel_timeout=self.cancel_timeout,
        )

    async def run(self) -> None:
        await self.client.connect()
        if not await self.client.is_user_authorized():
            raise RuntimeError("telegram session is not authorized")
        await self.client.get_me()
        await self._recover_challenges()
        await self._review_admin.start()
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
            await self._review_admin.stop()
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
            state = self.store.sender(sender_key)
            trusted_history = False
            if (
                state.status in {"unknown", "provisional"}
                and not getattr(sender, "bot", False)
                and not getattr(sender, "contact", False)
                and sender_id not in SERVICE_USER_IDS
            ):
                trusted_history = await self._has_prior_outgoing(
                    event,
                    sender_key,
                    since=state.updated_at if state.status == "provisional" else None,
                )
            sent_at = message_timestamp(event.message, fallback=int(time.time()))
            incoming = IncomingMessage(
                sender_id=sender_id,
                message_id=event.message.id,
                text=event.message.message or "",
                facts=facts_from_message(event.message),
                sent_at=sent_at,
                reply_to_message_id=reply_to_message_id(event.message),
                is_contact=bool(getattr(sender, "contact", False)),
                is_bot=bool(getattr(sender, "bot", False)),
                is_service=sender_id in SERVICE_USER_IDS,
                has_trusted_history=trusted_history,
                review_reference=self._review_reference(sender, event.message.id),
            )
            actions = TelegramActions(self, event.input_chat, sender_key)
            outcome = await self.service.handle(incoming, actions)
            LOG.info(f"message_handled:{outcome}")
        except Exception:
            LOG.error("event_handler_failed")

    def _review_reference(self, sender, message_id: int) -> bytes | None:
        sender_id = getattr(sender, "id", None)
        access_hash = getattr(sender, "access_hash", None)
        if not isinstance(sender_id, int) or not isinstance(access_hash, int):
            return None
        return self.service.protector.seal_review_reference(
            sender_id, access_hash, message_id
        )

    async def _has_prior_outgoing(
        self, event, sender_key: str, *, since: int | None = None
    ) -> bool:
        async for message in self.client.iter_messages(
            event.input_chat, limit=20, from_user="me"
        ):
            if since is not None and message.date and int(message.date.timestamp()) < since:
                continue
            text = message.message or ""
            generated_by_gatekeeper = text.startswith(GATEKEEPER_MESSAGE_PREFIXES)
            if (
                message.id != event.message.id
                and message.out
                and not self.store.is_automated_message(sender_key, message.id)
                and not generated_by_gatekeeper
            ):
                return True
        return False

    async def _recover_challenges(self) -> None:
        for sender_key, state in self.store.challenge_states():
            if state.status == "challenged":
                if state.challenge_expires_at is not None:
                    self.schedule_timeout(
                        sender_key,
                        state.challenge_expires_at,
                        grace_seconds=30,
                        minimum_delay_seconds=30,
                    )
                continue
            reference = state.challenge_action_reference
            if reference is None:
                await self.service.abandon_incomplete_challenge(
                    sender_key, "reference_unavailable"
                )
                continue
            try:
                user_id, access_hash, _ = self.service.protector.open_review_reference(
                    reference
                )
            except ValueError:
                await self.service.abandon_incomplete_challenge(
                    sender_key, "reference_invalid"
                )
                continue
            peer = types.InputPeerUser(user_id=user_id, access_hash=access_hash)
            recovered_message_id = None
            if state.status == "challenge_issuing" and state.challenge_prompt:
                async for outgoing in self.client.iter_messages(
                    peer, limit=10, from_user="me"
                ):
                    sent_at = int(outgoing.date.timestamp()) if outgoing.date else 0
                    if (
                        outgoing.out
                        and outgoing.message == state.challenge_prompt
                        and sent_at >= state.updated_at - 5
                    ):
                        recovered_message_id = int(outgoing.id)
                        break
            actions = TelegramActions(self, peer, sender_key)
            await self.service.recover_incomplete_challenge(
                sender_key,
                actions,
                recovered_message_id=recovered_message_id,
            )

    def schedule_timeout(
        self,
        sender_key: str,
        expires_at: int,
        *,
        grace_seconds: int = 5,
        minimum_delay_seconds: int = 0,
    ) -> None:
        self.cancel_timeout(sender_key)
        self._timeout_tasks[sender_key] = asyncio.create_task(
            self._timeout_worker(
                sender_key,
                expires_at,
                grace_seconds,
                minimum_delay_seconds,
            )
        )

    def cancel_timeout(self, sender_key: str) -> None:
        task = self._timeout_tasks.pop(sender_key, None)
        if task and task is not asyncio.current_task():
            task.cancel()

    async def _timeout_worker(
        self,
        sender_key: str,
        expires_at: int,
        grace_seconds: int,
        minimum_delay_seconds: int,
    ) -> None:
        try:
            await asyncio.sleep(
                max(
                    minimum_delay_seconds,
                    expires_at + grace_seconds - int(time.time()),
                )
            )
            await self.service.expire_challenge(sender_key, expires_at)
        except asyncio.CancelledError:
            pass
        except Exception:
            LOG.error("timeout_action_failed")
        finally:
            if self._timeout_tasks.get(sender_key) is asyncio.current_task():
                self._timeout_tasks.pop(sender_key, None)
