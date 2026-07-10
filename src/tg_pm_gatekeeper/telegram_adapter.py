# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

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
from .service import (
    TEST_MESSAGE_DELETE_DELAY_SECONDS,
    TEST_STATE_RESET_DELAY_SECONDS,
    GatekeeperService,
    IncomingMessage,
    TextStyleSpan,
)
from .store import DialogSnapshot, StateStore


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
    "⚠️ Verification Required",
    "↩️ Reply Required",
    "🔢 Digits Only",
    "❌ Incorrect Answer",
    "✅ Verification Passed",
    "⛔ Verification Failed",
    "Verification required",
    "Reply required",
    "Digits only",
    "Incorrect answer",
    "Verification passed",
    "Verification failed",
    "Please use Telegram's Reply action",
    "Reply with digits only.",
    "Incorrect answer.",
    "Verification passed.",
    "Verification failed.",
)


def formatting_entities_from_spans(
    text: str, spans: tuple[TextStyleSpan, ...]
) -> list[types.TypeMessageEntity]:
    entity_types = {
        "bold": types.MessageEntityBold,
        "italic": types.MessageEntityItalic,
        "code": types.MessageEntityCode,
    }
    entities: list[types.TypeMessageEntity] = []
    for span in spans:
        if span.offset < 0 or span.length <= 0 or span.offset + span.length > len(text):
            raise ValueError("invalid formatting span")
        offset = len(text[: span.offset].encode("utf-16-le")) // 2
        length = (
            len(text[span.offset : span.offset + span.length].encode("utf-16-le")) // 2
        )
        entities.append(entity_types[span.style](offset=offset, length=length))
    return entities


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
    button_texts: set[str] = set()
    button_urls: set[str] = set()
    markup = message.reply_markup
    for row in getattr(markup, "rows", ()) or ():
        for button in getattr(row, "buttons", ()) or ():
            has_any_button = True
            text_value = getattr(button, "text", None)
            if isinstance(text_value, str) and text_value.strip():
                button_texts.add(text_value.strip())
            if isinstance(button, LINK_BUTTON_TYPES):
                has_link_button = True
                link_button_count += 1
                url = getattr(button, "url", None)
                if url:
                    urls.add(url)
                    button_urls.add(url)

    webpage = getattr(message.media, "webpage", None)
    webpage_url = getattr(webpage, "url", None)
    preview_urls: set[str] = set()
    if webpage_url:
        urls.add(webpage_url)
        preview_urls.add(webpage_url)
    preview_text = "\n".join(
        value
        for attribute in ("site_name", "title", "description", "author")
        if isinstance((value := getattr(webpage, attribute, None)), str) and value
    )
    domains = tuple(
        sorted({domain for url in urls if (domain := normalized_domain(url))})
    )
    quote_domains = tuple(
        sorted({domain for url in quote_urls if (domain := normalized_domain(url))})
    )
    return MessageFacts(
        text=text,
        preview_text=preview_text,
        quote_text=quote_text,
        urls=tuple(sorted(urls)),
        domains=domains,
        button_texts=tuple(sorted(button_texts)),
        button_urls=tuple(sorted(button_urls)),
        preview_urls=tuple(sorted(preview_urls)),
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


def input_peer_from_sender(sender) -> types.InputPeerUser | None:
    sender_id = getattr(sender, "id", None)
    access_hash = getattr(sender, "access_hash", None)
    if not isinstance(sender_id, int) or not isinstance(access_hash, int):
        return None
    return types.InputPeerUser(user_id=sender_id, access_hash=access_hash)


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
        self,
        text: str,
        *,
        reply_to_message_id: int | None = None,
        formatting: tuple[TextStyleSpan, ...] = (),
    ) -> int:
        formatting_entities = formatting_entities_from_spans(text, formatting)
        try:
            message = await self.adapter.client.send_message(
                self.peer,
                text,
                reply_to=reply_to_message_id,
                link_preview=False,
                formatting_entities=formatting_entities or None,
            )
        except Exception as error:
            LOG.error(f"send_message_failed:{type(error).__name__}")
            raise
        return int(message.id)

    async def archive_and_mute(self) -> bool:
        archive_applied = False
        try:
            peer = self.peer
            if self.adapter.store.dialog_snapshot(self.sender_key) is None:
                dialogs = await self.adapter.client(
                    functions.messages.GetPeerDialogsRequest(
                        [types.InputDialogPeer(peer)]
                    )
                )
                if not dialogs.dialogs:
                    raise RuntimeError("dialog state unavailable")
                dialog = dialogs.dialogs[0]
                mute_until = getattr(dialog.notify_settings, "mute_until", None)
                self.adapter.store.save_dialog_snapshot(
                    self.sender_key,
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
            snapshot = self.adapter.store.dialog_snapshot(self.sender_key)
            folder_id = snapshot.folder_id if snapshot is not None else 0
            silent = snapshot.silent if snapshot is not None else False
            mute_until = (
                datetime.fromtimestamp(snapshot.mute_until, timezone.utc)
                if snapshot is not None and snapshot.mute_until is not None
                else datetime.now(timezone.utc)
            )
            await self.adapter.client(
                functions.folders.EditPeerFoldersRequest(
                    [types.InputFolderPeer(peer=peer, folder_id=folder_id)]
                )
            )
            await self.adapter.client(
                functions.account.UpdateNotifySettingsRequest(
                    peer=types.InputNotifyPeer(peer),
                    settings=types.InputPeerNotifySettings(
                        silent=silent,
                        mute_until=mute_until,
                    ),
                )
            )
            self.adapter.store.clear_dialog_snapshot(self.sender_key)
            return True
        except Exception:
            LOG.error("restore_action_failed")
            return False

    async def delete_message(self, message_id: int) -> bool:
        try:
            await self.adapter.client.delete_messages(
                self.peer, [message_id], revoke=True
            )
            return True
        except Exception:
            LOG.error("delete_message_failed")
            return False

    async def delete_messages(self, message_ids: tuple[int, ...]) -> bool:
        if not message_ids:
            return True
        try:
            await self.adapter.client.delete_messages(
                self.peer, list(message_ids), revoke=True
            )
            return True
        except Exception:
            LOG.error("delete_messages_failed")
            return False

    async def delete_dialog(self) -> bool:
        try:
            await self.adapter.client.delete_dialog(self.peer, revoke=True)
            self.adapter.store.clear_dialog_snapshot(self.sender_key)
            return True
        except Exception:
            LOG.error("delete_dialog_failed")
            return False

    def schedule_timeout(
        self, sender_key: str, expires_at: int, *, grace_seconds: int = 5
    ) -> None:
        self.adapter.schedule_timeout(
            sender_key,
            expires_at,
            grace_seconds=grace_seconds,
            peer=self.peer,
        )

    def cancel_timeout(self, sender_key: str) -> None:
        self.adapter.cancel_timeout(sender_key)

    def schedule_test_message_deletion(
        self, sender_key: str, since: int, delete_at: int
    ) -> None:
        self.adapter.schedule_test_message_deletion(
            self.peer, sender_key, since, delete_at
        )

    def schedule_dialog_deletion(self, action_id: int, delete_at: int) -> None:
        self.adapter.schedule_dialog_deletion(action_id, delete_at)

    def schedule_test_state_reset(
        self, sender_key: str, expected_updated_at: int, reset_at: int
    ) -> None:
        self.adapter.schedule_test_state_reset(
            sender_key, expected_updated_at, reset_at
        )


class TelegramAdapter:
    def __init__(
        self,
        settings: Settings,
        store: StateStore,
        service: GatekeeperService,
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
        self._maintenance_tasks: set[asyncio.Task] = set()
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
        await self._recover_test_sender_cleanup()
        await self._recover_pending_actions()
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
            for task in self._maintenance_tasks:
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
                sender_id != self.settings.test_sender_id
                and state.status in {"unknown", "provisional"}
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
            peer = input_peer_from_sender(sender)
            if peer is None:
                peer = event.input_chat
            actions = TelegramActions(self, peer, sender_key)
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
            if (
                since is not None
                and message.date
                and int(message.date.timestamp()) < since
            ):
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
                    peer = None
                    if state.challenge_action_reference is not None:
                        try:
                            user_id, access_hash, _ = (
                                self.service.protector.open_review_reference(
                                    state.challenge_action_reference
                                )
                            )
                            peer = types.InputPeerUser(user_id, access_hash)
                        except Exception:
                            LOG.error("challenge_peer_recovery_failed")
                    self.schedule_timeout(
                        sender_key,
                        state.challenge_expires_at,
                        grace_seconds=30,
                        minimum_delay_seconds=0 if peer is not None else 30,
                        peer=peer,
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

    async def _recover_test_sender_cleanup(self) -> None:
        sender_id = self.settings.test_sender_id
        sender_key = self.service.test_sender_key
        if sender_id is None or sender_key is None:
            return
        state = self.store.sender(sender_key)
        if state.status not in {"provisional", "quarantined"}:
            return
        if state.status == "quarantined":
            try:
                peer = await self.client.get_input_entity(sender_id)
            except Exception:
                LOG.error("test_sender_resolution_failed")
            else:
                challenge_started_at = self.store.latest_challenge_started_at(
                    sender_key, state.updated_at
                )
                if challenge_started_at is None:
                    challenge_started_at = (
                        state.updated_at - self.settings.challenge_ttl_seconds
                    )
                terminal_event = self.store.latest_challenge_terminal_event(
                    sender_key, challenge_started_at
                )
                if terminal_event and terminal_event[0] == "CHALLENGE_TIMEOUT":
                    self.schedule_test_message_deletion(
                        peer,
                        sender_key,
                        challenge_started_at,
                        state.updated_at + TEST_MESSAGE_DELETE_DELAY_SECONDS,
                    )
        self.schedule_test_state_reset(
            sender_key,
            state.updated_at,
            state.updated_at + TEST_STATE_RESET_DELAY_SECONDS,
        )

    async def _recover_pending_actions(self) -> None:
        for action in self.store.pending_actions():
            self.schedule_dialog_deletion(action.id, action.execute_at)

    def schedule_timeout(
        self,
        sender_key: str,
        expires_at: int,
        *,
        grace_seconds: int = 5,
        minimum_delay_seconds: int = 0,
        peer=None,
    ) -> None:
        self.cancel_timeout(sender_key)
        self._timeout_tasks[sender_key] = asyncio.create_task(
            self._timeout_worker(
                sender_key,
                expires_at,
                grace_seconds,
                minimum_delay_seconds,
                peer,
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
        peer,
    ) -> None:
        try:
            await asyncio.sleep(
                max(
                    minimum_delay_seconds,
                    expires_at + grace_seconds - int(time.time()),
                )
            )
            actions = (
                TelegramActions(self, peer, sender_key) if peer is not None else None
            )
            await self.service.expire_challenge(sender_key, expires_at, actions=actions)
        except asyncio.CancelledError:
            pass
        except Exception:
            LOG.error("timeout_action_failed")
        finally:
            if self._timeout_tasks.get(sender_key) is asyncio.current_task():
                self._timeout_tasks.pop(sender_key, None)

    def _track_maintenance_task(self, coroutine) -> None:
        task = asyncio.create_task(coroutine)
        self._maintenance_tasks.add(task)
        task.add_done_callback(self._maintenance_tasks.discard)

    def schedule_test_message_deletion(
        self, peer, sender_key: str, since: int, delete_at: int
    ) -> None:
        self._track_maintenance_task(
            self._test_message_deletion_worker(peer, sender_key, since, delete_at)
        )

    async def _test_message_deletion_worker(
        self, peer, sender_key: str, since: int, delete_at: int
    ) -> None:
        try:
            await asyncio.sleep(max(0, delete_at - int(time.time())))
            message_ids = self.store.message_ids_since(sender_key, since)
            if message_ids:
                await self.client.delete_messages(peer, message_ids, revoke=True)
        except asyncio.CancelledError:
            pass
        except Exception:
            LOG.error("test_message_deletion_failed")

    def schedule_dialog_deletion(self, action_id: int, delete_at: int) -> None:
        self._track_maintenance_task(self._dialog_deletion_worker(action_id, delete_at))

    async def _dialog_deletion_worker(self, action_id: int, delete_at: int) -> None:
        action = None
        try:
            await asyncio.sleep(max(0, delete_at - int(time.time())))
            action = self.store.claim_action(action_id)
            if action is None:
                return
            user_id, access_hash, _ = self.service.protector.open_review_reference(
                action.reference
            )
            peer = types.InputPeerUser(user_id, access_hash)
            actions = TelegramActions(self, peer, action.sender_key)
            deleted = await actions.delete_dialog()
            self.store.finish_action(action_id, "completed" if deleted else "failed")
            if deleted:
                self.store.clear_action_reference(
                    action.sender_key, action.expected_revision
                )
            if not deleted:
                self.store.enqueue_action_failure(action)
            self.store.audit(
                action.sender_key,
                "DIALOG_DELETE",
                "deleted" if deleted else "action_failed",
                int(time.time()),
            )
        except asyncio.CancelledError:
            pass
        except Exception:
            LOG.error("dialog_deletion_failed")
            if action is not None:
                self.store.finish_action(action_id, "failed")
                self.store.enqueue_action_failure(action)
                self.store.audit(
                    action.sender_key,
                    "DIALOG_DELETE",
                    "action_failed",
                    int(time.time()),
                )

    def schedule_test_state_reset(
        self, sender_key: str, expected_updated_at: int, reset_at: int
    ) -> None:
        self._track_maintenance_task(
            self._test_state_reset_worker(sender_key, expected_updated_at, reset_at)
        )

    async def _test_state_reset_worker(
        self, sender_key: str, expected_updated_at: int, reset_at: int
    ) -> None:
        try:
            await asyncio.sleep(max(0, reset_at - int(time.time())))
            await self.service.reset_test_sender(sender_key, expected_updated_at)
        except asyncio.CancelledError:
            pass
        except Exception:
            LOG.error("test_state_reset_failed")
