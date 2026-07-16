# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import logging
import os
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from telethon import TelegramClient, events, functions, types
from telethon.sessions import StringSession

from .config import ConfigurationError, Settings, read_private_file
from .message_facts import facts_from_message
from .restriction_actions import RestrictionActions, RestrictionReleaseResult
from .review_admin import ReviewAdminServer
from .rules import normalized_domain
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
HEARTBEAT_PATH = Path("/tmp/gatekeeper-heartbeat")  # noqa: S108 - private tmpfs
PRUNE_INTERVAL_SECONDS = 12 * 60 * 60
OPERATOR_CASE_LIMIT = 5
OPERATOR_CONTROL_TTL_SECONDS = 15 * 60
OPERATOR_IDENTITY_TIMEOUT_SECONDS = 5
OPERATOR_SYNC_INTERVAL_SECONDS = 3
OPERATOR_SYNC_BATCH_LIMIT = 100
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


class TelegramAuthorizationError(RuntimeError):
    """Raised when the configured Telegram session cannot operate the client."""


@dataclass(frozen=True, slots=True)
class OperatorCaseControl:
    sender_key: str
    expires_at: float


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

    def schedule_verification_message_deletion(
        self, sender_key: str, message_ids: tuple[int, ...], delete_at: int
    ) -> None:
        self.adapter.schedule_verification_message_deletion(
            self.peer, sender_key, message_ids, delete_at
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
        self._self_user_id: int | None = None
        self._operator_case_controls: dict[int, OperatorCaseControl] = {}
        self._operator_command_lock = asyncio.Lock()
        self._operator_sync_cursor: int | None = None
        self._operator_handled_message_ids: dict[int, float] = {}
        self._restriction_actions = RestrictionActions(
            store,
            service,
            self.client,
            cancel_timeout=self.cancel_timeout,
        )
        self._review_admin = ReviewAdminServer(
            settings.review_socket_path,
            store,
            service,
            self.client,
            mute_days=settings.mute_days,
            cancel_timeout=self.cancel_timeout,
            restriction_actions=self._restriction_actions,
        )

    async def run(self) -> None:
        await self.client.connect()
        if not await self.client.is_user_authorized():
            raise TelegramAuthorizationError("telegram session is not authorized")
        me = await self.client.get_me()
        self._self_user_id = int(me.id)
        if self.settings.telegram_operator_controls_enabled:
            await self._initialize_operator_sync_cursor()
        await self._recover_challenges()
        await self._recover_test_sender_cleanup()
        await self._recover_pending_actions()
        await self._review_admin.start()
        self.client.add_event_handler(
            self._on_message, events.NewMessage(incoming=True)
        )
        if self.settings.telegram_operator_controls_enabled:
            self.client.add_event_handler(
                self._on_operator_message, events.NewMessage(outgoing=True)
            )
            self._track_maintenance_task(self._operator_sync_loop())
        disconnect_task: asyncio.Task | None = None
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        LOG.info("service_started")
        try:
            disconnect_task = asyncio.create_task(self.client.run_until_disconnected())
            done, _ = await asyncio.wait(
                (disconnect_task, self._heartbeat_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if self._heartbeat_task in done:
                failure = self._heartbeat_task.exception()
                if failure is not None:
                    raise failure
                raise RuntimeError("heartbeat task stopped unexpectedly")
            await disconnect_task
        finally:
            tasks = [
                task
                for task in (
                    disconnect_task,
                    self._heartbeat_task,
                    *self._timeout_tasks.values(),
                    *self._maintenance_tasks,
                )
                if task is not None
            ]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
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
                try:
                    trusted_history = await self._has_prior_outgoing(
                        event,
                        sender_key,
                        since=(
                            state.updated_at if state.status == "provisional" else None
                        ),
                    )
                except Exception:
                    self.store.audit(
                        sender_key,
                        "TRUSTED_HISTORY_LOOKUP",
                        "action_failed",
                        int(time.time()),
                    )
                    LOG.warning("trusted_history_lookup_failed")
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

    async def _on_operator_message(self, event) -> None:
        if (
            not self.settings.telegram_operator_controls_enabled
            or self._self_user_id is None
            or not event.is_private
            or not event.outgoing
            or event.chat_id != self._self_user_id
            or getattr(event.message, "fwd_from", None) is not None
        ):
            return
        text = (event.raw_text or "").strip()
        if text != "/gatekeeper" and not text.startswith("/gatekeeper "):
            return
        try:
            async with self._operator_command_lock:
                message_id = getattr(event, "id", None)
                now = time.monotonic()
                self._operator_handled_message_ids = {
                    handled_id: expires_at
                    for handled_id, expires_at in self._operator_handled_message_ids.items()
                    if expires_at > now
                }
                if (
                    isinstance(message_id, int)
                    and message_id in self._operator_handled_message_ids
                ):
                    return
                if isinstance(message_id, int):
                    self._operator_handled_message_ids[message_id] = (
                        now + OPERATOR_CONTROL_TTL_SECONDS
                    )
                if text in {"/gatekeeper", "/gatekeeper help"}:
                    command_name = "help"
                    await event.respond(
                        self._operator_help(), link_preview=False, parse_mode=None
                    )
                elif text == "/gatekeeper ping":
                    command_name = "ping"
                    await event.respond(
                        "✅ Gatekeeper operator controls are online.",
                        link_preview=False,
                        parse_mode=None,
                    )
                elif text == "/gatekeeper cases":
                    command_name = "cases"
                    await self._send_operator_cases(event)
                elif text == "/gatekeeper allow":
                    command_name = "allow"
                    await self._allow_operator_case(event)
                else:
                    command_name = "unknown"
                    await event.respond(
                        "Unknown Gatekeeper command. Send /gatekeeper help.",
                        link_preview=False,
                        parse_mode=None,
                    )
                LOG.info(f"operator_command_handled:{command_name}")
        except Exception:
            LOG.error("operator_command_failed")
            try:
                await event.respond(
                    "❌ Gatekeeper could not process that operator command.",
                    link_preview=False,
                    parse_mode=None,
                )
            except Exception:
                LOG.error("operator_response_failed")

    async def _initialize_operator_sync_cursor(self) -> None:
        try:
            messages = await self.client.get_messages("me", limit=1)
        except Exception:
            self._operator_sync_cursor = None
            LOG.warning("operator_sync_initialization_failed")
            return
        self._operator_sync_cursor = max(
            (int(message.id) for message in messages),
            default=0,
        )

    async def _operator_sync_loop(self) -> None:
        while True:
            await asyncio.sleep(OPERATOR_SYNC_INTERVAL_SECONDS)
            try:
                await self._sync_operator_messages()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.warning("operator_sync_failed")

    async def _sync_operator_messages(self) -> None:
        if self._operator_sync_cursor is None:
            await self._initialize_operator_sync_cursor()
            return
        while True:
            messages = await self.client.get_messages(
                "me",
                limit=OPERATOR_SYNC_BATCH_LIMIT,
                min_id=self._operator_sync_cursor,
                reverse=True,
                search="/gatekeeper",
            )
            if not messages:
                return
            for message in messages:
                message_id = int(message.id)
                if message_id <= self._operator_sync_cursor:
                    continue
                self._operator_sync_cursor = message_id
                await self._on_operator_message(message)
            if len(messages) < OPERATOR_SYNC_BATCH_LIMIT:
                return

    async def _send_operator_cases(self, event) -> None:
        self._operator_case_controls.clear()
        total = self.store.active_restriction_count()
        items = self.store.active_restrictions(limit=OPERATOR_CASE_LIMIT)
        if not items:
            await event.respond(
                "✅ Gatekeeper has no active restrictions.",
                link_preview=False,
                parse_mode=None,
            )
            return
        await event.respond(
            f"Gatekeeper Active Cases · showing {len(items)} of {total}",
            link_preview=False,
            parse_mode=None,
        )
        expires_at = time.monotonic() + OPERATOR_CONTROL_TTL_SECONDS
        for item in items:
            identity = await self._operator_identity(item.reference)
            actionable = item.reference is not None
            instruction = (
                "Reply to this message with /gatekeeper allow\n"
                "This control is single-use and expires in 15 minutes."
                if actionable
                else "Telegram identity is unavailable. Use Dashboard legacy recovery."
            )
            message = await event.respond(
                "Gatekeeper Active Case\n\n"
                f"Sender: {identity}\n"
                f"State: {item.status.title()}\n"
                f"Reason: {self._operator_reason(item.reason)}\n"
                f"Updated: {self._operator_age(item.updated_at)}\n\n"
                f"{instruction}",
                link_preview=False,
                parse_mode=None,
            )
            if actionable:
                self._operator_case_controls[int(message.id)] = OperatorCaseControl(
                    item.sender_key,
                    expires_at,
                )

    async def _allow_operator_case(self, event) -> None:
        reply_id = reply_to_message_id(event.message)
        now = time.monotonic()
        self._operator_case_controls = {
            message_id: control
            for message_id, control in self._operator_case_controls.items()
            if control.expires_at > now
        }
        control = (
            self._operator_case_controls.pop(reply_id, None)
            if reply_id is not None
            else None
        )
        if control is None:
            await event.respond(
                "Reply to a current case from /gatekeeper cases. "
                "Case controls expire after 15 minutes.",
                link_preview=False,
                parse_mode=None,
            )
            return
        result = await self._restriction_actions.allow(control.sender_key)
        response = {
            RestrictionReleaseResult.ALLOWED: (
                "✅ Restriction removed. The sender is now allowed and pending "
                "Gatekeeper deletion jobs were cancelled."
            ),
            RestrictionReleaseResult.NOT_ACTIVE: (
                "ℹ️ This restriction was already resolved. No action was taken."
            ),
            RestrictionReleaseResult.IDENTITY_UNAVAILABLE: (
                "⚠️ Telegram identity is unavailable. Use Dashboard legacy recovery."
            ),
            RestrictionReleaseResult.TELEGRAM_ACTION_FAILED: (
                "❌ Telegram restore failed. The restriction was left unchanged."
            ),
        }[result]
        await event.respond(response, link_preview=False, parse_mode=None)

    async def _operator_identity(self, reference: bytes | None) -> str:
        if reference is None:
            return "Identity unavailable"
        try:
            user_id, access_hash = self.service.protector.open_restriction_reference(
                reference
            )
            sender = await asyncio.wait_for(
                self.client.get_entity(
                    types.InputPeerUser(user_id=user_id, access_hash=access_hash)
                ),
                timeout=OPERATOR_IDENTITY_TIMEOUT_SECONDS,
            )
        except Exception:
            return "Name unavailable"
        name = " ".join(
            self._operator_text(value)
            for value in (
                getattr(sender, "first_name", None),
                getattr(sender, "last_name", None),
            )
            if value
        ).strip() or "Unnamed sender"
        name = name[:120]
        username = getattr(sender, "username", None)
        clean_username = self._operator_text(username)[:64] if username else ""
        return f"{name} (@{clean_username})" if clean_username else name

    @staticmethod
    def _operator_text(value: object) -> str:
        return " ".join(
            "".join(
                (" " if unicodedata.category(char) == "Cc" else char)
                for char in str(value)
                if unicodedata.category(char) != "Cf"
            ).split()
        )

    @staticmethod
    def _operator_reason(reason: str) -> str:
        return reason.replace("_", " ").title()

    @staticmethod
    def _operator_age(updated_at: int) -> str:
        age = max(0, int(time.time()) - updated_at)
        if age < 60:
            return "just now"
        if age < 3600:
            return f"{age // 60} minutes ago"
        if age < 86400:
            return f"{age // 3600} hours ago"
        return f"{age // 86400} days ago"

    @staticmethod
    def _operator_help() -> str:
        return (
            "Gatekeeper operator controls work only in Saved Messages.\n\n"
            "/gatekeeper ping — check the control channel\n"
            "/gatekeeper cases — list up to 5 active restrictions\n"
            "Reply to a case with /gatekeeper allow — restore and allow the sender"
        )

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

    def schedule_verification_message_deletion(
        self,
        peer,
        sender_key: str,
        message_ids: tuple[int, ...],
        delete_at: int,
    ) -> None:
        self._track_maintenance_task(
            self._verification_message_deletion_worker(
                peer, sender_key, message_ids, delete_at
            )
        )

    async def _verification_message_deletion_worker(
        self,
        peer,
        sender_key: str,
        message_ids: tuple[int, ...],
        delete_at: int,
    ) -> None:
        try:
            await asyncio.sleep(max(0, delete_at - int(time.time())))
            await self.client.delete_messages(peer, list(message_ids), revoke=True)
            self.store.audit(
                sender_key, "CHALLENGE_CLEANUP", "messages_deleted", int(time.time())
            )
        except asyncio.CancelledError:
            pass
        except Exception:
            self.store.audit(
                sender_key, "CHALLENGE_CLEANUP", "action_failed", int(time.time())
            )
            LOG.error("verification_message_deletion_failed")

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
