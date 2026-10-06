# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Owner commands in Telegram Saved Messages and cleanup of the messages they create."""

from __future__ import annotations

import asyncio
import logging
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from telethon import types

from .message_facts import reply_to_message_id
from .restriction_actions import RestrictionActions, RestrictionReleaseResult
from .service import GatekeeperService
from .store import StateStore

LOG = logging.getLogger("gatekeeper.telegram")
OPERATOR_CASE_LIMIT = 5
OPERATOR_CONTROL_TTL_SECONDS = 15 * 60
OPERATOR_IDENTITY_TIMEOUT_SECONDS = 5
OPERATOR_SYNC_INTERVAL_SECONDS = 3
OPERATOR_SYNC_BATCH_LIMIT = 100
OPERATOR_CLEANUP_BATCH_LIMIT = 100
OPERATOR_CLEANUP_RETRY_BASE_SECONDS = 30
OPERATOR_CLEANUP_RETRY_MAX_SECONDS = 60 * 60
OPERATOR_CLEANUP_POLL_SECONDS = 60
OPERATOR_ORPHAN_LOOKBACK_SECONDS = 7 * 24 * 60 * 60
OPERATOR_ORPHAN_SEARCH_LIMIT = 200
OPERATOR_ORPHAN_SEARCH_QUERIES = ("/gatekeeper", "Gatekeeper", "restriction")


@dataclass(frozen=True, slots=True)
class OperatorCaseControl:
    sender_key: str
    expires_at: float


class OperatorControls:
    """`/gatekeeper` help, ping, cases, and reply-to-allow, plus their cleanup queue."""

    def __init__(
        self,
        client: Any,
        store: StateStore,
        service: GatekeeperService,
        restriction_actions: RestrictionActions,
        *,
        enabled: bool,
    ) -> None:
        self.client = client
        self.store = store
        self.service = service
        self.restriction_actions = restriction_actions
        self.enabled = enabled
        self.self_user_id: int | None = None
        self._case_controls: dict[int, OperatorCaseControl] = {}
        self._command_lock = asyncio.Lock()
        self._sync_cursor: int | None = None
        self._handled_message_ids: dict[int, float] = {}
        self._cleanup_wakeup = asyncio.Event()

    def forget_sender(self, sender_key: str) -> None:
        """Invalidate any case control that still points at a forgotten sender."""
        self._case_controls = {
            message_id: control
            for message_id, control in self._case_controls.items()
            if control.sender_key != sender_key
        }

    async def handle_message(self, event) -> None:
        if (
            not self.enabled
            or self.self_user_id is None
            or not event.is_private
            or not bool(getattr(event.message, "out", False))
            or event.chat_id != self.self_user_id
            or getattr(event.message, "fwd_from", None) is not None
        ):
            return
        text = (event.raw_text or "").strip()
        if text != "/gatekeeper" and not text.startswith("/gatekeeper "):
            return
        artifact_ids: list[int] = []
        try:
            async with self._command_lock:
                message_id = getattr(event, "id", None)
                now = time.monotonic()
                self._handled_message_ids = {
                    handled_id: expires_at
                    for handled_id, expires_at in self._handled_message_ids.items()
                    if expires_at > now
                }
                if (
                    isinstance(message_id, int)
                    and message_id in self._handled_message_ids
                ):
                    return
                if isinstance(message_id, int):
                    self._handled_message_ids[message_id] = (
                        now + OPERATOR_CONTROL_TTL_SECONDS
                    )
                    artifact_ids.append(message_id)
                if text in {"/gatekeeper", "/gatekeeper help"}:
                    command_name = "help"
                    await self._respond(
                        event,
                        self.help_text(),
                        artifact_ids,
                    )
                elif text == "/gatekeeper ping":
                    command_name = "ping"
                    await self._respond(
                        event,
                        "✅ Gatekeeper operator controls are online.",
                        artifact_ids,
                    )
                elif text == "/gatekeeper cases":
                    command_name = "cases"
                    await self._send_cases(event, artifact_ids)
                elif text == "/gatekeeper allow":
                    command_name = "allow"
                    await self._allow_case(event, artifact_ids)
                else:
                    command_name = "unknown"
                    await self._respond(
                        event,
                        "Unknown Gatekeeper command. Send /gatekeeper help.",
                        artifact_ids,
                    )
                LOG.info(f"operator_command_handled:{command_name}")
        except Exception:
            LOG.error("operator_command_failed")
            try:
                await self._respond(
                    event,
                    "❌ Gatekeeper could not process that operator command.",
                    artifact_ids,
                )
            except Exception:
                LOG.error("operator_response_failed")
        finally:
            if artifact_ids:
                self.schedule_artifact_deletion(artifact_ids)

    @staticmethod
    async def _respond(event, text: str, artifact_ids: list[int]):
        message = await event.respond(text, link_preview=False, parse_mode=None)
        message_id = getattr(message, "id", None)
        if isinstance(message_id, int):
            artifact_ids.append(message_id)
        return message

    async def initialize_sync_cursor(self) -> None:
        try:
            messages = await self.client.get_messages("me", limit=1)
        except Exception:
            self._sync_cursor = None
            LOG.warning("operator_sync_initialization_failed")
            return
        self._sync_cursor = max(
            (int(message.id) for message in messages),
            default=0,
        )

    async def sync_loop(self) -> None:
        while True:
            await asyncio.sleep(OPERATOR_SYNC_INTERVAL_SECONDS)
            try:
                await self.sync_messages()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.warning("operator_sync_failed")

    async def sync_messages(self) -> None:
        if self._sync_cursor is None:
            await self.initialize_sync_cursor()
            return
        while True:
            messages = await self.client.get_messages(
                "me",
                limit=OPERATOR_SYNC_BATCH_LIMIT,
                min_id=self._sync_cursor,
                reverse=True,
                search="/gatekeeper",
            )
            if not messages:
                return
            for message in messages:
                message_id = int(message.id)
                if message_id <= self._sync_cursor:
                    continue
                self._sync_cursor = message_id
                await self.handle_message(message)
            if len(messages) < OPERATOR_SYNC_BATCH_LIMIT:
                return

    async def reconcile_artifacts(self) -> None:
        now = int(time.time())
        cutoff = now - OPERATOR_ORPHAN_LOOKBACK_SECONDS
        artifacts: dict[int, int] = {}
        try:
            for query in OPERATOR_ORPHAN_SEARCH_QUERIES:
                messages = await self.client.get_messages(
                    "me",
                    limit=OPERATOR_ORPHAN_SEARCH_LIMIT,
                    search=query,
                )
                for message in messages:
                    message_id = getattr(message, "id", None)
                    sent_at = getattr(message, "date", None)
                    if (
                        not isinstance(message_id, int)
                        or not isinstance(sent_at, datetime)
                        or int(sent_at.timestamp()) < cutoff
                        or not bool(getattr(message, "out", False))
                        or getattr(message, "fwd_from", None) is not None
                        or not self.is_artifact_text(
                            getattr(message, "message", "")
                        )
                    ):
                        continue
                    artifacts[message_id] = max(
                        now,
                        int(sent_at.timestamp()) + OPERATOR_CONTROL_TTL_SECONDS,
                    )
        except Exception:
            LOG.warning("operator_artifact_reconciliation_failed")
            return
        if not artifacts:
            return
        for message_id, delete_at in artifacts.items():
            self.store.schedule_operator_artifacts([message_id], delete_at)
        self._cleanup_wakeup.set()
        LOG.info("operator_artifacts_reconciled")

    @staticmethod
    def is_artifact_text(value: object) -> bool:
        text = str(value or "").strip()
        if text == "/gatekeeper" or text.startswith("/gatekeeper "):
            return True
        if text in {
            OperatorControls.help_text(),
            "✅ Gatekeeper operator controls are online.",
            "Unknown Gatekeeper command. Send /gatekeeper help.",
            "❌ Gatekeeper could not process that operator command.",
            "✅ Gatekeeper has no active restrictions.",
            "Reply to a current case from /gatekeeper cases. "
            "Case controls expire after 15 minutes.",
            "✅ Restriction removed. The sender is now allowed and pending "
            "Gatekeeper deletion jobs were cancelled.",
            "ℹ️ This restriction was already resolved. No action was taken.",
            "⚠️ Telegram identity is unavailable. Use Advanced Recovery in the Dashboard.",
            "❌ Telegram restore failed. The restriction was left unchanged.",
        }:
            return True
        if text.startswith("Gatekeeper Active Cases · showing "):
            counts = text.removeprefix("Gatekeeper Active Cases · showing ").split(
                " of ", 1
            )
            return len(counts) == 2 and all(value.isdecimal() for value in counts)
        lines = text.splitlines()
        return (
            len(lines) >= 8
            and lines[0] == "Gatekeeper Active Case"
            and lines[1] == ""
            and lines[2].startswith("Sender: ")
            and lines[3].startswith("State: ")
            and lines[4].startswith("Reason: ")
            and lines[5].startswith("Updated: ")
            and lines[6] == ""
            and "\n".join(lines[7:])
            in {
                "Reply to this message with /gatekeeper allow\n"
                "This control is single-use and expires in 15 minutes.",
                "Telegram identity is unavailable. Use Advanced Recovery in the Dashboard.",
            }
        )

    async def _send_cases(self, event, artifact_ids: list[int]) -> None:
        self._case_controls.clear()
        total = self.store.active_restriction_count()
        items = self.store.active_restrictions(limit=OPERATOR_CASE_LIMIT)
        if not items:
            await self._respond(
                event,
                "✅ Gatekeeper has no active restrictions.",
                artifact_ids,
            )
            return
        await self._respond(
            event,
            f"Gatekeeper Active Cases · showing {len(items)} of {total}",
            artifact_ids,
        )
        expires_at = time.monotonic() + OPERATOR_CONTROL_TTL_SECONDS
        for item in items:
            identity = await self._identity(item.reference)
            actionable = item.reference is not None
            instruction = (
                "Reply to this message with /gatekeeper allow\n"
                "This control is single-use and expires in 15 minutes."
                if actionable
                else "Telegram identity is unavailable. Use Advanced Recovery in the Dashboard."
            )
            message = await self._respond(
                event,
                "Gatekeeper Active Case\n\n"
                f"Sender: {identity}\n"
                f"State: {item.status.title()}\n"
                f"Reason: {self._reason_label(item.reason)}\n"
                f"Updated: {self._age_label(item.updated_at)}\n\n"
                f"{instruction}",
                artifact_ids,
            )
            if actionable:
                self._case_controls[int(message.id)] = OperatorCaseControl(
                    item.sender_key,
                    expires_at,
                )

    async def _allow_case(self, event, artifact_ids: list[int]) -> None:
        reply_id = reply_to_message_id(event.message)
        now = time.monotonic()
        self._case_controls = {
            message_id: control
            for message_id, control in self._case_controls.items()
            if control.expires_at > now
        }
        control = (
            self._case_controls.pop(reply_id, None)
            if reply_id is not None
            else None
        )
        if control is None:
            await self._respond(
                event,
                "Reply to a current case from /gatekeeper cases. "
                "Case controls expire after 15 minutes.",
                artifact_ids,
            )
            return
        result = await self.restriction_actions.allow(control.sender_key)
        response = {
            RestrictionReleaseResult.ALLOWED: (
                "✅ Restriction removed. The sender is now allowed and pending "
                "Gatekeeper deletion jobs were cancelled."
            ),
            RestrictionReleaseResult.NOT_ACTIVE: (
                "ℹ️ This restriction was already resolved. No action was taken."
            ),
            RestrictionReleaseResult.IDENTITY_UNAVAILABLE: (
                "⚠️ Telegram identity is unavailable. Use Advanced Recovery in the Dashboard."
            ),
            RestrictionReleaseResult.TELEGRAM_ACTION_FAILED: (
                "❌ Telegram restore failed. The restriction was left unchanged."
            ),
        }[result]
        await self._respond(event, response, artifact_ids)

    async def _identity(self, reference: bytes | None) -> str:
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
            self._clean_text(value)
            for value in (
                getattr(sender, "first_name", None),
                getattr(sender, "last_name", None),
            )
            if value
        ).strip() or "Unnamed sender"
        name = name[:120]
        username = getattr(sender, "username", None)
        clean_username = self._clean_text(username)[:64] if username else ""
        return f"{name} (@{clean_username})" if clean_username else name

    @staticmethod
    def _clean_text(value: object) -> str:
        return " ".join(
            "".join(
                (" " if unicodedata.category(char) == "Cc" else char)
                for char in str(value)
                if unicodedata.category(char) != "Cf"
            ).split()
        )

    @staticmethod
    def _reason_label(reason: str) -> str:
        # critical_rule predates adaptive scoring and survives only in old restrictions.
        if reason == "critical_rule":
            return "Legacy Critical Rule Match"
        return reason.replace("_", " ").title()

    @staticmethod
    def _age_label(updated_at: int) -> str:
        age = max(0, int(time.time()) - updated_at)
        if age < 60:
            return "just now"
        if age < 3600:
            return f"{age // 60} minutes ago"
        if age < 86400:
            return f"{age // 3600} hours ago"
        return f"{age // 86400} days ago"

    @staticmethod
    def help_text() -> str:
        return (
            "Gatekeeper operator controls work only in Saved Messages.\n\n"
            "/gatekeeper ping — check the control channel\n"
            "/gatekeeper cases — list up to 5 active restrictions\n"
            "Reply to a case with /gatekeeper allow — restore and allow the sender"
        )

    def schedule_artifact_deletion(self, message_ids: list[int]) -> None:
        unique_ids = tuple(dict.fromkeys(message_ids))
        self.store.schedule_operator_artifacts(
            unique_ids,
            int(time.time()) + OPERATOR_CONTROL_TTL_SECONDS,
        )
        self._cleanup_wakeup.set()

    async def artifact_cleanup_loop(self) -> None:
        while True:
            now = int(time.time())
            if await self.delete_due_artifacts(now):
                continue
            next_delete_at = self.store.next_operator_artifact_delete_at()
            delay = OPERATOR_CLEANUP_POLL_SECONDS
            if next_delete_at is not None:
                delay = max(
                    0,
                    min(OPERATOR_CLEANUP_POLL_SECONDS, next_delete_at - now),
                )
            self._cleanup_wakeup.clear()
            try:
                await asyncio.wait_for(
                    self._cleanup_wakeup.wait(), timeout=delay
                )
            except TimeoutError:
                pass

    async def delete_due_artifacts(self, now: int) -> bool:
        due = self.store.due_operator_artifacts(
            now, limit=OPERATOR_CLEANUP_BATCH_LIMIT
        )
        if not due:
            return False
        message_ids = [message_id for message_id, _ in due]
        try:
            await self.client.delete_messages("me", message_ids, revoke=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            retry_count = max(count for _, count in due) + 1
            retry_delay = min(
                OPERATOR_CLEANUP_RETRY_MAX_SECONDS,
                OPERATOR_CLEANUP_RETRY_BASE_SECONDS
                * (2 ** min(retry_count - 1, 7)),
            )
            self.store.retry_operator_artifacts(message_ids, now + retry_delay)
            LOG.warning("operator_artifact_deletion_failed")
        else:
            self.store.complete_operator_artifacts(message_ids)
            LOG.info("operator_artifacts_deleted")
        return True
