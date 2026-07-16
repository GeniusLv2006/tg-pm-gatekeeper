# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import StrEnum
from typing import Callable

from telethon import functions, types

from .service import GatekeeperService
from .store import StateStore

LOG = logging.getLogger("gatekeeper.restrictions")


class RestrictionReleaseResult(StrEnum):
    ALLOWED = "allowed"
    NOT_ACTIVE = "not_active"
    IDENTITY_UNAVAILABLE = "identity_unavailable"
    TELEGRAM_ACTION_FAILED = "telegram_action_failed"


class RestrictionActions:
    def __init__(
        self,
        store: StateStore,
        service: GatekeeperService,
        telegram_client,
        *,
        cancel_timeout: Callable[[str], None] = lambda _sender_key: None,
    ) -> None:
        self.store = store
        self.service = service
        self.telegram_client = telegram_client
        self.cancel_timeout = cancel_timeout

    async def allow(self, sender_key: str) -> RestrictionReleaseResult:
        async with self.service.sender_lock(sender_key):
            item = self.store.active_restriction(sender_key)
            if item is None:
                return RestrictionReleaseResult.NOT_ACTIVE
            if item.reference is None:
                return RestrictionReleaseResult.IDENTITY_UNAVAILABLE
            try:
                user_id, access_hash = self.service.protector.open_restriction_reference(
                    item.reference
                )
            except ValueError:
                return RestrictionReleaseResult.IDENTITY_UNAVAILABLE
            peer = types.InputPeerUser(user_id=user_id, access_hash=access_hash)
            if not await self.restore_dialog(peer, sender_key):
                return RestrictionReleaseResult.TELEGRAM_ACTION_FAILED
            self.store.allow(sender_key)
            self.cancel_timeout(sender_key)
            return RestrictionReleaseResult.ALLOWED

    async def restore_dialog(
        self, peer: types.InputPeerUser, sender_key: str
    ) -> bool:
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
            LOG.error("restriction_restore_failed")
            return False
