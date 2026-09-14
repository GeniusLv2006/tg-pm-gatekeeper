# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from telethon import functions, types

from .dashboard_protocol import DashboardBackendError
from .message_facts import facts_from_message
from .restriction_actions import RestrictionActions, RestrictionReleaseResult
from .rules import url_evidence, url_shape
from .service import GatekeeperService
from .store import ActiveRestriction, DialogSnapshot, ReviewItem, StateStore

LOG = logging.getLogger("gatekeeper.dashboard_backend")
PAGE_SIZE = 50
IDENTITY_CACHE_LIMIT = 256
IDENTITY_CACHE_SECONDS = 5 * 60
IDENTITY_FAILURE_CACHE_SECONDS = 30
IDENTITY_BATCH_SIZE = 100


class InProcessDashboardBackend:
    """Security-sensitive Dashboard operations owned by the live core process."""

    def __init__(
        self,
        store: StateStore,
        service: GatekeeperService,
        telegram_client,
        *,
        mute_days: int,
        cancel_timeout=lambda _sender_key: None,
        schedule_dialog_deletion=lambda _action_id, _delete_at: None,
        restriction_actions: RestrictionActions | None = None,
    ) -> None:
        self.store = store
        self.service = service
        self.telegram_client = telegram_client
        self.mute_days = mute_days
        self.cancel_timeout = cancel_timeout
        self.schedule_dialog_deletion = schedule_dialog_deletion
        self.restriction_actions = restriction_actions or RestrictionActions(
            store,
            service,
            telegram_client,
            cancel_timeout=cancel_timeout,
        )
        self._identity_cache: OrderedDict[
            str, tuple[float, int, str | None, str | None]
        ] = OrderedDict()

    async def request(
        self, method: str, params: dict[str, object]
    ) -> dict[str, object]:
        handlers = {
            "overview": self._overview,
            "page_version": self._page_version_request,
            "reviews.list": self._review_list,
            "reviews.detail": self._review_detail,
            "reviews.decide": self._review_decide,
            "cases.list": self._case_list,
            "cases.detail": self._case_detail,
            "cases.decide": self._case_decide,
            "cases.release_legacy": self._release_legacy,
        }
        handler = handlers.get(method)
        if handler is None:
            raise DashboardBackendError("unknown_method")
        return await handler(params)

    async def _overview(self, _params: dict[str, object]) -> dict[str, object]:
        stats = self.store.enforcement_statistics()
        return {
            "mode": self.store.get_mode(),
            "pending_reviews": self.store.pending_review_count(),
            "active_stats": stats,
        }

    async def _page_version_request(
        self, params: dict[str, object]
    ) -> dict[str, object]:
        target = params.get("target")
        if not isinstance(target, str):
            raise DashboardBackendError("invalid_request")
        return {"version": self.page_version(target)}

    async def _review_list(self, params: dict[str, object]) -> dict[str, object]:
        page = self._page_param(params)
        total = self.store.pending_review_count()
        self._require_page(page, total)
        items = self.store.review_items(
            limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE
        )
        identities = await self._review_identities(items)
        return {
            "page": page,
            "total": total,
            "items": [
                {
                    "id": item.id,
                    "classification": item.classification,
                    "signals": item.signals,
                    "message_count": item.message_count,
                    "updated_at": item.updated_at,
                    "identity": identities.get(item.sender_key),
                }
                for item in items
            ],
        }

    async def _review_detail(self, params: dict[str, object]) -> dict[str, object]:
        review_id = self._positive_int(params, "review_id")
        item = self.store.review_item(review_id)
        now = int(time.time())
        if item is None or (item.status == "pending" and item.expires_at <= now):
            raise DashboardBackendError("review_not_found")
        if item.status != "pending" or item.reference is None:
            raise DashboardBackendError("review_not_pending")
        user_id, access_hash, message_id = self.service.protector.open_review_reference(
            item.reference
        )
        peer = types.InputPeerUser(user_id=user_id, access_hash=access_hash)
        message = await self.telegram_client.get_messages(peer, ids=message_id)
        sender = await self.telegram_client.get_entity(peer)
        identity = self._identity_value(user_id, sender)
        self._cache_identity(item.sender_key, identity)
        text: str | None = None
        if message is not None:
            text = message.message or f"[Non-text message: {type(message.media).__name__}]"
        return {
            "id": item.id,
            "classification": item.classification,
            "signals": item.signals,
            "features": item.features,
            "message_count": item.message_count,
            "updated_at": item.updated_at,
            "user_id": user_id,
            "identity": identity,
            "message": text,
        }

    async def _review_decide(self, params: dict[str, object]) -> dict[str, object]:
        review_id = self._positive_int(params, "review_id")
        item = self.store.review_item(review_id)
        if item is None or (
            item.status == "pending" and item.expires_at <= int(time.time())
        ):
            raise DashboardBackendError("review_not_found")
        async with self.service.sender_lock(item.sender_key):
            item = self.store.review_item(review_id)
            if item is None or item.status != "pending" or item.reference is None:
                raise DashboardBackendError("review_already_decided")
            if item.expires_at <= int(time.time()):
                raise DashboardBackendError("review_not_found")
            action = params.get("action")
            if action not in {"legitimate", "spam", "dismiss"}:
                raise DashboardBackendError("unknown_action")
            state = self.store.sender(item.sender_key)
            if action == "legitimate":
                if state.status in {"challenged", "quarantined", "suppressed"}:
                    peer = self._peer_from_review(item)
                    if not await self.restriction_actions.restore_dialog(
                        peer, item.sender_key
                    ):
                        raise DashboardBackendError("telegram_action_failed")
                self.store.allow(item.sender_key)
                self.cancel_timeout(item.sender_key)
                self.store.decide_sender_reviews(item.sender_key, "legitimate")
            elif action == "spam":
                peer = self._peer_from_review(item)
                if state.status != "suppressed":
                    await self._capture_manual_enforcement(item, peer)
                if state.status not in {"challenged", "quarantined", "suppressed"}:
                    if not await self._archive_and_mute(peer, item.sender_key):
                        self.store.delete_enforcement_review(item.sender_key)
                        raise DashboardBackendError("telegram_action_failed")
                self.store.decide_sender_reviews(item.sender_key, "spam")
                suppressed = self.store.suppress(
                    item.sender_key,
                    "manual_permanent_suppression",
                    until=None,
                    reference=item.reference,
                    restriction_reference=self.service.restriction_reference(
                        item.reference
                    ),
                )
                now = int(time.time())
                self.store.activate_enforcement_review(
                    item.sender_key,
                    "manual_permanent_suppression",
                    now + self.service.active_case_retention_days * 86400,
                )
                action_id = self.store.schedule_action(
                    item.sender_key,
                    reason="manual_permanent_suppression",
                    reference=item.reference,
                    execute_at=now,
                    expected_revision=suppressed.revision,
                    mode_independent=True,
                    now=now,
                )
                self.schedule_dialog_deletion(action_id, now)
                self.cancel_timeout(item.sender_key)
            else:
                self.store.decide_sender_reviews(item.sender_key, "dismissed")
            self._identity_cache.pop(item.sender_key, None)
        return {"outcome": "completed"}

    async def _case_list(self, params: dict[str, object]) -> dict[str, object]:
        page = self._page_param(params)
        total = self.store.active_restriction_count()
        self._require_page(page, total)
        items = self.store.active_restrictions(
            limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE
        )
        identities = await self._case_identities(items)
        return {
            "page": page,
            "total": total,
            "stats": self.store.enforcement_statistics(),
            "items": [self._case_value(item, identities.get(item.sender_key)) for item in items],
        }

    async def _case_detail(self, params: dict[str, object]) -> dict[str, object]:
        sender_key = self._sender_key(params)
        item = self.store.active_restriction(sender_key)
        if item is None:
            raise DashboardBackendError("case_not_found")
        payload: dict[str, object] = {}
        evidence_available = False
        unavailable_reason = "missing"
        if item.envelope is not None and self.service.active_case_protector is not None:
            try:
                payload = self.service.active_case_protector.open(item.envelope)
                evidence_available = True
                unavailable_reason = ""
            except ValueError:
                unavailable_reason = "authentication_failed"
                LOG.error("active_case_evidence_invalid")
        identity = None
        if item.reference is not None:
            try:
                user_id, access_hash = (
                    self.service.protector.open_restriction_reference(item.reference)
                )
                sender = await self.telegram_client.get_entity(
                    types.InputPeerUser(user_id=user_id, access_hash=access_hash)
                )
                identity = self._identity_value(user_id, sender)
                self._cache_identity(item.sender_key, identity)
            except Exception:
                LOG.info("active_case_identity_lookup_failed")
        value = self._case_value(item, identity)
        value.update(
            {
                "payload": payload,
                "evidence_available": evidence_available,
                "evidence_unavailable_reason": unavailable_reason,
                "has_dialog_snapshot": self.store.dialog_snapshot(sender_key)
                is not None,
            }
        )
        return value

    async def _case_decide(self, params: dict[str, object]) -> dict[str, object]:
        sender_key = self._sender_key(params)
        if self.store.active_restriction(sender_key) is None:
            raise DashboardBackendError("case_not_found")
        action = params.get("action")
        if action == "keep":
            async with self.service.sender_lock(sender_key):
                if self.store.active_restriction(sender_key) is None:
                    raise DashboardBackendError("case_not_found")
                self.store.audit(sender_key, "OPERATOR_KEEP", "kept", int(time.time()))
            return {"outcome": "kept"}
        if action != "allow":
            raise DashboardBackendError("unknown_action")
        result = await self.restriction_actions.allow(sender_key)
        errors = {
            RestrictionReleaseResult.NOT_ACTIVE: "case_not_active",
            RestrictionReleaseResult.IDENTITY_UNAVAILABLE: "identity_unavailable",
            RestrictionReleaseResult.TELEGRAM_ACTION_FAILED: "telegram_action_failed",
        }
        if result in errors:
            raise DashboardBackendError(errors[result])
        if result != RestrictionReleaseResult.ALLOWED:
            raise DashboardBackendError("restriction_release_failed")
        self._identity_cache.pop(sender_key, None)
        return {"outcome": "allowed"}

    async def _release_legacy(self, params: dict[str, object]) -> dict[str, object]:
        user_id = self._positive_int(params, "user_id", maximum=2**63 - 1)
        sender_key = self.service.protector.sender_key(user_id)
        async with self.service.sender_lock(sender_key):
            state = self.store.sender(sender_key)
            if state.status not in {"quarantined", "suppressed"}:
                raise DashboardBackendError("restricted_sender_not_found")
            if state.restriction_reference is not None:
                raise DashboardBackendError("use_active_case")
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
        return {"outcome": "allowed"}

    def page_version(self, target: str) -> str | None:
        parsed = urlsplit(target)
        path = parsed.path
        page = self._query_page(parsed.query)
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
            total = self.store.pending_review_count(now=now)
            if not self._page_exists(page, total):
                return None
            payload = [
                (item.id, item.updated_at, item.message_count, item.classification, item.signals)
                for item in self.store.review_items(limit=PAGE_SIZE, offset=offset, now=now)
            ]
        elif path == "/cases":
            total = self.store.active_restriction_count()
            if not self._page_exists(page, total):
                return None
            payload = [
                self._case_version(item, now)
                for item in self.store.active_restrictions(
                    limit=PAGE_SIZE, offset=offset, now=now
                )
            ]
        elif path.startswith("/review/"):
            try:
                item = self.store.review_item(int(path.removeprefix("/review/")))
            except ValueError:
                return None
            payload = None if item is None else (
                item.id,
                item.status,
                item.updated_at,
                item.message_count,
                item.reference is not None,
                item.expires_at > now,
            )
        elif path.startswith("/cases/"):
            sender_key = path.removeprefix("/cases/")
            if not sender_key or "/" in sender_key:
                return None
            item = self.store.active_restriction(sender_key, now=now)
            payload = None if item is None else self._case_version(item, now)
        else:
            return None
        serialized = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(serialized.encode("ascii")).hexdigest()[:20]

    async def _review_identities(
        self, items: list[ReviewItem]
    ) -> dict[str, dict[str, object]]:
        peers: list[tuple[ReviewItem, types.InputPeerUser, int]] = []
        identities: dict[str, dict[str, object]] = {}
        now = time.monotonic()
        self._expire_identities(now)
        for item in items:
            if item.reference is None:
                continue
            try:
                user_id, access_hash, _ = self.service.protector.open_review_reference(
                    item.reference
                )
            except ValueError:
                continue
            cached = self._identity_cache.get(item.sender_key)
            if cached is not None and cached[0] > now:
                identities[item.sender_key] = self._cached_identity(cached)
            else:
                peers.append(
                    (item, types.InputPeerUser(user_id, access_hash), user_id)
                )
        await self._resolve_identities(peers, identities)
        return identities

    async def _case_identities(
        self, items: list[ActiveRestriction]
    ) -> dict[str, dict[str, object]]:
        peers: list[tuple[object, types.InputPeerUser, int]] = []
        identities: dict[str, dict[str, object]] = {}
        now = time.monotonic()
        self._expire_identities(now)
        for item in items:
            if item.reference is None:
                continue
            try:
                user_id, access_hash = self.service.protector.open_restriction_reference(
                    item.reference
                )
            except ValueError:
                continue
            cached = self._identity_cache.get(item.sender_key)
            if cached is not None and cached[0] > now:
                identities[item.sender_key] = self._cached_identity(cached)
            else:
                peers.append(
                    (item, types.InputPeerUser(user_id, access_hash), user_id)
                )
        await self._resolve_identities(peers, identities)
        return identities

    async def _resolve_identities(
        self,
        pending: list[tuple[object, types.InputPeerUser, int]],
        identities: dict[str, dict[str, object]],
    ) -> None:
        for start in range(0, len(pending), IDENTITY_BATCH_SIZE):
            batch = pending[start : start + IDENTITY_BATCH_SIZE]
            try:
                senders = await asyncio.wait_for(
                    self.telegram_client.get_entity([peer for _, peer, _ in batch]),
                    timeout=5,
                )
                if not isinstance(senders, (list, tuple)):
                    senders = [senders]
            except Exception:
                senders = []
            for (item, _, user_id), sender in zip(batch, senders, strict=False):
                value = self._identity_value(user_id, sender)
                identities[item.sender_key] = value
                self._cache_identity(item.sender_key, value)
            for item, _, user_id in batch[len(senders) :]:
                value = {"user_id": user_id, "name": None, "username": None}
                identities[item.sender_key] = value
                self._cache_identity(
                    item.sender_key, value, ttl=IDENTITY_FAILURE_CACHE_SECONDS
                )

    async def _capture_manual_enforcement(
        self, item: ReviewItem, peer: types.InputPeerUser
    ) -> None:
        if self.service.active_case_protector is None or item.reference is None:
            return
        try:
            _, _, message_id = self.service.protector.open_review_reference(item.reference)
            message = await self.telegram_client.get_messages(peer, ids=message_id)
            if message is None:
                return
            facts = facts_from_message(message)
            payload: dict[str, object] = {
                "schema_version": 5,
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
                "signals": json.loads(item.signals),
                "risk_score": "Manual decision",
                "challenge_profile": None,
                "planned_action": "manual_permanent_suppression",
                "decision_basis": "manual_operator_decision",
                "policy_version": "manual-review-v1",
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
                            if mute_until is not None
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
                await self.restriction_actions.restore_dialog(peer, sender_key)
            LOG.error("review_archive_failed")
            return False

    @staticmethod
    def _case_value(
        item: ActiveRestriction, identity: dict[str, object] | None
    ) -> dict[str, object]:
        return {
            "sender_key": item.sender_key,
            "status": item.status,
            "reason": item.reason,
            "suppressed_until": item.suppressed_until,
            "updated_at": item.updated_at,
            "has_evidence": item.envelope is not None,
            "evidence_created_at": item.evidence_created_at,
            "evidence_expires_at": item.evidence_expires_at,
            "has_identity": item.reference is not None,
            "identity": identity,
        }

    @staticmethod
    def _case_version(item: ActiveRestriction, now: int) -> tuple[object, ...]:
        return (
            item.sender_key,
            item.status,
            item.reason,
            item.suppressed_until,
            item.updated_at,
            item.envelope is not None,
            item.evidence_expires_at,
            item.reference is not None,
            item.suppressed_until is not None and item.suppressed_until <= now,
        )

    @staticmethod
    def _identity_value(user_id: int, sender) -> dict[str, object]:
        name = " ".join(
            str(value)
            for value in (
                getattr(sender, "first_name", None),
                getattr(sender, "last_name", None),
            )
            if value
        ).strip() or "Unnamed sender"
        username = getattr(sender, "username", None)
        return {
            "user_id": user_id,
            "name": name[:120],
            "username": str(username)[:64] if username else None,
        }

    def _cache_identity(
        self,
        sender_key: str,
        value: dict[str, object],
        *,
        ttl: int = IDENTITY_CACHE_SECONDS,
    ) -> None:
        self._identity_cache[sender_key] = (
            time.monotonic() + ttl,
            int(value["user_id"]),
            value.get("name") if isinstance(value.get("name"), str) else None,
            value.get("username")
            if isinstance(value.get("username"), str)
            else None,
        )
        self._identity_cache.move_to_end(sender_key)
        while len(self._identity_cache) > IDENTITY_CACHE_LIMIT:
            self._identity_cache.popitem(last=False)

    def _expire_identities(self, now: float) -> None:
        self._identity_cache = OrderedDict(
            (key, value)
            for key, value in self._identity_cache.items()
            if value[0] > now
        )

    @staticmethod
    def _cached_identity(
        value: tuple[float, int, str | None, str | None]
    ) -> dict[str, object]:
        return {"user_id": value[1], "name": value[2], "username": value[3]}

    def _peer_from_review(self, item: ReviewItem) -> types.InputPeerUser:
        if item.reference is None:
            raise DashboardBackendError("review_not_pending")
        user_id, access_hash, _ = self.service.protector.open_review_reference(
            item.reference
        )
        return types.InputPeerUser(user_id, access_hash)

    @staticmethod
    def _positive_int(
        params: dict[str, object], name: str, *, maximum: int = 2**31 - 1
    ) -> int:
        value = params.get(name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise DashboardBackendError("invalid_request")
        if value < 1 or value > maximum:
            raise DashboardBackendError("invalid_request")
        return value

    @classmethod
    def _page_param(cls, params: dict[str, object]) -> int:
        return cls._positive_int(params, "page", maximum=100_000)

    @staticmethod
    def _sender_key(params: dict[str, object]) -> str:
        value = params.get("sender_key")
        if not isinstance(value, str) or len(value) != 64:
            raise DashboardBackendError("invalid_request")
        if any(char not in "0123456789abcdef" for char in value):
            raise DashboardBackendError("invalid_request")
        return value

    @staticmethod
    def _page_exists(page: int, total: int) -> bool:
        return page == 1 or (page - 1) * PAGE_SIZE < total

    @classmethod
    def _require_page(cls, page: int, total: int) -> None:
        if not cls._page_exists(page, total):
            raise DashboardBackendError("page_not_found")

    @staticmethod
    def _query_page(query: str) -> int | None:
        from urllib.parse import parse_qs

        raw = parse_qs(query).get("page", ["1"])[0]
        if not raw.isascii() or not raw.isdecimal():
            return None
        page = int(raw)
        return page if 1 <= page <= 100_000 else None
