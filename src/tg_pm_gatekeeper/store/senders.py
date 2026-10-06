# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Trust-state transitions outside the challenge flow."""

from __future__ import annotations

import time

from ..states import SenderStatus
from .base import StoreBase
from .models import SenderState


class SenderStateMixin(StoreBase):
    def allow(self, sender_key: str, now: int | None = None) -> None:
        self._set_state(sender_key, SenderStatus.ALLOWED, now=now)
        self.resolve_sender_actions(sender_key, now)
        self.delete_enforcement_review(sender_key)

    def revoke(self, sender_key: str, now: int | None = None) -> None:
        self._set_state(sender_key, SenderStatus.UNKNOWN, now=now)
        self.resolve_sender_actions(sender_key, now)

    def reset_test_sender(
        self, sender_key: str, expected_updated_at: int, now: int | None = None
    ) -> bool:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET status='unknown', challenge_id=NULL, "
                "answer_digest=NULL, challenge_expires_at=NULL, "
                "challenge_message_id=NULL, challenge_prompt=NULL, "
                "challenge_profile=NULL, "
                "challenge_action_reference=NULL, restriction_reference=NULL, guidance_sent=0, attempts=0, "
                "suppression_reason=NULL, suppressed_until=NULL, archived_at=NULL, "
                "revision=revision+1, "
                "updated_at=? WHERE sender_key=? AND updated_at=? "
                "AND status IN ('provisional', 'quarantined', 'suppressed')",
                (timestamp, sender_key, expected_updated_at),
            )
        if cursor.rowcount == 1:
            self.delete_enforcement_review(sender_key)
            return True
        return False

    def quarantine(
        self,
        sender_key: str,
        now: int | None = None,
        *,
        restriction_reference: bytes | None = None,
    ) -> None:
        self._set_state(
            sender_key,
            SenderStatus.QUARANTINED,
            restriction_reference=restriction_reference,
            now=now,
        )

    def suppress(
        self,
        sender_key: str,
        reason: str,
        *,
        until: int | None,
        reference: bytes | None = None,
        restriction_reference: bytes | None = None,
        now: int | None = None,
    ) -> SenderState:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO sender_state(sender_key,status,suppression_reason,"
                "suppressed_until,challenge_action_reference,restriction_reference,revision,updated_at) "
                "VALUES (?,'suppressed',?,?,?,?,1,?) ON CONFLICT(sender_key) DO UPDATE SET "
                "status='suppressed',challenge_id=NULL,answer_digest=NULL,"
                "challenge_expires_at=NULL,challenge_message_id=NULL,challenge_prompt=NULL,"
                "challenge_profile=NULL,"
                "challenge_action_reference=COALESCE(excluded.challenge_action_reference,"
                "sender_state.challenge_action_reference),"
                "restriction_reference=COALESCE(excluded.restriction_reference,"
                "sender_state.restriction_reference),guidance_sent=0,attempts=0,"
                "suppression_reason=excluded.suppression_reason,"
                "suppressed_until=excluded.suppressed_until,archived_at=NULL,"
                "revision=sender_state.revision+1,"
                "updated_at=excluded.updated_at",
                (
                    sender_key,
                    reason,
                    until,
                    reference,
                    restriction_reference,
                    timestamp,
                ),
            )
        return self.sender(sender_key)

    def release_expired_suppression(
        self, sender_key: str, now: int | None = None
    ) -> bool:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            return self._release_expired_suppression(sender_key, timestamp)
