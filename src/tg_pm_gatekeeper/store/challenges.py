# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Arithmetic challenge lifecycle and its message bookkeeping."""

from __future__ import annotations

import time

from ..states import SenderStatus
from .base import StoreBase
from .models import SenderState


class ChallengeMixin(StoreBase):
    def set_challenge(
        self,
        sender_key: str,
        challenge_id: str,
        answer_digest: str,
        expires_at: int,
        message_id: int,
        now: int | None = None,
    ) -> None:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO sender_state(sender_key, status, challenge_id, "
                "answer_digest, challenge_expires_at, challenge_message_id, "
                "challenge_profile, guidance_sent, attempts, updated_at) "
                "VALUES (?, 'challenged', ?, ?, ?, ?, 'standard', 0, 0, ?) "
                "ON CONFLICT(sender_key) DO UPDATE SET "
                "status='challenged', challenge_id=excluded.challenge_id, "
                "answer_digest=excluded.answer_digest, "
                "challenge_expires_at=excluded.challenge_expires_at, "
                "challenge_message_id=excluded.challenge_message_id, "
                "challenge_prompt=NULL, challenge_profile='standard', "
                "challenge_action_reference=NULL, "
                "restriction_reference=NULL, "
                "guidance_sent=0, attempts=0, updated_at=excluded.updated_at",
                (
                    sender_key,
                    challenge_id,
                    answer_digest,
                    expires_at,
                    message_id,
                    timestamp,
                ),
            )

    def begin_challenge_issue(
        self,
        sender_key: str,
        challenge_id: str,
        answer_digest: str,
        expires_at: int,
        prompt: str,
        action_reference: bytes | None,
        now: int | None = None,
        *,
        challenge_profile: str = "standard",
    ) -> None:
        if challenge_profile not in {"standard", "strict"}:
            raise ValueError("invalid challenge profile")
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO sender_state(sender_key, status, challenge_id, "
                "answer_digest, challenge_expires_at, challenge_message_id, "
                "challenge_prompt, challenge_profile, challenge_action_reference, "
                "guidance_sent, attempts, updated_at) VALUES (?, 'challenge_issuing', "
                "?, ?, ?, NULL, ?, ?, ?, 0, 0, ?) ON CONFLICT(sender_key) DO UPDATE SET "
                "status='challenge_issuing', challenge_id=excluded.challenge_id, "
                "answer_digest=excluded.answer_digest, "
                "challenge_expires_at=excluded.challenge_expires_at, "
                "challenge_message_id=NULL, challenge_prompt=excluded.challenge_prompt, "
                "challenge_profile=excluded.challenge_profile, "
                "challenge_action_reference=excluded.challenge_action_reference, "
                "restriction_reference=NULL, guidance_sent=0, attempts=0, "
                "updated_at=excluded.updated_at",
                (
                    sender_key,
                    challenge_id,
                    answer_digest,
                    expires_at,
                    prompt,
                    challenge_profile,
                    action_reference,
                    timestamp,
                ),
            )

    def bind_challenge_message(
        self, sender_key: str, message_id: int, now: int | None = None
    ) -> bool:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET status='challenge_archiving', "
                "challenge_message_id=?, updated_at=? WHERE sender_key=? "
                "AND status='challenge_issuing'",
                (message_id, timestamp, sender_key),
            )
        return cursor.rowcount == 1

    def activate_challenge(self, sender_key: str, now: int | None = None) -> bool:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET status='challenged', challenge_prompt=NULL, "
                "revision=revision+1, updated_at=? WHERE sender_key=? "
                "AND status='challenge_archiving'",
                (timestamp, sender_key),
            )
        return cursor.rowcount == 1

    def reset_incomplete_challenge(
        self, sender_key: str, now: int | None = None
    ) -> bool:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET status='unknown', challenge_id=NULL, "
                "answer_digest=NULL, challenge_expires_at=NULL, "
                "challenge_message_id=NULL, challenge_prompt=NULL, "
                "challenge_profile=NULL, "
                "challenge_action_reference=NULL, restriction_reference=NULL, "
                "guidance_sent=0, attempts=0, "
                "updated_at=? WHERE sender_key=? AND status IN "
                "('challenge_issuing', 'challenge_archiving')",
                (timestamp, sender_key),
            )
        if cursor.rowcount == 1:
            self.delete_enforcement_review(sender_key)
            return True
        return False

    def mark_provisional(self, sender_key: str, now: int | None = None) -> None:
        self._set_state(sender_key, SenderStatus.PROVISIONAL, now=now)
        self.delete_enforcement_review(sender_key)

    def mark_challenge_guidance_sent(self, sender_key: str) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET guidance_sent=1 WHERE sender_key=? "
                "AND status='challenged' AND guidance_sent=0",
                (sender_key,),
            )
        return cursor.rowcount == 1

    def refresh_challenge_expiry(
        self, sender_key: str, expires_at: int, now: int | None = None
    ) -> bool:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET challenge_expires_at=?, updated_at=? "
                "WHERE sender_key=? AND status='challenge_issuing'",
                (expires_at, timestamp, sender_key),
            )
        return cursor.rowcount == 1

    def expire_challenge(
        self,
        sender_key: str,
        expires_at: int,
        now: int | None = None,
        *,
        suppression_seconds: int = 2 * 3600,
        restriction_reference: bytes | None = None,
    ) -> bool:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET status='suppressed', challenge_id=NULL, "
                "answer_digest=NULL, challenge_expires_at=NULL, "
                "challenge_message_id=NULL, challenge_prompt=NULL, "
                "challenge_profile=NULL, "
                "guidance_sent=0, attempts=0, suppression_reason='challenge_timeout', "
                "suppressed_until=?, restriction_reference=?, revision=revision+1, "
                "updated_at=? WHERE sender_key=? AND status='challenged' "
                "AND challenge_expires_at=?",
                (
                    timestamp + suppression_seconds,
                    restriction_reference,
                    timestamp,
                    sender_key,
                    expires_at,
                ),
            )
        return cursor.rowcount == 1

    def challenge_states(self) -> list[tuple[str, SenderState]]:
        with self._lock:
            keys = [
                row["sender_key"]
                for row in self._connection.execute(
                    "SELECT sender_key FROM sender_state WHERE status IN "
                    "('challenge_issuing', 'challenge_archiving', 'challenged')"
                )
            ]
        return [(key, self.sender(key)) for key in keys]

    def increment_attempts(self, sender_key: str, now: int | None = None) -> int:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE sender_state SET attempts=attempts+1, updated_at=? WHERE sender_key=?",
                (timestamp, sender_key),
            )
            row = self._connection.execute(
                "SELECT attempts FROM sender_state WHERE sender_key=?", (sender_key,)
            ).fetchone()
        return int(row["attempts"]) if row else 0

    def latest_challenge_started_at(self, sender_key: str, before: int) -> int | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT MAX(processed_at) AS started_at FROM processed_messages "
                "WHERE sender_key=? AND outcome='challenged' AND processed_at<=?",
                (sender_key, before),
            ).fetchone()
        value = row["started_at"] if row else None
        return int(value) if value is not None else None

    def latest_challenge_terminal_event(
        self, sender_key: str, since: int
    ) -> tuple[str, str] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT rule_code, outcome FROM audit "
                "WHERE sender_key=? AND created_at>=? "
                "AND rule_code IN ('attempts_exhausted', 'CHALLENGE_TIMEOUT') "
                "ORDER BY id DESC LIMIT 1",
                (sender_key, since),
            ).fetchone()
        return (str(row["rule_code"]), str(row["outcome"])) if row else None
