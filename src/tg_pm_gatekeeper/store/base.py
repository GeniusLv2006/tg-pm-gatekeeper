# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Connection ownership and the primitives every store aggregate shares."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from pathlib import Path

from ..states import SenderStatus
from .models import SenderState
from .schema import (
    RELEASED_RESTRICTION_TABLES,
    SENDER_LINKED_TABLES,
    SENDER_STATUSES,
    initialize_schema,
)


def _inserted_id(cursor: sqlite3.Cursor) -> int:
    if cursor.lastrowid is None:
        raise RuntimeError("insert did not produce a row id")
    return cursor.lastrowid


class StoreBase:
    def __init__(self, path: Path, *, pending_review_retention_days: int = 7) -> None:
        if not 1 <= pending_review_retention_days <= 7:
            raise ValueError("pending review retention must be between 1 and 7 days")
        self.pending_review_retention_days = pending_review_retention_days
        self.path = path
        self._last_maintenance = {
            "auto_forgotten": 0,
            "auto_forget_skipped": 0,
            "temporary_released": 0,
        }
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._connection = sqlite3.connect(path, timeout=5)
        os.chmod(path, 0o600)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        try:
            with self._connection:
                self._connection.execute("PRAGMA journal_mode=WAL")
                self._connection.execute("PRAGMA synchronous=FULL")
                self._connection.execute("PRAGMA foreign_keys=ON")
                self._connection.execute("PRAGMA cache_size=-512")
                initialize_schema(self._connection)
                self._connection.execute(
                    "INSERT OR IGNORE INTO settings(key, value) "
                    "VALUES ('mode', 'monitor')"
                )
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def heartbeat(self, now: int | None = None) -> None:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO settings(key, value) VALUES ('heartbeat', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(timestamp),),
            )

    def healthy(
        self,
        *,
        max_age: int = 120,
        max_future_skew: int = 5,
        now: int | None = None,
    ) -> bool:
        timestamp = now or int(time.time())
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM settings WHERE key='heartbeat'"
            ).fetchone()
        if not row:
            return False
        age = timestamp - int(row["value"])
        return -max_future_skew <= age <= max_age

    def get_mode(self) -> str:
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM settings WHERE key='mode'"
            ).fetchone()
        return row["value"] if row else "monitor"

    def set_mode(self, mode: str) -> None:
        if mode not in {"monitor", "protect"}:
            raise ValueError("invalid mode")
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE settings SET value=? WHERE key='mode'", (mode,)
            )
            if mode == "monitor":
                now = int(time.time())
                pending = self._connection.execute(
                    "SELECT sender_key,reference,reason FROM pending_actions "
                    "WHERE status='pending' AND mode_independent=0"
                ).fetchall()
                self._connection.execute(
                    "UPDATE pending_actions SET status='cancelled',finished_at=? "
                    "WHERE status='pending' AND mode_independent=0",
                    (now,),
                )
                for item in pending:
                    exists = self._connection.execute(
                        "SELECT 1 FROM review_queue WHERE sender_key=? AND status='pending'",
                        (item["sender_key"],),
                    ).fetchone()
                    if not exists:
                        self._connection.execute(
                            "INSERT INTO review_queue(sender_key,reference,classification,"
                            "signals,features,created_at,updated_at,expires_at) "
                            "VALUES (?,?,?,'[]','{}',?,?,?)",
                            (
                                item["sender_key"],
                                item["reference"],
                                f"cancelled_{item['reason']}",
                                now,
                                now,
                                now + self.pending_review_retention_days * 86400,
                            ),
                        )

    def protect_preflight(self, *, max_heartbeat_age: int = 120) -> list[str]:
        failures: list[str] = []
        if not self.healthy(max_age=max_heartbeat_age):
            failures.append("service heartbeat is stale")
        with self._lock:
            integrity = str(
                self._connection.execute("PRAGMA quick_check").fetchone()[0]
            )
            active = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM sender_state WHERE status IN "
                    "('challenge_issuing','challenge_archiving','challenged')"
                ).fetchone()[0]
            )
            failed = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM pending_actions WHERE status='failed'"
                ).fetchone()[0]
            )
            unsafe_pending = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM pending_actions AS action "
                    "LEFT JOIN sender_state AS sender "
                    "ON sender.sender_key=action.sender_key "
                    "WHERE action.status='pending' AND (sender.sender_key IS NULL "
                    "OR sender.status NOT IN ('suppressed','quarantined') "
                    "OR sender.revision<>action.expected_revision)"
                ).fetchone()[0]
            )
        if integrity != "ok":
            failures.append("database integrity check failed")
        if active:
            failures.append("active challenges exist")
        if failed:
            failures.append("failed actions require review")
        if unsafe_pending:
            failures.append("stale pending actions require review")
        return failures

    def claim_message(
        self, sender_key: str, message_id: int, now: int | None = None
    ) -> bool:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO processed_messages(sender_key, message_id, outcome, processed_at) "
                "VALUES (?, ?, 'claimed', ?)",
                (sender_key, message_id, timestamp),
            )
        return cursor.rowcount == 1

    def finish_message(self, sender_key: str, message_id: int, outcome: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE processed_messages SET outcome=? WHERE sender_key=? AND message_id=?",
                (outcome, sender_key, message_id),
            )

    def sender(self, sender_key: str) -> SenderState:
        with self._lock:
            row = self._connection.execute(
                "SELECT status, challenge_id, answer_digest, challenge_expires_at, "
                "challenge_message_id, challenge_prompt, challenge_profile, "
                "challenge_action_reference, "
                "restriction_reference, guidance_sent, attempts, suppression_reason, suppressed_until, "
                "revision, updated_at "
                "FROM sender_state WHERE sender_key=?",
                (sender_key,),
            ).fetchone()
        if not row:
            return SenderState(
                SenderStatus.UNKNOWN,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                False,
                0,
                None,
                None,
                0,
                0,
            )
        return SenderState(
            row["status"],
            row["challenge_id"],
            row["answer_digest"],
            row["challenge_expires_at"],
            row["challenge_message_id"],
            row["challenge_prompt"],
            row["challenge_profile"],
            row["challenge_action_reference"],
            row["restriction_reference"],
            bool(row["guidance_sent"]),
            row["attempts"],
            row["suppression_reason"],
            row["suppressed_until"],
            row["revision"],
            row["updated_at"],
        )

    def _set_state(
        self,
        sender_key: str,
        status: SenderStatus,
        *,
        challenge_id: str | None = None,
        answer_digest: str | None = None,
        expires_at: int | None = None,
        attempts: int = 0,
        restriction_reference: bytes | None = None,
        now: int | None = None,
    ) -> None:
        if status not in SENDER_STATUSES:
            raise ValueError("invalid sender status")
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO sender_state(sender_key, status, challenge_id, answer_digest, "
                "challenge_expires_at, challenge_message_id, challenge_prompt, "
                "challenge_action_reference, restriction_reference, guidance_sent, attempts, suppression_reason, "
                "suppressed_until, revision, updated_at) "
                "VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, ?, 0, ?, NULL, NULL, 1, ?) "
                "ON CONFLICT(sender_key) DO UPDATE SET status=excluded.status, "
                "challenge_id=excluded.challenge_id, answer_digest=excluded.answer_digest, "
                "challenge_expires_at=excluded.challenge_expires_at, attempts=excluded.attempts, "
                "challenge_message_id=NULL, challenge_prompt=NULL, "
                "challenge_profile=NULL, challenge_action_reference=NULL, "
                "restriction_reference=excluded.restriction_reference, guidance_sent=0, "
                "suppression_reason=NULL, suppressed_until=NULL, "
                "archived_at=NULL, "
                "revision=sender_state.revision+1, updated_at=excluded.updated_at",
                (
                    sender_key,
                    status,
                    challenge_id,
                    answer_digest,
                    expires_at,
                    restriction_reference,
                    attempts,
                    timestamp,
                ),
            )

    def resolve_sender_actions(self, sender_key: str, now: int | None = None) -> int:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE pending_actions SET status='cancelled',finished_at=? "
                "WHERE sender_key=? AND status IN ('pending','failed')",
                (timestamp, sender_key),
            )
        return cursor.rowcount

    def delete_enforcement_review(self, sender_key: str) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM enforcement_reviews WHERE sender_key=?", (sender_key,)
            )
        return cursor.rowcount == 1

    def _release_expired_suppression(self, sender_key: str, timestamp: int) -> bool:
        """Release one expired temporary suppression inside the caller's transaction."""
        cursor = self._connection.execute(
            "UPDATE sender_state SET status='unknown',suppression_reason=NULL,"
            "suppressed_until=NULL,challenge_action_reference=NULL,"
            "restriction_reference=NULL,revision=revision+1,"
            "archived_at=NULL,"
            "updated_at=? WHERE sender_key=? AND status='suppressed' "
            "AND suppressed_until IS NOT NULL AND suppressed_until<=?",
            (timestamp, sender_key, timestamp),
        )
        if cursor.rowcount != 1:
            return False
        self._connection.execute(
            "UPDATE pending_actions SET status='cancelled',finished_at=?,"
            "reference=X'' "
            "WHERE sender_key=? AND status IN ('pending','failed')",
            (timestamp, sender_key),
        )
        for table in RELEASED_RESTRICTION_TABLES:
            self._connection.execute(
                f"DELETE FROM {table} WHERE sender_key=?",  # noqa: S608
                (sender_key,),
            )
        return True

    def _erase_sender_rows(self, sender_key: str) -> None:
        for table in SENDER_LINKED_TABLES:
            self._connection.execute(
                f"DELETE FROM {table} WHERE sender_key=?",  # noqa: S608
                (sender_key,),
            )

    def audit(
        self, sender_key: str, rule_code: str, outcome: str, now: int | None = None
    ) -> None:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO audit(sender_key, rule_code, outcome, created_at) VALUES (?, ?, ?, ?)",
                (sender_key, rule_code, outcome, timestamp),
            )
