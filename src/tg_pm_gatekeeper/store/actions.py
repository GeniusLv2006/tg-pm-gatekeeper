# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Persistent deletion jobs and operator-artifact cleanup queue."""

from __future__ import annotations

import time

from ..states import (
    FINISHED_ACTION_STATUSES,
    RESTRICTED_STATUSES,
    ActionStatus,
    SenderStatus,
)
from .base import StoreBase, _inserted_id
from .models import (
    PendingAction,
)


class ActionMixin(StoreBase):
    def schedule_action(
        self,
        sender_key: str,
        *,
        reason: str,
        reference: bytes,
        execute_at: int,
        expected_revision: int,
        mode_independent: bool = False,
        now: int | None = None,
    ) -> int:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE pending_actions SET status='cancelled',finished_at=? "
                "WHERE sender_key=? AND status='pending'",
                (timestamp, sender_key),
            )
            cursor = self._connection.execute(
                "INSERT INTO pending_actions(sender_key,action,reason,reference,execute_at,"
                "expected_revision,mode_independent,created_at) "
                "VALUES (?,'delete_dialog',?,?,?,?,?,?)",
                (
                    sender_key,
                    reason,
                    reference,
                    execute_at,
                    expected_revision,
                    int(mode_independent),
                    timestamp,
                ),
            )
        return _inserted_id(cursor)

    def pending_actions(self) -> list[PendingAction]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT id,sender_key,action,reason,reference,execute_at,"
                "expected_revision,mode_independent,status,created_at,finished_at "
                "FROM pending_actions "
                "WHERE status='pending' ORDER BY execute_at"
            ).fetchall()
        return [PendingAction(**dict(row)) for row in rows]

    def pending_action_sender_key(self, action_id: int) -> str | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT sender_key FROM pending_actions WHERE id=? AND status='pending'",
                (action_id,),
            ).fetchone()
        return str(row["sender_key"]) if row is not None else None

    def claim_action(
        self, action_id: int, now: int | None = None
    ) -> PendingAction | None:
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            row = self._connection.execute(
                "SELECT id,sender_key,action,reason,reference,execute_at,"
                "expected_revision,mode_independent,status,created_at,finished_at "
                "FROM pending_actions "
                "WHERE id=? AND status='pending'",
                (action_id,),
            ).fetchone()
            if row is None:
                return None
            if self.get_mode() != "protect" and not bool(row["mode_independent"]):
                return None
            state = self.sender(str(row["sender_key"]))
            if state.status not in RESTRICTED_STATUSES or state.revision != int(row["expected_revision"]):
                return None
            if (
                state.status == SenderStatus.SUPPRESSED
                and state.suppressed_until is not None
                and state.suppressed_until <= timestamp
            ):
                return None
        return PendingAction(**dict(row))

    def finish_action(
        self, action_id: int, status: ActionStatus, now: int | None = None
    ) -> bool:
        if status not in FINISHED_ACTION_STATUSES:
            raise ValueError("invalid action status")
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            if status == ActionStatus.COMPLETED:
                cursor = self._connection.execute(
                    "UPDATE pending_actions SET status=?,finished_at=?,reference=X'' "
                    "WHERE id=? AND status='pending'",
                    (status, timestamp, action_id),
                )
            else:
                cursor = self._connection.execute(
                    "UPDATE pending_actions SET status=?,finished_at=? "
                    "WHERE id=? AND status='pending'",
                    (status, timestamp, action_id),
                )
        return cursor.rowcount == 1

    def clear_action_reference(self, sender_key: str, expected_revision: int) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET challenge_action_reference=NULL "
                "WHERE sender_key=? AND status='suppressed' AND revision=?",
                (sender_key, expected_revision),
            )
        return cursor.rowcount == 1

    def enqueue_action_failure(
        self, action: PendingAction, now: int | None = None
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            exists = self._connection.execute(
                "SELECT 1 FROM review_queue WHERE sender_key=? AND status='pending'",
                (action.sender_key,),
            ).fetchone()
            if not exists:
                self._connection.execute(
                    "INSERT INTO review_queue(sender_key,reference,classification,signals,"
                    "features,created_at,updated_at,expires_at) "
                    "VALUES (?,?,?,'[]','{}',?,?,?)",
                    (
                        action.sender_key,
                        action.reference,
                        f"{action.reason}_action_failed",
                        timestamp,
                        timestamp,
                        timestamp + self.pending_review_retention_days * 86400,
                    ),
                )

    def schedule_operator_artifacts(
        self, message_ids: list[int] | tuple[int, ...], delete_at: int
    ) -> None:
        unique_ids = tuple(dict.fromkeys(message_ids))
        if not unique_ids:
            return
        if delete_at < 0 or any(message_id <= 0 for message_id in unique_ids):
            raise ValueError("invalid operator artifact cleanup")
        with self._lock, self._connection:
            self._connection.executemany(
                "INSERT INTO operator_artifacts(message_id,delete_at) VALUES (?,?) "
                "ON CONFLICT(message_id) DO UPDATE SET "
                "delete_at=MIN(operator_artifacts.delete_at,excluded.delete_at)",
                ((message_id, delete_at) for message_id in unique_ids),
            )

    def due_operator_artifacts(
        self, now: int, *, limit: int = 100
    ) -> list[tuple[int, int]]:
        if limit < 1 or limit > 1000:
            raise ValueError("invalid operator artifact limit")
        with self._lock:
            rows = self._connection.execute(
                "SELECT message_id,retry_count FROM operator_artifacts "
                "WHERE delete_at<=? ORDER BY delete_at,message_id LIMIT ?",
                (now, limit),
            ).fetchall()
        return [(int(row["message_id"]), int(row["retry_count"])) for row in rows]

    def next_operator_artifact_delete_at(self) -> int | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT MIN(delete_at) AS delete_at FROM operator_artifacts"
            ).fetchone()
        return int(row["delete_at"]) if row and row["delete_at"] is not None else None

    def complete_operator_artifacts(
        self, message_ids: list[int] | tuple[int, ...]
    ) -> None:
        unique_ids = tuple(dict.fromkeys(message_ids))
        if not unique_ids:
            return
        with self._lock, self._connection:
            self._connection.executemany(
                "DELETE FROM operator_artifacts WHERE message_id=?",
                ((message_id,) for message_id in unique_ids),
            )

    def retry_operator_artifacts(
        self, message_ids: list[int] | tuple[int, ...], retry_at: int
    ) -> None:
        unique_ids = tuple(dict.fromkeys(message_ids))
        if not unique_ids:
            return
        with self._lock, self._connection:
            self._connection.executemany(
                "UPDATE operator_artifacts SET delete_at=?,retry_count=retry_count+1 "
                "WHERE message_id=?",
                ((retry_at, message_id) for message_id in unique_ids),
            )
