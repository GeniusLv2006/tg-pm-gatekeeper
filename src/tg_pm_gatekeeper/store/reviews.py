# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Monitor-mode pending review queue."""

from __future__ import annotations

import time

from ..states import (
    REVIEW_DECISIONS,
    ReviewStatus,
)
from .base import StoreBase, _inserted_id
from .models import (
    ReviewItem,
)


class ReviewMixin(StoreBase):
    def enqueue_review(
        self,
        sender_key: str,
        reference: bytes,
        classification: str,
        signals: str,
        features: str,
        expires_at: int,
        now: int | None = None,
    ) -> int:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            pending = self._connection.execute(
                "SELECT id, classification FROM review_queue "
                "WHERE sender_key=? AND status='pending'",
                (sender_key,),
            ).fetchone()
            if pending:
                if not (
                    pending["classification"] == "would_quarantine"
                    and classification != "would_quarantine"
                ):
                    self._connection.execute(
                        "UPDATE review_queue SET reference=?, classification=?, "
                        "signals=?, features=?, message_count=message_count+1, "
                        "updated_at=?, expires_at=? WHERE id=?",
                        (
                            reference,
                            classification,
                            signals,
                            features,
                            timestamp,
                            expires_at,
                            pending["id"],
                        ),
                    )
                else:
                    self._connection.execute(
                        "UPDATE review_queue SET message_count=message_count+1, "
                        "updated_at=?, expires_at=? WHERE id=?",
                        (timestamp, expires_at, pending["id"]),
                    )
                return int(pending["id"])
            cursor = self._connection.execute(
                "INSERT INTO review_queue(sender_key, reference, classification, "
                "signals, features, created_at, updated_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sender_key,
                    reference,
                    classification,
                    signals,
                    features,
                    timestamp,
                    timestamp,
                    expires_at,
                ),
            )
        return _inserted_id(cursor)

    def review_items(
        self, *, limit: int = 50, offset: int = 0, now: int | None = None
    ) -> list[ReviewItem]:
        if limit < 1 or offset < 0:
            raise ValueError("invalid review page bounds")
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, sender_key, reference, classification, signals, "
                "features, status, message_count, created_at, updated_at, "
                "expires_at, reviewed_at "
                "FROM review_queue WHERE status='pending' AND expires_at>? "
                "ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?",
                (timestamp, limit, offset),
            ).fetchall()
        return [ReviewItem(**dict(row)) for row in rows]

    def pending_review_count(self, *, now: int | None = None) -> int:
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) FROM review_queue "
                "WHERE status='pending' AND expires_at>?",
                (timestamp,),
            ).fetchone()
        return int(row[0])

    def review_item(self, review_id: int) -> ReviewItem | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT id, sender_key, reference, classification, signals, "
                "features, status, message_count, created_at, updated_at, "
                "expires_at, reviewed_at "
                "FROM review_queue WHERE id=?",
                (review_id,),
            ).fetchone()
        return ReviewItem(**dict(row)) if row else None

    def decide_review(
        self, review_id: int, status: ReviewStatus, now: int | None = None
    ) -> bool:
        if status not in REVIEW_DECISIONS:
            raise ValueError("invalid review decision")
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE review_queue SET status=?, reviewed_at=?, reference=NULL "
                "WHERE id=? AND status='pending'",
                (status, timestamp, review_id),
            )
        return cursor.rowcount == 1

    def decide_sender_reviews(
        self, sender_key: str, status: ReviewStatus, now: int | None = None
    ) -> int:
        if status not in REVIEW_DECISIONS:
            raise ValueError("invalid review decision")
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE review_queue SET status=?, reviewed_at=?, reference=NULL "
                "WHERE sender_key=? AND status='pending'",
                (status, timestamp, sender_key),
            )
            self._connection.execute(
                "UPDATE pending_actions SET status='cancelled',finished_at=? "
                "WHERE sender_key=? AND status IN ('pending','failed')",
                (timestamp, sender_key),
            )
        return cursor.rowcount
