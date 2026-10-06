# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Short-lived detector, rate-limit, and automated-message records."""

from __future__ import annotations

import time

from .base import StoreBase
from .schema import CAMPAIGN_WINDOW_SECONDS


class EventMixin(StoreBase):
    def record_decision(
        self,
        sender_key: str,
        *,
        detector: str,
        signals: str,
        assessment: str,
        risk_score: float | None,
        model_version: str | None,
        decision_basis: str,
        planned_action: str,
        actual_action: str,
        policy_version: str,
        now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO decision_events(sender_key,detector,signals,assessment,"
                "risk_score,model_version,decision_basis,planned_action,actual_action,"
                "policy_version,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    sender_key,
                    detector,
                    signals,
                    assessment,
                    risk_score,
                    model_version,
                    decision_basis,
                    planned_action,
                    actual_action,
                    policy_version,
                    timestamp,
                ),
            )

    def recent_link_messages(
        self, sender_key: str, *, window_seconds: int = 60, now: int | None = None
    ) -> int:
        timestamp = now or int(time.time())
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM link_events WHERE sender_key=? AND created_at>=?",
                (sender_key, timestamp - window_seconds),
            ).fetchone()
        return int(row["count"])

    def record_link_message(self, sender_key: str, now: int | None = None) -> None:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO link_events(sender_key, created_at) VALUES (?, ?)",
                (sender_key, timestamp),
            )

    def observe_campaign(
        self,
        fingerprint: str,
        sender_key: str,
        *,
        window_seconds: int = CAMPAIGN_WINDOW_SECONDS,
        now: int | None = None,
    ) -> int:
        timestamp = int(time.time()) if now is None else now
        cutoff = timestamp - window_seconds
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM campaign_events WHERE observed_at < ?", (cutoff,)
            )
            self._connection.execute(
                "INSERT INTO campaign_events(fingerprint,sender_key,observed_at) "
                "VALUES (?,?,?) ON CONFLICT(fingerprint,sender_key) DO UPDATE SET "
                "observed_at=excluded.observed_at",
                (fingerprint, sender_key, timestamp),
            )
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM campaign_events "
                "WHERE fingerprint=? AND observed_at>=?",
                (fingerprint, cutoff),
            ).fetchone()
        return int(row["count"])

    def claim_outbound_slot(
        self,
        *,
        limit: int,
        notice_reserve: int,
        notice_sender_limit: int,
        sender_key: str,
        category: str,
        now: int | None = None,
    ) -> bool:
        if limit < 1:
            raise ValueError("outbound limit must be positive")
        if not 0 <= notice_reserve < limit:
            raise ValueError("notice reserve must be between zero and limit minus one")
        if notice_sender_limit < 1:
            raise ValueError("sender notice limit must be positive")
        if not sender_key:
            raise ValueError("sender key is required")
        if category not in {"challenge", "notice"}:
            raise ValueError("invalid outbound category")
        timestamp = int(time.time()) if now is None else now
        rejected_category = f"{category}_rejected"
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                cutoff = timestamp - 3600
                self._connection.execute(
                    "DELETE FROM outbound_events WHERE created_at < ?", (cutoff,)
                )
                total = int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM outbound_events WHERE created_at>=? "
                        "AND category IN ('legacy','challenge','notice')",
                        (cutoff,),
                    ).fetchone()[0]
                )
                allowed = total < limit
                if category == "challenge":
                    allowed = allowed and total < limit - notice_reserve
                else:
                    sender_notices = int(
                        self._connection.execute(
                            "SELECT COUNT(*) FROM outbound_events "
                            "WHERE created_at>=? AND sender_key=? AND category='notice'",
                            (cutoff, sender_key),
                        ).fetchone()[0]
                    )
                    allowed = allowed and sender_notices < notice_sender_limit
                self._connection.execute(
                    "INSERT INTO outbound_events(sender_key,category,created_at) "
                    "VALUES (?,?,?)",
                    (
                        sender_key,
                        category if allowed else rejected_category,
                        timestamp,
                    ),
                )
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
            else:
                self._connection.execute("COMMIT")
        return allowed

    def outbound_statistics(self, *, now: int | None = None) -> dict[str, int]:
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            rows = self._connection.execute(
                "SELECT category,COUNT(*) AS count FROM outbound_events "
                "WHERE created_at>=? GROUP BY category",
                (timestamp - 3600,),
            ).fetchall()
        counts = {str(row["category"]): int(row["count"]) for row in rows}
        return {
            "outbound_total_1h": sum(
                counts.get(category, 0)
                for category in ("legacy", "challenge", "notice")
            ),
            "outbound_challenge_1h": counts.get("challenge", 0),
            "outbound_notice_1h": counts.get("notice", 0),
            "outbound_quota_rejected_1h": (
                counts.get("challenge_rejected", 0)
                + counts.get("notice_rejected", 0)
            ),
        }

    def record_automated_message(
        self, sender_key: str, message_id: int, now: int | None = None
    ) -> None:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT OR IGNORE INTO automated_messages(sender_key, message_id, "
                "created_at) VALUES (?, ?, ?)",
                (sender_key, message_id, timestamp),
            )

    def message_ids_since(self, sender_key: str, since: int) -> list[int]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT message_id FROM processed_messages "
                "WHERE sender_key=? AND processed_at>=? UNION "
                "SELECT message_id FROM automated_messages "
                "WHERE sender_key=? AND created_at>=? ORDER BY message_id",
                (sender_key, since, sender_key, since),
            ).fetchall()
        return [int(row["message_id"]) for row in rows]

    def message_ids_between(
        self, sender_key: str, first_message_id: int, last_message_id: int
    ) -> list[int]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT message_id FROM processed_messages "
                "WHERE sender_key=? AND message_id BETWEEN ? AND ? UNION "
                "SELECT message_id FROM automated_messages "
                "WHERE sender_key=? AND message_id BETWEEN ? AND ? "
                "ORDER BY message_id",
                (
                    sender_key,
                    first_message_id,
                    last_message_id,
                    sender_key,
                    first_message_id,
                    last_message_id,
                ),
            ).fetchall()
        return [int(row["message_id"]) for row in rows]

    def automated_message_ids_between(
        self, sender_key: str, first_message_id: int, last_message_id: int
    ) -> list[int]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT message_id FROM automated_messages WHERE sender_key=? "
                "AND message_id BETWEEN ? AND ? ORDER BY message_id",
                (sender_key, first_message_id, last_message_id),
            ).fetchall()
        return [int(row["message_id"]) for row in rows]

    def is_automated_message(self, sender_key: str, message_id: int) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM automated_messages WHERE sender_key=? AND message_id=?",
                (sender_key, message_id),
            ).fetchone()
        return row is not None
