# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Retention pruning and aggregate statistics."""

from __future__ import annotations

import time

from .events import EventMixin
from .restrictions import RestrictionMixin
from .schema import (
    ARCHIVED_PERMANENT_SQL,
    CAMPAIGN_WINDOW_SECONDS,
    OPEN_ACTION_SQL,
    SCHEMA_VERSION,
)


class MaintenanceMixin(RestrictionMixin, EventMixin):
    def prune(
        self,
        retention_days: int,
        now: int | None = None,
        *,
        archived_restriction_retention_days: int | None = None,
        lifecycle_sender_keys: list[str] | None = None,
    ) -> dict[str, int]:
        timestamp = now or int(time.time())
        cutoff = timestamp - retention_days * 86400
        permitted = None if lifecycle_sender_keys is None else set(lifecycle_sender_keys)
        with self._lock, self._connection:
            expired = [
                str(row["sender_key"])
                for row in self._connection.execute(
                    "SELECT sender_key FROM sender_state WHERE status='suppressed' "
                    "AND suppressed_until IS NOT NULL AND suppressed_until<=?",
                    (timestamp,),
                )
                if permitted is None or str(row["sender_key"]) in permitted
            ]
            temporary_released = sum(
                self._release_expired_suppression(sender_key, timestamp)
                for sender_key in expired
            )
            self._connection.execute(
                "DELETE FROM audit WHERE created_at < ?", (cutoff,)
            )
            self._connection.execute(
                "DELETE FROM processed_messages WHERE processed_at < ?", (cutoff,)
            )
            self._connection.execute(
                "DELETE FROM link_events WHERE created_at < ?", (timestamp - 3600,)
            )
            self._connection.execute(
                "DELETE FROM outbound_events WHERE created_at < ?", (timestamp - 3600,)
            )
            self._connection.execute(
                "DELETE FROM campaign_events WHERE observed_at < ?",
                (timestamp - CAMPAIGN_WINDOW_SECONDS,),
            )
            self._connection.execute(
                "DELETE FROM automated_messages WHERE created_at < ?", (cutoff,)
            )
            self._connection.execute(
                "DELETE FROM decision_events WHERE created_at < ?", (cutoff,)
            )
            self._connection.execute(
                "DELETE FROM pending_actions WHERE finished_at < ? "
                "AND (status IN ('completed','cancelled') OR "
                "(status='failed' AND NOT EXISTS (SELECT 1 FROM sender_state "
                "WHERE sender_state.sender_key=pending_actions.sender_key "
                "AND status IN ('quarantined','suppressed'))))",
                (cutoff,),
            )
            self._connection.execute(
                "DELETE FROM review_queue WHERE "
                "(status='pending' AND expires_at <= ?) OR "
                "(status!='pending' AND reviewed_at < ?)",
                (timestamp, cutoff),
            )
            self._connection.execute(
                "DELETE FROM enforcement_reviews WHERE expires_at <= ?", (timestamp,)
            )
            auto_forgotten = 0
            skipped = 0
            if archived_restriction_retention_days is not None:
                archive_cutoff = (
                    timestamp - archived_restriction_retention_days * 86400
                )
                skipped = int(
                    self._connection.execute(
                        f"SELECT COUNT(*) FROM sender_state WHERE {ARCHIVED_PERMANENT_SQL} "  # noqa: S608
                        f"AND archived_at<=? AND {OPEN_ACTION_SQL}",
                        (archive_cutoff,),
                    ).fetchone()[0]
                )
                rows = self._connection.execute(
                    f"SELECT sender_key FROM sender_state WHERE {ARCHIVED_PERMANENT_SQL} "  # noqa: S608
                    f"AND archived_at<=? AND NOT {OPEN_ACTION_SQL}",
                    (archive_cutoff,),
                ).fetchall()
                for row in rows:
                    sender_key = str(row["sender_key"])
                    if permitted is None or sender_key in permitted:
                        self._erase_sender_rows(sender_key)
                        auto_forgotten += 1
            maintenance = {
                "auto_forgotten": auto_forgotten,
                "auto_forget_skipped": skipped,
                "temporary_released": temporary_released,
            }
            for key, value in maintenance.items():
                self._connection.execute(
                    "INSERT INTO settings(key,value) VALUES (?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (f"maintenance_{key}", str(value)),
                )
        self._last_maintenance = maintenance
        return dict(self._last_maintenance)

    def database_statistics(self) -> dict[str, int]:
        with self._lock:
            page_count = int(self._connection.execute("PRAGMA page_count").fetchone()[0])
            freelist_count = int(
                self._connection.execute("PRAGMA freelist_count").fetchone()[0]
            )
            page_size = int(self._connection.execute("PRAGMA page_size").fetchone()[0])
        return {
            "database_page_count": page_count,
            "database_freelist_count": freelist_count,
            "database_page_size": page_size,
            "database_logical_bytes": page_count * page_size,
            "database_freelist_percent": (
                (freelist_count * 100 // page_count) if page_count else 0
            ),
        }

    def statistics(self, *, now: int | None = None) -> dict[str, int | str | None]:
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            states = {
                row["status"]: int(row["count"])
                for row in self._connection.execute(
                    "SELECT status, COUNT(*) AS count FROM sender_state GROUP BY status"
                )
            }
            audit_count = int(
                self._connection.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            )
            heartbeat = self._connection.execute(
                "SELECT value FROM settings WHERE key='heartbeat'"
            ).fetchone()
            pending_reviews = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM review_queue WHERE status='pending' "
                    "AND expires_at>?",
                    (timestamp,),
                ).fetchone()[0]
            )
            challenge_metrics = {
                row["rule_code"]: int(row["count"])
                for row in self._connection.execute(
                    "SELECT rule_code, COUNT(*) AS count FROM audit "
                    "WHERE created_at>=? AND rule_code IN ("
                    "'CHALLENGE_SENT','CHALLENGE_CORRECT',"
                    "'CHALLENGE_WRONG_REPLY_TARGET','CHALLENGE_NON_NUMERIC',"
                    "'CHALLENGE_TIMEOUT','attempts_exhausted',"
                    "'CHALLENGE_RESTORE') GROUP BY rule_code",
                    (timestamp - 7 * 86400,),
                )
            }
            adaptive_metrics = {
                row["assessment"]: int(row["count"])
                for row in self._connection.execute(
                    "SELECT assessment, COUNT(*) AS count FROM decision_events "
                    "WHERE created_at>=? "
                    "AND policy_version IN ('adaptive-v1','adaptive-v2') "
                    "GROUP BY assessment",
                    (timestamp - 7 * 86400,),
                )
            }
            repeated_campaigns = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM decision_events WHERE created_at>=? "
                    "AND policy_version IN ('adaptive-v1','adaptive-v2') "
                    "AND signals LIKE '%\"code\":\"REPEATED_CAMPAIGN\"%'",
                    (timestamp - 7 * 86400,),
                ).fetchone()[0]
            )
            pending_actions = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM pending_actions WHERE status='pending'"
                ).fetchone()[0]
            )
            action_failures = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM pending_actions WHERE status='failed'"
                ).fetchone()[0]
            )
            operator_cleanup_pending = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM operator_artifacts"
                ).fetchone()[0]
            )
            operator_cleanup_retrying = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM operator_artifacts WHERE retry_count>0"
                ).fetchone()[0]
            )
        result: dict[str, int | str | None] = {
            "schema_version": SCHEMA_VERSION,
            "mode": self.get_mode(),
            "allowed": states.get("allowed", 0),
            "challenged": states.get("challenged", 0),
            "challenge_issuing": states.get("challenge_issuing", 0),
            "challenge_archiving": states.get("challenge_archiving", 0),
            "provisional": states.get("provisional", 0),
            "quarantined": states.get("quarantined", 0),
            "suppressed": states.get("suppressed", 0),
            "audit_records": audit_count,
            "pending_reviews": pending_reviews,
            "pending_actions": pending_actions,
            "action_failures": action_failures,
            "operator_cleanup_pending": operator_cleanup_pending,
            "operator_cleanup_retrying": operator_cleanup_retrying,
            "heartbeat": int(heartbeat["value"]) if heartbeat else None,
            "challenge_sent_7d": challenge_metrics.get("CHALLENGE_SENT", 0),
            "challenge_correct_7d": challenge_metrics.get("CHALLENGE_CORRECT", 0),
            "challenge_wrong_reply_7d": challenge_metrics.get(
                "CHALLENGE_WRONG_REPLY_TARGET", 0
            ),
            "challenge_non_numeric_7d": challenge_metrics.get(
                "CHALLENGE_NON_NUMERIC", 0
            ),
            "challenge_timeout_7d": challenge_metrics.get("CHALLENGE_TIMEOUT", 0),
            "challenge_exhausted_7d": challenge_metrics.get("attempts_exhausted", 0),
            "challenge_restore_failed_7d": challenge_metrics.get(
                "CHALLENGE_RESTORE", 0
            ),
            "standard_challenge_7d": adaptive_metrics.get("standard", 0),
            "strict_challenge_7d": adaptive_metrics.get("strict", 0),
            "permanent_suppression_7d": adaptive_metrics.get(
                "permanent_suppression", 0
            ),
            "repeated_campaign_7d": repeated_campaigns,
        }
        result.update(self.outbound_statistics(now=timestamp))
        result["attention_cases"] = self.active_restriction_count(archived=False)
        result["archived_restrictions"] = self.active_restriction_count(archived=True)
        result.update(self.database_statistics())
        with self._lock:
            maintenance_rows = self._connection.execute(
                "SELECT key,value FROM settings WHERE key IN "
                "('maintenance_auto_forgotten','maintenance_auto_forget_skipped',"
                "'maintenance_temporary_released')"
            ).fetchall()
        result.update({
            key: int(next(
                (row["value"] for row in maintenance_rows
                 if row["key"] == f"maintenance_{key}"),
                0,
            ))
            for key in self._last_maintenance
        })
        return result
