# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Active Cases: restrictions, evidence envelopes, and dialog snapshots."""

from __future__ import annotations

import time

from .base import StoreBase
from .models import (
    ActiveRestriction,
    DialogSnapshot,
    EnforcementReview,
)
from .schema import (
    ARCHIVED_PERMANENT_SQL,
    OPEN_ACTION_SQL,
)


class RestrictionMixin(StoreBase):
    def save_dialog_snapshot(self, sender_key: str, snapshot: DialogSnapshot) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT OR IGNORE INTO dialog_snapshots("
                "sender_key, folder_id, silent, mute_until) VALUES (?, ?, ?, ?)",
                (
                    sender_key,
                    snapshot.folder_id,
                    int(snapshot.silent),
                    snapshot.mute_until,
                ),
            )

    def dialog_snapshot(self, sender_key: str) -> DialogSnapshot | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT folder_id, silent, mute_until FROM dialog_snapshots "
                "WHERE sender_key=?",
                (sender_key,),
            ).fetchone()
        if row is None:
            return None
        return DialogSnapshot(
            folder_id=int(row["folder_id"]),
            silent=bool(row["silent"]),
            mute_until=(
                int(row["mute_until"]) if row["mute_until"] is not None else None
            ),
        )

    def clear_dialog_snapshot(self, sender_key: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM dialog_snapshots WHERE sender_key=?", (sender_key,)
            )

    def save_enforcement_review(
        self,
        sender_key: str,
        *,
        reference: bytes | None,
        envelope: bytes,
        reason: str,
        expires_at: int,
        now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO enforcement_reviews(sender_key,reference,envelope,reason,"
                "created_at,updated_at,expires_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(sender_key) DO NOTHING",
                (
                    sender_key,
                    reference,
                    envelope,
                    reason,
                    timestamp,
                    timestamp,
                    expires_at,
                ),
            )

    def activate_enforcement_review(
        self,
        sender_key: str,
        reason: str,
        expires_at: int,
        *,
        reference: bytes | None = None,
        now: int | None = None,
    ) -> bool:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE enforcement_reviews SET reference=COALESCE(reference,?),"
                "reason=?,updated_at=?,expires_at=? WHERE sender_key=?",
                (reference, reason, timestamp, expires_at, sender_key),
            )
        return cursor.rowcount == 1

    def enforcement_review(
        self, sender_key: str, *, now: int | None = None
    ) -> EnforcementReview | None:
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            row = self._connection.execute(
                "SELECT review.sender_key,review.reference,review.envelope,review.reason,"
                "review.created_at,review.updated_at,review.expires_at,sender.status,"
                "sender.suppressed_until FROM enforcement_reviews AS review "
                "JOIN sender_state AS sender ON sender.sender_key=review.sender_key "
                "WHERE review.sender_key=? AND review.expires_at>? "
                "AND sender.status IN ('quarantined','suppressed')",
                (sender_key, timestamp),
            ).fetchone()
        return EnforcementReview(**dict(row)) if row else None

    def enforcement_reviews(
        self, *, limit: int = 100, now: int | None = None
    ) -> list[EnforcementReview]:
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            rows = self._connection.execute(
                "SELECT review.sender_key,review.reference,review.envelope,review.reason,"
                "review.created_at,review.updated_at,review.expires_at,sender.status,"
                "sender.suppressed_until FROM enforcement_reviews AS review "
                "JOIN sender_state AS sender ON sender.sender_key=review.sender_key "
                "WHERE review.expires_at>? "
                "AND sender.status IN ('quarantined','suppressed') "
                "ORDER BY review.updated_at DESC LIMIT ?",
                (timestamp, limit),
            ).fetchall()
        return [EnforcementReview(**dict(row)) for row in rows]

    def active_restriction(
        self, sender_key: str, *, now: int | None = None
    ) -> ActiveRestriction | None:
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            row = self._connection.execute(
                self._active_restriction_select()
                + " WHERE sender.sender_key=? AND sender.status IN "
                "('quarantined','suppressed')",
                (timestamp, sender_key),
            ).fetchone()
        return ActiveRestriction(**dict(row)) if row else None

    def active_restrictions(
        self,
        *,
        archived: bool | None = None,
        reason: str | None = None,
        archived_before: int | None = None,
        limit: int | None = None,
        offset: int = 0,
        now: int | None = None,
    ) -> list[ActiveRestriction]:
        if offset < 0 or (limit is not None and limit < 1):
            raise ValueError("invalid active restriction page bounds")
        timestamp = int(time.time()) if now is None else now
        ordering = (
            "sender.archived_at DESC, sender.sender_key ASC"
            if archived is True
            else "sender.updated_at DESC, sender.sender_key ASC"
        )
        filters = self._restriction_partition(archived) + " "
        parameters: list[object] = [timestamp]
        if reason is not None:
            filters += f"AND {self._restriction_reason_sql()}=? "
            parameters.append(reason)
        if archived_before is not None:
            filters += "AND sender.archived_at<=? "
            parameters.append(archived_before)
        query = self._active_restriction_select() + f" WHERE {filters}ORDER BY {ordering}"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            parameters.extend((limit, offset))
        with self._lock:
            rows = self._connection.execute(query, tuple(parameters)).fetchall()
        return [ActiveRestriction(**dict(row)) for row in rows]

    def active_restriction_count(
        self,
        *,
        archived: bool | None = None,
        reason: str | None = None,
        archived_before: int | None = None,
        now: int | None = None,
    ) -> int:
        timestamp = int(time.time()) if now is None else now
        where = self._restriction_partition(archived)
        parameters: list[object] = [timestamp]
        if reason is not None:
            where += f" AND {self._restriction_reason_sql()}=?"
            parameters.append(reason)
        if archived_before is not None:
            where += " AND sender.archived_at<=?"
            parameters.append(archived_before)
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) FROM sender_state AS sender "  # noqa: S608 -- internal clauses
                "LEFT JOIN enforcement_reviews AS review ON "
                "review.sender_key=sender.sender_key AND review.expires_at>? "
                f"WHERE {where}",
                tuple(parameters),
            ).fetchone()
        return int(row[0])

    @staticmethod
    def _restriction_partition(archived: bool | None) -> str:
        """Return the WHERE clause shared by restriction lists, counts, and statistics.

        Archived restrictions are confirmed permanent suppressions with no open work;
        everything else that is still restricted needs attention.
        """
        if archived is True:
            return (
                "sender.status='suppressed' AND sender.suppressed_until IS NULL "
                "AND sender.archived_at IS NOT NULL AND NOT EXISTS ("
                "SELECT 1 FROM pending_actions AS action WHERE "
                "action.sender_key=sender.sender_key AND "
                "action.status IN ('pending','failed'))"
            )
        if archived is False:
            return (
                "sender.status IN ('quarantined','suppressed') AND ("
                "sender.status='quarantined' OR sender.suppressed_until IS NOT NULL OR "
                "sender.archived_at IS NULL OR EXISTS (SELECT 1 FROM pending_actions AS action "
                "WHERE action.sender_key=sender.sender_key AND "
                "action.status IN ('pending','failed')))"
            )
        return "sender.status IN ('quarantined','suppressed')"

    @staticmethod
    def _restriction_reason_sql() -> str:
        """Return the displayed restriction reason; filters must match what lists show."""
        return (
            "COALESCE(sender.suppression_reason,review.reason,"
            "CASE WHEN EXISTS (SELECT 1 FROM review_queue AS verdict "
            "WHERE verdict.sender_key=sender.sender_key AND verdict.status='spam') "
            "THEN 'manual_spam' ELSE 'reason_unavailable' END)"
        )

    @classmethod
    def _active_restriction_select(cls) -> str:
        return (
            "SELECT sender.sender_key,sender.restriction_reference AS reference,"  # noqa: S608 -- internal clauses
            f"sender.status,{cls._restriction_reason_sql()} AS reason,"
            "sender.suppressed_until,sender.updated_at,review.envelope,"
            "review.created_at AS evidence_created_at,"
            "review.expires_at AS evidence_expires_at,sender.archived_at,"
            "EXISTS (SELECT 1 FROM pending_actions AS action WHERE "
            "action.sender_key=sender.sender_key AND action.status IN "
            "('pending','failed')) AS has_open_actions FROM sender_state AS sender "
            "LEFT JOIN enforcement_reviews AS review ON "
            "review.sender_key=sender.sender_key AND review.expires_at>?"
        )

    def legacy_restriction_references(self) -> list[tuple[str, bytes]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT sender.sender_key,COALESCE(sender.challenge_action_reference,"
                "(SELECT review.reference FROM enforcement_reviews AS review "
                "WHERE review.sender_key=sender.sender_key AND review.reference IS NOT NULL),"
                "(SELECT queue.reference FROM review_queue AS queue "
                "WHERE queue.sender_key=sender.sender_key AND queue.reference IS NOT NULL "
                "ORDER BY queue.updated_at DESC LIMIT 1)) AS reference "
                "FROM sender_state AS sender WHERE sender.status IN "
                "('quarantined','suppressed') AND sender.restriction_reference IS NULL"
            ).fetchall()
        return [
            (str(row["sender_key"]), bytes(row["reference"]))
            for row in rows
            if row["reference"] is not None
        ]

    def save_restriction_reference(self, sender_key: str, reference: bytes) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET restriction_reference=? WHERE sender_key=? "
                "AND status IN ('quarantined','suppressed') "
                "AND restriction_reference IS NULL",
                (reference, sender_key),
            )
        return cursor.rowcount == 1

    def enforcement_statistics(
        self, *, archived: bool | None = None, now: int | None = None
    ) -> dict[str, int]:
        """Count restrictions in the same partition the restriction lists use."""
        timestamp = int(time.time()) if now is None else now
        partition = self._restriction_partition(archived)
        source = (
            "FROM sender_state AS sender LEFT JOIN enforcement_reviews AS review "
            "ON review.sender_key=sender.sender_key AND review.expires_at>? "
            f"WHERE {partition}"
        )
        with self._lock:
            rows = self._connection.execute(
                f"SELECT sender.status,COUNT(*) AS count {source} GROUP BY sender.status",  # noqa: S608 -- internal clauses
                (timestamp,),
            ).fetchall()
            reasons = self._connection.execute(
                f"SELECT {self._restriction_reason_sql()} AS reason,COUNT(*) AS count "  # noqa: S608 -- internal clauses
                f"{source} GROUP BY reason",
                (timestamp,),
            ).fetchall()
            reviewable = int(
                self._connection.execute(
                    f"SELECT COUNT(review.sender_key) {source}",  # noqa: S608 -- internal clauses
                    (timestamp,),
                ).fetchone()[0]
            )
            identifiable = int(
                self._connection.execute(
                    f"SELECT COUNT(*) {source} AND sender.restriction_reference IS NOT NULL",  # noqa: S608 -- internal clauses
                    (timestamp,),
                ).fetchone()[0]
            )
        result = {
            "quarantined": 0,
            "suppressed": 0,
            "reviewable": reviewable,
            "identifiable": identifiable,
        }
        result.update({str(row["status"]): int(row["count"]) for row in rows})
        result["unreviewable"] = (
            result["quarantined"] + result["suppressed"] - reviewable
        )
        result["unidentified"] = (
            result["quarantined"] + result["suppressed"] - identifiable
        )
        result.update(
            {f"reason:{row['reason']}": int(row["count"]) for row in reasons}
        )
        return result

    def archive_restriction(self, sender_key: str, now: int | None = None) -> bool:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET archived_at=? WHERE sender_key=? "
                "AND status='suppressed' AND suppressed_until IS NULL",
                (timestamp, sender_key),
            )
        return cursor.rowcount == 1

    def unarchive_restriction(self, sender_key: str) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE sender_state SET archived_at=NULL WHERE sender_key=? "
                "AND status='suppressed' AND suppressed_until IS NULL "
                "AND archived_at IS NOT NULL",
                (sender_key,),
            )
        return cursor.rowcount == 1

    def forget_restriction(
        self, sender_key: str, *, archived_before: int | None = None
    ) -> bool:
        """Erase one archived permanent restriction and every sender-linked row."""
        with self._lock, self._connection:
            eligible = self._connection.execute(
                f"SELECT 1 FROM sender_state WHERE sender_key=? AND {ARCHIVED_PERMANENT_SQL} "  # noqa: S608
                f"AND (? IS NULL OR archived_at<=?) AND NOT {OPEN_ACTION_SQL}",
                (sender_key, archived_before, archived_before),
            ).fetchone()
            if eligible is None:
                return False
            self._erase_sender_rows(sender_key)
        return True

    def archived_before_keys(self, cutoff: int) -> list[str]:
        """Candidates only; every deletion must recheck eligibility in its transaction."""
        with self._lock:
            rows = self._connection.execute(
                f"SELECT sender_key FROM sender_state WHERE {ARCHIVED_PERMANENT_SQL} "  # noqa: S608
                "AND archived_at<=? ORDER BY sender_key",
                (cutoff,),
            ).fetchall()
        return [str(row["sender_key"]) for row in rows]

    def maintenance_sender_keys(
        self, now: int, archived_restriction_retention_days: int | None
    ) -> list[str]:
        with self._lock:
            expired = self._connection.execute(
                "SELECT sender_key FROM sender_state WHERE status='suppressed' "
                "AND suppressed_until IS NOT NULL AND suppressed_until<=?",
                (now,),
            ).fetchall()
            keys = {str(row["sender_key"]) for row in expired}
            if archived_restriction_retention_days is not None:
                keys.update(
                    self.archived_before_keys(
                        now - archived_restriction_retention_days * 86400
                    )
                )
        return sorted(keys)

    def archived_before_count(self, cutoff: int) -> int:
        with self._lock:
            row = self._connection.execute(
                f"SELECT COUNT(*) FROM sender_state WHERE {ARCHIVED_PERMANENT_SQL} "  # noqa: S608
                f"AND archived_at<=? AND NOT {OPEN_ACTION_SQL}",
                (cutoff,),
            ).fetchone()
        return int(row[0])
