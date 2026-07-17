# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 7
SENDER_STATUSES = (
    "unknown",
    "challenge_issuing",
    "challenge_archiving",
    "challenged",
    "provisional",
    "allowed",
    "quarantined",
    "suppressed",
)
SENDER_STATE_SCHEMA = """
CREATE TABLE sender_state (
    sender_key TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN (
        'unknown', 'challenge_issuing', 'challenge_archiving', 'challenged',
        'provisional', 'allowed', 'quarantined', 'suppressed'
    )),
    challenge_id TEXT,
    answer_digest TEXT,
    challenge_expires_at INTEGER,
    challenge_message_id INTEGER,
    challenge_prompt TEXT,
    challenge_profile TEXT CHECK (challenge_profile IN ('standard', 'strict')),
    challenge_action_reference BLOB,
    restriction_reference BLOB,
    guidance_sent INTEGER NOT NULL DEFAULT 0 CHECK (guidance_sent IN (0, 1)),
    attempts INTEGER NOT NULL DEFAULT 0,
    suppression_reason TEXT,
    suppressed_until INTEGER,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
"""
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS processed_messages (
    sender_key TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    processed_at INTEGER NOT NULL,
    PRIMARY KEY (sender_key, message_id)
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_key TEXT NOT NULL,
    rule_code TEXT NOT NULL,
    outcome TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_created_at_idx ON audit(created_at);
CREATE TABLE IF NOT EXISTS link_events (
    sender_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS link_events_sender_time_idx ON link_events(sender_key, created_at);
CREATE TABLE IF NOT EXISTS outbound_events (
    sender_key TEXT,
    category TEXT NOT NULL CHECK (category IN (
        'legacy', 'challenge', 'notice', 'challenge_rejected', 'notice_rejected'
    )),
    created_at INTEGER NOT NULL,
    CHECK ((category='legacy' AND sender_key IS NULL) OR
           (category!='legacy' AND sender_key IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS outbound_events_time_idx ON outbound_events(created_at);
CREATE INDEX IF NOT EXISTS outbound_events_sender_category_time_idx
    ON outbound_events(sender_key, category, created_at);
CREATE TABLE IF NOT EXISTS automated_messages (
    sender_key TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (sender_key, message_id)
);
CREATE INDEX IF NOT EXISTS automated_messages_created_idx
    ON automated_messages(created_at);
CREATE TABLE IF NOT EXISTS operator_artifacts (
    message_id INTEGER PRIMARY KEY,
    delete_at INTEGER NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0)
);
CREATE INDEX IF NOT EXISTS operator_artifacts_delete_at_idx
    ON operator_artifacts(delete_at);
CREATE TABLE IF NOT EXISTS dialog_snapshots (
    sender_key TEXT PRIMARY KEY,
    folder_id INTEGER NOT NULL,
    silent INTEGER NOT NULL CHECK (silent IN (0, 1)),
    mute_until INTEGER
);
CREATE TABLE IF NOT EXISTS review_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_key TEXT NOT NULL,
    reference BLOB,
    classification TEXT NOT NULL,
    signals TEXT NOT NULL,
    features TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'legitimate', 'spam', 'dismissed')),
    message_count INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    reviewed_at INTEGER
);
CREATE INDEX IF NOT EXISTS review_queue_status_created_idx
    ON review_queue(status, created_at);
CREATE TABLE IF NOT EXISTS pending_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_key TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('delete_dialog')),
    reason TEXT NOT NULL,
    reference BLOB NOT NULL,
    execute_at INTEGER NOT NULL,
    expected_revision INTEGER NOT NULL,
    mode_independent INTEGER NOT NULL DEFAULT 0 CHECK (mode_independent IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'cancelled', 'completed', 'failed')),
    created_at INTEGER NOT NULL,
    finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS pending_actions_status_time_idx
    ON pending_actions(status, execute_at);
CREATE TABLE IF NOT EXISTS decision_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_key TEXT NOT NULL,
    detector TEXT NOT NULL,
    signals TEXT NOT NULL,
    assessment TEXT NOT NULL,
    risk_score REAL,
    model_version TEXT,
    decision_basis TEXT NOT NULL,
    planned_action TEXT NOT NULL,
    actual_action TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS decision_events_created_idx
    ON decision_events(created_at);
CREATE TABLE IF NOT EXISTS campaign_events (
    fingerprint TEXT NOT NULL,
    sender_key TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (fingerprint, sender_key)
);
CREATE INDEX IF NOT EXISTS campaign_events_fingerprint_time_idx
    ON campaign_events(fingerprint, observed_at);
CREATE TABLE IF NOT EXISTS enforcement_reviews (
    sender_key TEXT PRIMARY KEY,
    reference BLOB,
    envelope BLOB NOT NULL,
    reason TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS enforcement_reviews_expiry_idx
    ON enforcement_reviews(expires_at);
"""


@dataclass(frozen=True, slots=True)
class SenderState:
    status: str
    challenge_id: str | None
    answer_digest: str | None
    challenge_expires_at: int | None
    challenge_message_id: int | None
    challenge_prompt: str | None
    challenge_profile: str | None
    challenge_action_reference: bytes | None
    restriction_reference: bytes | None
    guidance_sent: bool
    attempts: int
    suppression_reason: str | None
    suppressed_until: int | None
    revision: int
    updated_at: int


class StoreMigrationError(RuntimeError):
    """Raised when an existing state database cannot be migrated safely."""


@dataclass(frozen=True, slots=True)
class ReviewItem:
    id: int
    sender_key: str
    reference: bytes | None
    classification: str
    signals: str
    features: str
    status: str
    message_count: int
    created_at: int
    updated_at: int
    expires_at: int
    reviewed_at: int | None


@dataclass(frozen=True, slots=True)
class EnforcementReview:
    sender_key: str
    reference: bytes | None
    envelope: bytes
    reason: str
    created_at: int
    updated_at: int
    expires_at: int
    status: str
    suppressed_until: int | None


@dataclass(frozen=True, slots=True)
class ActiveRestriction:
    sender_key: str
    reference: bytes | None
    status: str
    reason: str
    suppressed_until: int | None
    updated_at: int
    envelope: bytes | None
    evidence_created_at: int | None
    evidence_expires_at: int | None


@dataclass(frozen=True, slots=True)
class DialogSnapshot:
    folder_id: int
    silent: bool
    mute_until: int | None


@dataclass(frozen=True, slots=True)
class PendingAction:
    id: int
    sender_key: str
    action: str
    reason: str
    reference: bytes
    execute_at: int
    expected_revision: int
    mode_independent: int
    status: str
    created_at: int
    finished_at: int | None


class StateStore:
    def __init__(self, path: Path, *, pending_review_retention_days: int = 7) -> None:
        if not 1 <= pending_review_retention_days <= 7:
            raise ValueError("pending review retention must be between 1 and 7 days")
        self.pending_review_retention_days = pending_review_retention_days
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
                self._initialize_schema()
                self._connection.execute(
                    "INSERT OR IGNORE INTO settings(key, value) "
                    "VALUES ('mode', 'monitor')"
                )
        except Exception:
            self._connection.close()
            raise

    def _initialize_schema(self) -> None:
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        sender_table = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sender_state'"
        ).fetchone()
        if sender_table is None:
            self._connection.executescript(SENDER_STATE_SCHEMA + SCHEMA)
            self._connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            return
        if version == 0:
            self._migrate_v0_to_v1()
            version = 4
        elif version == 1:
            self._migrate_v1_to_v2()
            version = 4
        else:
            if version == 2:
                self._migrate_v2_to_v3()
                version = 3
            if version == 3:
                self._migrate_v3_to_v4()
                version = 4
        if version == 4:
            self._migrate_v4_to_v5()
            version = 5
        if version == 5:
            self._migrate_v5_to_v6()
            version = 6
        if version == 6:
            self._migrate_v6_to_v7()
            version = 7
        if version != SCHEMA_VERSION:
            raise StoreMigrationError(f"unsupported database schema version: {version}")
        self._connection.executescript(SCHEMA)

    def _migrate_v0_to_v1(self) -> None:
        active = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM sender_state WHERE status='challenged'"
            ).fetchone()[0]
        )
        if active:
            raise StoreMigrationError(
                "cannot migrate while legacy challenged senders exist"
            )
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "ALTER TABLE sender_state RENAME TO sender_state_v0"
            )
            self._connection.execute(SENDER_STATE_SCHEMA)
            self._connection.execute(
                "INSERT INTO sender_state(sender_key, status, challenge_id, "
                "answer_digest, challenge_expires_at, attempts, updated_at) "
                "SELECT sender_key, status, challenge_id, answer_digest, "
                "challenge_expires_at, attempts, updated_at FROM sender_state_v0"
            )
            self._connection.execute("DROP TABLE sender_state_v0")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS automated_messages ("
                "sender_key TEXT NOT NULL, message_id INTEGER NOT NULL, "
                "created_at INTEGER NOT NULL, PRIMARY KEY (sender_key, message_id))"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS automated_messages_created_idx "
                "ON automated_messages(created_at)"
            )
            self._connection.execute(
                "UPDATE settings SET value=CASE value "
                "WHEN 'observe' THEN 'monitor' WHEN 'enforce' THEN 'protect' "
                "ELSE value END WHERE key='mode'"
            )
            self._connection.execute("PRAGMA user_version=4")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    def _migrate_v3_to_v4(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            columns = {
                str(row["name"])
                for row in self._connection.execute("PRAGMA table_info(sender_state)")
            }
            if "restriction_reference" not in columns:
                self._connection.execute(
                    "ALTER TABLE sender_state ADD COLUMN restriction_reference BLOB"
                )
            self._connection.execute("PRAGMA user_version=4")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    def _migrate_v4_to_v5(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            table = self._connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type='table' AND name='outbound_events'"
            ).fetchone()
            self._connection.execute("DROP INDEX IF EXISTS outbound_events_time_idx")
            self._connection.execute(
                "DROP INDEX IF EXISTS outbound_events_sender_category_time_idx"
            )
            if table is not None:
                self._connection.execute(
                    "ALTER TABLE outbound_events RENAME TO outbound_events_v4"
                )
            self._connection.execute(
                "CREATE TABLE outbound_events ("
                "sender_key TEXT,category TEXT NOT NULL CHECK (category IN ("
                "'legacy','challenge','notice','challenge_rejected',"
                "'notice_rejected')),created_at INTEGER NOT NULL,"
                "CHECK ((category='legacy' AND sender_key IS NULL) OR "
                "(category!='legacy' AND sender_key IS NOT NULL)))"
            )
            if table is not None:
                self._connection.execute(
                    "INSERT INTO outbound_events(sender_key,category,created_at) "
                    "SELECT NULL,'legacy',created_at FROM outbound_events_v4"
                )
                self._connection.execute("DROP TABLE outbound_events_v4")
            self._connection.execute(
                "CREATE INDEX outbound_events_time_idx "
                "ON outbound_events(created_at)"
            )
            self._connection.execute(
                "CREATE INDEX outbound_events_sender_category_time_idx "
                "ON outbound_events(sender_key,category,created_at)"
            )
            self._connection.execute("PRAGMA user_version=5")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    def _migrate_v5_to_v6(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            sender_columns = {
                str(row["name"])
                for row in self._connection.execute("PRAGMA table_info(sender_state)")
            }
            if "challenge_profile" not in sender_columns:
                self._connection.execute(
                    "ALTER TABLE sender_state ADD COLUMN challenge_profile TEXT "
                    "CHECK (challenge_profile IN ('standard','strict'))"
                )
            self._connection.execute(
                "UPDATE sender_state SET challenge_profile='standard' "
                "WHERE status IN ('challenge_issuing','challenge_archiving','challenged') "
                "AND challenge_profile IS NULL"
            )
            review_columns = {
                str(row["name"])
                for row in self._connection.execute("PRAGMA table_info(review_queue)")
            }
            if "rule_codes" in review_columns and "signals" not in review_columns:
                self._connection.execute(
                    "ALTER TABLE review_queue RENAME COLUMN rule_codes TO signals"
                )
            decision_columns = {
                str(row["name"])
                for row in self._connection.execute("PRAGMA table_info(decision_events)")
            }
            if "severity" in decision_columns and "assessment" not in decision_columns:
                self._connection.execute(
                    "ALTER TABLE decision_events RENAME COLUMN severity TO assessment"
                )
            if "score" in decision_columns and "risk_score" not in decision_columns:
                self._connection.execute(
                    "ALTER TABLE decision_events RENAME COLUMN score TO risk_score"
                )
            decision_columns = {
                str(row["name"])
                for row in self._connection.execute("PRAGMA table_info(decision_events)")
            }
            if decision_columns and "decision_basis" not in decision_columns:
                self._connection.execute(
                    "ALTER TABLE decision_events ADD COLUMN decision_basis TEXT "
                    "NOT NULL DEFAULT 'legacy_rules_v2'"
                )
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS campaign_events ("
                "fingerprint TEXT NOT NULL,sender_key TEXT NOT NULL,"
                "observed_at INTEGER NOT NULL,PRIMARY KEY (fingerprint,sender_key))"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS campaign_events_fingerprint_time_idx "
                "ON campaign_events(fingerprint,observed_at)"
            )
            self._connection.execute("PRAGMA user_version=6")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    def _migrate_v6_to_v7(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS operator_artifacts ("
                "message_id INTEGER PRIMARY KEY,delete_at INTEGER NOT NULL,"
                "retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count>=0))"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS operator_artifacts_delete_at_idx "
                "ON operator_artifacts(delete_at)"
            )
            self._connection.execute("PRAGMA user_version=7")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    def _migrate_v1_to_v2(self) -> None:
        active = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM sender_state WHERE status IN "
                "('challenge_issuing','challenge_archiving','challenged')"
            ).fetchone()[0]
        )
        if active:
            raise StoreMigrationError("cannot migrate while active challenges exist")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "ALTER TABLE sender_state RENAME TO sender_state_v1"
            )
            self._connection.execute(SENDER_STATE_SCHEMA)
            self._connection.execute(
                "INSERT INTO sender_state(sender_key,status,challenge_id,answer_digest,"
                "challenge_expires_at,challenge_message_id,challenge_prompt,"
                "challenge_action_reference,guidance_sent,attempts,updated_at) "
                "SELECT sender_key,status,challenge_id,answer_digest,challenge_expires_at,"
                "challenge_message_id,challenge_prompt,challenge_action_reference,"
                "guidance_sent,attempts,updated_at FROM sender_state_v1"
            )
            self._connection.execute("DROP TABLE sender_state_v1")
            self._connection.execute(
                "UPDATE settings SET value=CASE value "
                "WHEN 'observe' THEN 'monitor' WHEN 'enforce' THEN 'protect' "
                "ELSE value END WHERE key='mode'"
            )
            self._connection.execute("PRAGMA user_version=4")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    def _migrate_v2_to_v3(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "CREATE TABLE enforcement_reviews ("
                "sender_key TEXT PRIMARY KEY,reference BLOB,envelope BLOB NOT NULL,"
                "reason TEXT NOT NULL,created_at INTEGER NOT NULL,"
                "updated_at INTEGER NOT NULL,expires_at INTEGER NOT NULL)"
            )
            self._connection.execute(
                "CREATE INDEX enforcement_reviews_expiry_idx "
                "ON enforcement_reviews(expires_at)"
            )
            self._connection.execute("PRAGMA user_version=3")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

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
                "unknown",
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
        status: str,
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

    def allow(self, sender_key: str, now: int | None = None) -> None:
        self._set_state(sender_key, "allowed", now=now)
        self.resolve_sender_actions(sender_key, now)
        self.delete_enforcement_review(sender_key)

    def revoke(self, sender_key: str, now: int | None = None) -> None:
        self._set_state(sender_key, "unknown", now=now)
        self.resolve_sender_actions(sender_key, now)

    def resolve_sender_actions(self, sender_key: str, now: int | None = None) -> int:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE pending_actions SET status='cancelled',finished_at=? "
                "WHERE sender_key=? AND status IN ('pending','failed')",
                (timestamp, sender_key),
            )
        return cursor.rowcount

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
                "suppression_reason=NULL, suppressed_until=NULL, revision=revision+1, "
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
            "quarantined",
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
                "suppressed_until=excluded.suppressed_until,revision=sender_state.revision+1,"
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
            cursor = self._connection.execute(
                "UPDATE sender_state SET status='unknown',suppression_reason=NULL,"
                "suppressed_until=NULL,challenge_action_reference=NULL,"
                "restriction_reference=NULL,revision=revision+1,"
                "updated_at=? WHERE sender_key=? AND status='suppressed' "
                "AND suppressed_until IS NOT NULL AND suppressed_until<=?",
                (timestamp, sender_key, timestamp),
            )
        if cursor.rowcount == 1:
            self.delete_enforcement_review(sender_key)
            return True
        return False

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
        self._set_state(sender_key, "provisional", now=now)
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
        limit: int | None = None,
        offset: int = 0,
        now: int | None = None,
    ) -> list[ActiveRestriction]:
        if offset < 0 or (limit is not None and limit < 1):
            raise ValueError("invalid active restriction page bounds")
        timestamp = int(time.time()) if now is None else now
        query = (
            self._active_restriction_select()
            + " WHERE sender.status IN ('quarantined','suppressed') "
            "ORDER BY sender.updated_at DESC, sender.sender_key ASC"
        )
        parameters: tuple[int, ...] = (timestamp,)
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            parameters = (timestamp, limit, offset)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [ActiveRestriction(**dict(row)) for row in rows]

    def active_restriction_count(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) FROM sender_state "
                "WHERE status IN ('quarantined','suppressed')"
            ).fetchone()
        return int(row[0])

    @staticmethod
    def _active_restriction_select() -> str:
        return (
            "SELECT sender.sender_key,sender.restriction_reference AS reference,"
            "sender.status,COALESCE(sender.suppression_reason,review.reason,"
            "CASE WHEN EXISTS (SELECT 1 FROM review_queue AS verdict "
            "WHERE verdict.sender_key=sender.sender_key AND verdict.status='spam') "
            "THEN 'manual_spam' ELSE 'reason_unavailable' END) AS reason,"
            "sender.suppressed_until,sender.updated_at,review.envelope,"
            "review.created_at AS evidence_created_at,"
            "review.expires_at AS evidence_expires_at FROM sender_state AS sender "
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

    def delete_enforcement_review(self, sender_key: str) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM enforcement_reviews WHERE sender_key=?", (sender_key,)
            )
        return cursor.rowcount == 1

    def enforcement_statistics(self, *, now: int | None = None) -> dict[str, int]:
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            rows = self._connection.execute(
                "SELECT status,COUNT(*) AS count FROM sender_state "
                "WHERE status IN ('quarantined','suppressed') GROUP BY status"
            ).fetchall()
            reasons = self._connection.execute(
                "SELECT COALESCE(sender.suppression_reason,review.reason,"
                "CASE WHEN EXISTS (SELECT 1 FROM review_queue AS verdict "
                "WHERE verdict.sender_key=sender.sender_key AND verdict.status='spam') "
                "THEN 'manual_spam' ELSE 'reason_unavailable' END) "
                "AS reason,COUNT(*) AS count FROM sender_state AS sender "
                "LEFT JOIN enforcement_reviews AS review "
                "ON review.sender_key=sender.sender_key AND review.expires_at>? "
                "WHERE sender.status IN ('quarantined','suppressed') GROUP BY reason"
                ,
                (timestamp,),
            ).fetchall()
            reviewable = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM enforcement_reviews AS review "
                    "JOIN sender_state AS sender ON sender.sender_key=review.sender_key "
                    "WHERE review.expires_at>? "
                    "AND sender.status IN ('quarantined','suppressed')",
                    (timestamp,),
                ).fetchone()[0]
            )
            identifiable = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM sender_state WHERE status IN "
                    "('quarantined','suppressed') AND restriction_reference IS NOT NULL"
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

    def audit(
        self, sender_key: str, rule_code: str, outcome: str, now: int | None = None
    ) -> None:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO audit(sender_key, rule_code, outcome, created_at) VALUES (?, ?, ?, ?)",
                (sender_key, rule_code, outcome, timestamp),
            )

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
        return int(cursor.lastrowid)

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

    def pending_actions(self) -> list[PendingAction]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT id,sender_key,action,reason,reference,execute_at,"
                "expected_revision,mode_independent,status,created_at,finished_at "
                "FROM pending_actions "
                "WHERE status='pending' ORDER BY execute_at"
            ).fetchall()
        return [PendingAction(**dict(row)) for row in rows]

    def claim_action(self, action_id: int) -> PendingAction | None:
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
            if state.status not in {
                "suppressed",
                "quarantined",
            } or state.revision != int(row["expected_revision"]):
                return None
        return PendingAction(**dict(row))

    def finish_action(
        self, action_id: int, status: str, now: int | None = None
    ) -> bool:
        if status not in {"completed", "failed", "cancelled"}:
            raise ValueError("invalid action status")
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            if status == "completed":
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
        return int(cursor.lastrowid)

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
        self, review_id: int, status: str, now: int | None = None
    ) -> bool:
        if status not in {"legitimate", "spam", "dismissed"}:
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
        self, sender_key: str, status: str, now: int | None = None
    ) -> int:
        if status not in {"legitimate", "spam", "dismissed"}:
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
        window_seconds: int = 24 * 3600,
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

    def is_automated_message(self, sender_key: str, message_id: int) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM automated_messages WHERE sender_key=? AND message_id=?",
                (sender_key, message_id),
            ).fetchone()
        return row is not None

    def prune(self, retention_days: int, now: int | None = None) -> None:
        timestamp = now or int(time.time())
        cutoff = timestamp - retention_days * 86400
        with self._lock, self._connection:
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
                (timestamp - 24 * 3600,),
            )
            self._connection.execute(
                "DELETE FROM automated_messages WHERE created_at < ?", (cutoff,)
            )
            self._connection.execute(
                "DELETE FROM decision_events WHERE created_at < ?", (cutoff,)
            )
            self._connection.execute(
                "DELETE FROM pending_actions WHERE status!='pending' AND finished_at < ?",
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
                    "WHERE created_at>=? AND policy_version='adaptive-v1' "
                    "GROUP BY assessment",
                    (timestamp - 7 * 86400,),
                )
            }
            repeated_campaigns = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM decision_events WHERE created_at>=? "
                    "AND policy_version='adaptive-v1' "
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
        return result
