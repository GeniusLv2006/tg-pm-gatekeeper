from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sender_state (
    sender_key TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('unknown', 'challenged', 'allowed', 'quarantined')),
    challenge_id TEXT,
    answer_digest TEXT,
    challenge_expires_at INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
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
CREATE TABLE IF NOT EXISTS outbound_events (created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS outbound_events_time_idx ON outbound_events(created_at);
CREATE TABLE IF NOT EXISTS review_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_key TEXT NOT NULL,
    reference BLOB,
    classification TEXT NOT NULL,
    rule_codes TEXT NOT NULL,
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
"""


@dataclass(frozen=True, slots=True)
class SenderState:
    status: str
    challenge_id: str | None
    answer_digest: str | None
    challenge_expires_at: int | None
    attempts: int


@dataclass(frozen=True, slots=True)
class ReviewItem:
    id: int
    sender_key: str
    reference: bytes | None
    classification: str
    rule_codes: str
    features: str
    status: str
    message_count: int
    created_at: int
    updated_at: int
    expires_at: int
    reviewed_at: int | None


class StateStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._connection = sqlite3.connect(path, timeout=5)
        os.chmod(path, 0o600)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._connection:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.executescript(SCHEMA)
            self._connection.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES ('mode', 'observe')"
            )

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

    def healthy(self, *, max_age: int = 120, now: int | None = None) -> bool:
        timestamp = now or int(time.time())
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM settings WHERE key='heartbeat'"
            ).fetchone()
        return bool(row and timestamp - int(row["value"]) <= max_age)

    def get_mode(self) -> str:
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM settings WHERE key='mode'"
            ).fetchone()
        return row["value"] if row else "observe"

    def set_mode(self, mode: str) -> None:
        if mode not in {"observe", "enforce"}:
            raise ValueError("invalid mode")
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE settings SET value=? WHERE key='mode'", (mode,)
            )

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
                "SELECT status, challenge_id, answer_digest, challenge_expires_at, attempts "
                "FROM sender_state WHERE sender_key=?",
                (sender_key,),
            ).fetchone()
        if not row:
            return SenderState("unknown", None, None, None, 0)
        return SenderState(
            row["status"],
            row["challenge_id"],
            row["answer_digest"],
            row["challenge_expires_at"],
            row["attempts"],
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
        now: int | None = None,
    ) -> None:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO sender_state(sender_key, status, challenge_id, answer_digest, "
                "challenge_expires_at, attempts, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(sender_key) DO UPDATE SET status=excluded.status, "
                "challenge_id=excluded.challenge_id, answer_digest=excluded.answer_digest, "
                "challenge_expires_at=excluded.challenge_expires_at, attempts=excluded.attempts, "
                "updated_at=excluded.updated_at",
                (
                    sender_key,
                    status,
                    challenge_id,
                    answer_digest,
                    expires_at,
                    attempts,
                    timestamp,
                ),
            )

    def allow(self, sender_key: str, now: int | None = None) -> None:
        self._set_state(sender_key, "allowed", now=now)

    def revoke(self, sender_key: str, now: int | None = None) -> None:
        self._set_state(sender_key, "unknown", now=now)

    def quarantine(self, sender_key: str, now: int | None = None) -> None:
        self._set_state(sender_key, "quarantined", now=now)

    def set_challenge(
        self,
        sender_key: str,
        challenge_id: str,
        answer_digest: str,
        expires_at: int,
        now: int | None = None,
    ) -> None:
        self._set_state(
            sender_key,
            "challenged",
            challenge_id=challenge_id,
            answer_digest=answer_digest,
            expires_at=expires_at,
            now=now,
        )

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

    def enqueue_review(
        self,
        sender_key: str,
        reference: bytes,
        classification: str,
        rule_codes: str,
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
                        "rule_codes=?, features=?, message_count=message_count+1, "
                        "updated_at=?, expires_at=? WHERE id=?",
                        (
                            reference,
                            classification,
                            rule_codes,
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
                "rule_codes, features, created_at, updated_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sender_key,
                    reference,
                    classification,
                    rule_codes,
                    features,
                    timestamp,
                    timestamp,
                    expires_at,
                ),
            )
        return int(cursor.lastrowid)

    def review_items(self, *, limit: int = 100) -> list[ReviewItem]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, sender_key, reference, classification, rule_codes, "
                "features, status, message_count, created_at, updated_at, "
                "expires_at, reviewed_at "
                "FROM review_queue WHERE status='pending' "
                "ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [ReviewItem(**dict(row)) for row in rows]

    def review_item(self, review_id: int) -> ReviewItem | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT id, sender_key, reference, classification, rule_codes, "
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

    def claim_outbound_slot(self, limit: int, now: int | None = None) -> bool:
        timestamp = now or int(time.time())
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM outbound_events WHERE created_at < ?", (timestamp - 3600,)
            )
            count = self._connection.execute(
                "SELECT COUNT(*) FROM outbound_events"
            ).fetchone()[0]
            if count >= limit:
                return False
            self._connection.execute(
                "INSERT INTO outbound_events(created_at) VALUES (?)", (timestamp,)
            )
            return True

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
                "DELETE FROM review_queue WHERE "
                "(status='pending' AND expires_at <= ?) OR "
                "(status!='pending' AND reviewed_at < ?)",
                (timestamp, cutoff),
            )

    def statistics(self) -> dict[str, int | str | None]:
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
                    "SELECT COUNT(*) FROM review_queue WHERE status='pending'"
                ).fetchone()[0]
            )
        return {
            "mode": self.get_mode(),
            "allowed": states.get("allowed", 0),
            "challenged": states.get("challenged", 0),
            "quarantined": states.get("quarantined", 0),
            "audit_records": audit_count,
            "pending_reviews": pending_reviews,
            "heartbeat": int(heartbeat["value"]) if heartbeat else None,
        }
