# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Schema definition, shared SQL fragments, and in-place migrations."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable

from ..states import SenderStatus

LOG = logging.getLogger("gatekeeper.store")

SCHEMA_VERSION = 9

# Re-seals one version 1 encrypted reference, or returns None when it cannot be
# authenticated. Supplied by callers holding the HMAC key; the store never does.
LegacyReferenceResealer = Callable[[bytes], "bytes | None"]

# Every column holding an encrypted Telegram reference, with whether it is
# nullable. Schema version 9 requires each to hold only version 2 envelopes.
ENCRYPTED_REFERENCE_COLUMNS = (
    ("review_queue", "reference", True),
    ("pending_actions", "reference", False),
    ("enforcement_reviews", "reference", True),
    ("sender_state", "challenge_action_reference", True),
    ("sender_state", "restriction_reference", True),
)

CAMPAIGN_WINDOW_SECONDS = 7 * 24 * 3600

SENDER_STATUSES = tuple(SenderStatus)

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
    archived_at INTEGER,
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
CREATE INDEX IF NOT EXISTS sender_state_archive_idx
    ON sender_state(status, archived_at, updated_at);
"""

# Every table holding sender_key rows. Forgetting a sender erases each one, so a new
# sender-linked table must be added here; sender_state stays last.
SENDER_LINKED_TABLES = (
    "processed_messages",
    "audit",
    "link_events",
    "outbound_events",
    "automated_messages",
    "dialog_snapshots",
    "review_queue",
    "pending_actions",
    "decision_events",
    "campaign_events",
    "enforcement_reviews",
    "sender_state",
)

# Restriction data that no longer applies once a temporary suppression expires.
RELEASED_RESTRICTION_TABLES = ("enforcement_reviews", "review_queue", "dialog_snapshots")

ARCHIVED_PERMANENT_SQL = (
    "status='suppressed' AND suppressed_until IS NULL AND archived_at IS NOT NULL"
)

OPEN_ACTION_SQL = (
    "EXISTS (SELECT 1 FROM pending_actions "
    "WHERE pending_actions.sender_key=sender_state.sender_key "
    "AND pending_actions.status IN ('pending','failed'))"
)


class StoreMigrationError(RuntimeError):
    """Raised when an existing state database cannot be migrated safely."""


def initialize_schema(
    connection: sqlite3.Connection,
    reseal_legacy_reference: LegacyReferenceResealer | None = None,
) -> None:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    sender_table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sender_state'"
    ).fetchone()
    if sender_table is None:
        connection.executescript(SENDER_STATE_SCHEMA + SCHEMA)
        connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        return
    if version == 6:
        _migrate_v6_to_v7(connection)
        version = 7
    if version == 7:
        _migrate_v7_to_v8(connection)
        version = 8
    if version == 8:
        _migrate_v8_to_v9(connection, reseal_legacy_reference)
        version = 9
    if version != SCHEMA_VERSION:
        raise StoreMigrationError(f"unsupported database schema version: {version}")
    connection.executescript(SCHEMA)


def _migrate_v8_to_v9(
    connection: sqlite3.Connection,
    reseal_legacy_reference: LegacyReferenceResealer | None,
) -> None:
    """Re-seal every version 1 reference as an AES-GCM version 2 envelope.

    A reference no key purpose authenticates is unusable either way, so it is
    erased rather than kept: NULL in nullable columns, empty in pending_actions,
    matching how a finished action already clears its reference.
    """
    connection.execute("BEGIN IMMEDIATE")
    try:
        # Another process may have finished the migration while this one waited.
        if int(connection.execute("PRAGMA user_version").fetchone()[0]) != 8:
            connection.execute("COMMIT")
            return
        resealed = discarded = 0
        for table, column, nullable in ENCRYPTED_REFERENCE_COLUMNS:
            rows = connection.execute(
                f"SELECT rowid, {column} FROM {table} "  # noqa: S608 -- constant names
                f"WHERE substr({column}, 1, 1) = x'01'"
            ).fetchall()
            if not rows:
                continue
            if reseal_legacy_reference is None:
                raise StoreMigrationError(
                    "schema version 8 holds encrypted references; "
                    "migrating them requires the HMAC key"
                )
            for rowid, envelope in rows:
                replacement = reseal_legacy_reference(bytes(envelope))
                if replacement is None:
                    discarded += 1
                    replacement_value: bytes | None = None if nullable else b""
                else:
                    resealed += 1
                    replacement_value = replacement
                connection.execute(
                    f"UPDATE {table} SET {column}=? WHERE rowid=?",  # noqa: S608 -- constant names
                    (replacement_value, rowid),
                )
        connection.execute("PRAGMA user_version=9")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    else:
        connection.execute("COMMIT")
    LOG.info(
        "reference_migration_completed resealed=%d discarded=%d", resealed, discarded
    )


def _migrate_v7_to_v8(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(sender_state)")
        }
        if "archived_at" not in columns:
            connection.execute(
                "ALTER TABLE sender_state ADD COLUMN archived_at INTEGER"
            )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS sender_state_archive_idx "
            "ON sender_state(status, archived_at, updated_at)"
        )
        connection.execute("PRAGMA user_version=8")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    else:
        connection.execute("COMMIT")


def _migrate_v6_to_v7(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS operator_artifacts ("
            "message_id INTEGER PRIMARY KEY,delete_at INTEGER NOT NULL,"
            "retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count>=0))"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS operator_artifacts_delete_at_idx "
            "ON operator_artifacts(delete_at)"
        )
        connection.execute("PRAGMA user_version=7")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    else:
        connection.execute("COMMIT")
