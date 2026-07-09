# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


EVIDENCE_SCHEMA_VERSION = 1
REVIEW_OUTCOMES = {"correct", "false_positive", "insufficient"}
LEGACY_REVIEW_OUTCOME_MAP = {
    "spam": "correct",
    "legitimate": "false_positive",
    "uncertain": "insufficient",
}
WEAK_LABELS = {"spam_candidate", "legitimate_candidate", "uncertain"}
COLLECTION_OUTCOMES = {
    "collected_content",
    "collected_structural",
    "skipped_no_signal",
    "skipped_duplicate",
    "skipped_sender_cap",
}
CollectionStatus = Literal["collected", "duplicate", "sender_cap"]


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    id: int
    sender_token: str
    payload: dict[str, object]
    automatic_hint: str
    review_outcome: str | None
    created_at: int
    expires_at: int

    @property
    def weak_label(self) -> str:
        return self.automatic_hint

    @property
    def manual_label(self) -> str | None:
        return self.review_outcome


@dataclass(frozen=True, slots=True)
class CollectionResult:
    status: CollectionStatus
    record_id: int | None = None

    @property
    def sample_id(self) -> int | None:
        return self.record_id


class EvidenceProtector:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("evidence key must contain at least 32 bytes")
        self._encryption_key = self._derive(key, b"evidence-content")
        self._enforcement_key = self._derive(key, b"enforcement-review-content")
        self._sender_key = self._derive(key, b"evidence-sender")
        self._message_key = self._derive(key, b"evidence-message")

    @staticmethod
    def _derive(key: bytes, info: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
            key
        )

    def sender_token(self, sender_id: int) -> str:
        return hmac.new(
            self._sender_key, str(sender_id).encode("ascii"), hashlib.sha256
        ).hexdigest()

    def message_token(self, sender_id: int, message_id: int) -> str:
        value = f"{sender_id}:{message_id}".encode("ascii")
        return hmac.new(self._message_key, value, hashlib.sha256).hexdigest()

    def seal(self, payload: dict[str, object]) -> bytes:
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ciphertext = AESGCM(self._encryption_key).encrypt(
            nonce, plaintext, b"tg-pm-gatekeeper:evidence:v1"
        )
        return b"\x01" + nonce + ciphertext

    def open(self, envelope: bytes) -> dict[str, object]:
        if len(envelope) < 30 or envelope[0] != 1:
            raise ValueError("invalid evidence envelope")
        try:
            plaintext = AESGCM(self._encryption_key).decrypt(
                envelope[1:13], envelope[13:], b"tg-pm-gatekeeper:evidence:v1"
            )
            value = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise ValueError("invalid evidence envelope") from exc
        if not isinstance(value, dict):
            raise ValueError("invalid evidence payload")
        return value

    def seal_enforcement(self, payload: dict[str, object]) -> bytes:
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ciphertext = AESGCM(self._enforcement_key).encrypt(
            nonce, plaintext, b"tg-pm-gatekeeper:enforcement-review:v1"
        )
        return b"\x01" + nonce + ciphertext

    def open_enforcement(self, envelope: bytes) -> dict[str, object]:
        if len(envelope) < 30 or envelope[0] != 1:
            raise ValueError("invalid enforcement review envelope")
        try:
            plaintext = AESGCM(self._enforcement_key).decrypt(
                envelope[1:13],
                envelope[13:],
                b"tg-pm-gatekeeper:enforcement-review:v1",
            )
            value = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise ValueError("invalid enforcement review envelope") from exc
        if not isinstance(value, dict):
            raise ValueError("invalid enforcement review payload")
        return value


class EvidenceStore:
    def __init__(self, path: Path, protector: EvidenceProtector) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        self.protector = protector
        self._connection = sqlite3.connect(path, timeout=5)
        os.chmod(path, 0o600)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if self._has_legacy_dataset_schema(version):
            self._discard_legacy_dataset_schema()
            version = 0
        if version not in {0, EVIDENCE_SCHEMA_VERSION}:
            self._connection.close()
            raise ValueError(f"unsupported evidence schema version: {version}")
        with self._connection:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_token TEXT NOT NULL,
                    message_token TEXT NOT NULL UNIQUE,
                    envelope BLOB NOT NULL,
                    automatic_hint TEXT NOT NULL,
                    review_outcome TEXT,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS evidence_records_expiry_idx
                    ON evidence_records(expires_at);
                CREATE INDEX IF NOT EXISTS evidence_records_sender_idx
                    ON evidence_records(sender_token);
                CREATE TABLE IF NOT EXISTS collection_stats (
                    day_start INTEGER NOT NULL,
                    outcome TEXT NOT NULL,
                    count INTEGER NOT NULL,
                    PRIMARY KEY(day_start, outcome)
                );
                """
            )
            self._connection.execute(f"PRAGMA user_version={EVIDENCE_SCHEMA_VERSION}")

    def _has_legacy_dataset_schema(self, version: int) -> bool:
        if version not in {1, 2}:
            return False
        row = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='samples'"
        ).fetchone()
        evidence = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_records'"
        ).fetchone()
        return row is not None and evidence is None

    def _discard_legacy_dataset_schema(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                DROP TABLE IF EXISTS samples;
                DROP TABLE IF EXISTS collection_stats;
                PRAGMA user_version=0;
                """
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def collect(
        self,
        *,
        sender_id: int,
        message_id: int,
        payload: dict[str, object],
        automatic_hint: str | None = None,
        retention_days: int = 30,
        max_per_sender: int = 3,
        sample_kind: Literal["content", "structural"] = "content",
        now: int | None = None,
        weak_label: str | None = None,
    ) -> CollectionResult:
        if automatic_hint is None:
            automatic_hint = weak_label
        if automatic_hint is None:
            raise ValueError("missing automatic hint")
        if automatic_hint not in WEAK_LABELS:
            raise ValueError("invalid automatic hint")
        if sample_kind not in {"content", "structural"}:
            raise ValueError("invalid sample kind")
        timestamp = int(time.time()) if now is None else now
        sender_token = self.protector.sender_token(sender_id)
        message_token = self.protector.message_token(sender_id, message_id)
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM evidence_records WHERE expires_at<=?", (timestamp,)
            )
            if self._connection.execute(
                "SELECT 1 FROM evidence_records WHERE message_token=?", (message_token,)
            ).fetchone():
                self._increment_collection_stat_locked("skipped_duplicate", timestamp)
                return CollectionResult("duplicate")
            count = self._connection.execute(
                "SELECT COUNT(*) FROM evidence_records WHERE sender_token=? AND expires_at>?",
                (sender_token, timestamp),
            ).fetchone()[0]
            if int(count) >= max_per_sender:
                self._increment_collection_stat_locked("skipped_sender_cap", timestamp)
                return CollectionResult("sender_cap")
            cursor = self._connection.execute(
                "INSERT INTO evidence_records(sender_token,message_token,envelope,automatic_hint,"
                "created_at,expires_at) VALUES (?,?,?,?,?,?)",
                (
                    sender_token,
                    message_token,
                    self.protector.seal(payload),
                    automatic_hint,
                    timestamp,
                    timestamp + retention_days * 86400,
                ),
            )
            self._increment_collection_stat_locked(
                f"collected_{sample_kind}", timestamp
            )
            return CollectionResult("collected", int(cursor.lastrowid))

    def record_no_signal(self, now: int | None = None) -> None:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            self._increment_collection_stat_locked("skipped_no_signal", timestamp)

    def _increment_collection_stat_locked(self, outcome: str, timestamp: int) -> None:
        if outcome not in COLLECTION_OUTCOMES:
            raise ValueError("invalid collection outcome")
        day_start = timestamp - timestamp % 86400
        self._connection.execute(
            "INSERT INTO collection_stats(day_start,outcome,count) VALUES (?,?,1) "
            "ON CONFLICT(day_start,outcome) DO UPDATE SET count=count+1",
            (day_start, outcome),
        )

    def records(self, *, limit: int = 100, offset: int = 0) -> list[EvidenceRecord]:
        now = int(time.time())
        with self._lock:
            rows = self._connection.execute(
                "SELECT id,sender_token,envelope,automatic_hint,review_outcome,created_at,"
                "expires_at FROM evidence_records WHERE expires_at>? ORDER BY created_at DESC "
                "LIMIT ? OFFSET ?",
                (now, limit, offset),
            ).fetchall()
        return [self._record(row) for row in rows]

    def samples(self, *, limit: int = 100, offset: int = 0) -> list[EvidenceRecord]:
        return self.records(limit=limit, offset=offset)

    def summaries(self, *, limit: int = 100, offset: int = 0) -> list[EvidenceRecord]:
        now = int(time.time())
        with self._lock:
            rows = self._connection.execute(
                "SELECT id,sender_token,automatic_hint,review_outcome,created_at,expires_at "
                "FROM evidence_records WHERE expires_at>? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (now, limit, offset),
            ).fetchall()
        return [
            EvidenceRecord(
                id=int(row["id"]),
                sender_token=str(row["sender_token"]),
                payload={},
                automatic_hint=str(row["automatic_hint"]),
                review_outcome=(
                    str(row["review_outcome"]) if row["review_outcome"] else None
                ),
                created_at=int(row["created_at"]),
                expires_at=int(row["expires_at"]),
            )
            for row in rows
        ]

    def record(self, record_id: int) -> EvidenceRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT id,sender_token,envelope,automatic_hint,review_outcome,created_at,"
                "expires_at FROM evidence_records WHERE id=? AND expires_at>?",
                (record_id, int(time.time())),
            ).fetchone()
        return self._record(row) if row else None

    def sample(self, sample_id: int) -> EvidenceRecord | None:
        return self.record(sample_id)

    def _record(self, row: sqlite3.Row) -> EvidenceRecord:
        return EvidenceRecord(
            id=int(row["id"]),
            sender_token=str(row["sender_token"]),
            payload=self.protector.open(bytes(row["envelope"])),
            automatic_hint=str(row["automatic_hint"]),
            review_outcome=(
                str(row["review_outcome"]) if row["review_outcome"] else None
            ),
            created_at=int(row["created_at"]),
            expires_at=int(row["expires_at"]),
        )

    def review(self, record_id: int, outcome: str) -> bool:
        outcome = LEGACY_REVIEW_OUTCOME_MAP.get(outcome, outcome)
        if outcome not in REVIEW_OUTCOMES:
            raise ValueError("invalid review outcome")
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE evidence_records SET review_outcome=? WHERE id=? AND expires_at>?",
                (outcome, record_id, int(time.time())),
            )
        return cursor.rowcount == 1

    def label(self, sample_id: int, label: str) -> bool:
        return self.review(sample_id, label)

    def update_record_action(
        self, record_id: int, *, automatic_hint: str, actual_action: str
    ) -> bool:
        if automatic_hint not in WEAK_LABELS:
            raise ValueError("invalid automatic hint")
        now = int(time.time())
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT envelope FROM evidence_records WHERE id=? AND expires_at>?",
                (record_id, now),
            ).fetchone()
            if row is None:
                return False
            payload = self.protector.open(bytes(row["envelope"]))
            payload["actual_action"] = actual_action
            self._connection.execute(
                "UPDATE evidence_records SET envelope=?,automatic_hint=? WHERE id=?",
                (self.protector.seal(payload), automatic_hint, record_id),
            )
        return True

    def update_sample_outcome(
        self, sample_id: int, *, weak_label: str, actual_action: str
    ) -> bool:
        return self.update_record_action(
            sample_id, automatic_hint=weak_label, actual_action=actual_action
        )

    def finalize_challenged_record(
        self, sender_id: int, *, automatic_hint: str, actual_action: str
    ) -> bool:
        if automatic_hint not in WEAK_LABELS:
            raise ValueError("invalid automatic hint")
        token = self.protector.sender_token(sender_id)
        now = int(time.time())
        with self._lock, self._connection:
            rows = self._connection.execute(
                "SELECT id,envelope FROM evidence_records WHERE sender_token=? AND expires_at>? "
                "ORDER BY created_at DESC,id DESC",
                (token, now),
            ).fetchall()
            for row in rows:
                payload = self.protector.open(bytes(row["envelope"]))
                if payload.get("actual_action") != "challenged":
                    continue
                payload["actual_action"] = actual_action
                self._connection.execute(
                    "UPDATE evidence_records SET envelope=?,automatic_hint=? WHERE id=?",
                    (self.protector.seal(payload), automatic_hint, row["id"]),
                )
                return True
        return False

    def finalize_challenged_sample(
        self, sender_id: int, *, weak_label: str, actual_action: str
    ) -> bool:
        return self.finalize_challenged_record(
            sender_id, automatic_hint=weak_label, actual_action=actual_action
        )

    def delete(self, record_id: int) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM evidence_records WHERE id=?", (record_id,)
            )
        return cursor.rowcount == 1

    def purge(self) -> int:
        with self._lock, self._connection:
            cursor = self._connection.execute("DELETE FROM evidence_records")
        return cursor.rowcount

    def prune(self, now: int | None = None, *, retention_days: int = 30) -> int:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM evidence_records WHERE expires_at<=?", (timestamp,)
            )
            cutoff_day = self._collection_cutoff_day(timestamp, retention_days)
            self._connection.execute(
                "DELETE FROM collection_stats WHERE day_start<?", (cutoff_day,)
            )
        return cursor.rowcount

    @staticmethod
    def _collection_cutoff_day(timestamp: int, retention_days: int) -> int:
        today = timestamp - timestamp % 86400
        return today - (retention_days - 1) * 86400

    def statistics(
        self, *, retention_days: int = 30, now: int | None = None
    ) -> dict[str, int]:
        timestamp = int(time.time()) if now is None else now
        with self._lock:
            rows = self._connection.execute(
                "SELECT COALESCE(review_outcome,'unreviewed') AS label, COUNT(*) AS count "
                "FROM evidence_records WHERE expires_at>? GROUP BY label",
                (timestamp,),
            ).fetchall()
            weak = self._connection.execute(
                "SELECT automatic_hint,COUNT(*) AS count FROM evidence_records WHERE expires_at>? "
                "GROUP BY automatic_hint",
                (timestamp,),
            ).fetchall()
            expiring = self._connection.execute(
                "SELECT COUNT(*) FROM evidence_records WHERE expires_at>? AND expires_at<=?",
                (timestamp, timestamp + 86400),
            ).fetchone()[0]
            collection = self._connection.execute(
                "SELECT outcome,SUM(count) AS count FROM collection_stats "
                "WHERE day_start>=? GROUP BY outcome",
                (self._collection_cutoff_day(timestamp, retention_days),),
            ).fetchall()
        result = {str(row["label"]): int(row["count"]) for row in rows}
        result.update(
            {f"hint_{row['automatic_hint']}": int(row["count"]) for row in weak}
        )
        result.setdefault("unreviewed", 0)
        for outcome in REVIEW_OUTCOMES:
            result.setdefault(outcome, 0)
        result["total"] = sum(int(row["count"]) for row in rows)
        result["expiring_24h"] = int(expiring)
        result.update(
            {f"collection_{row['outcome']}": int(row["count"]) for row in collection}
        )
        for outcome in COLLECTION_OUTCOMES:
            result.setdefault(f"collection_{outcome}", 0)
        return result
