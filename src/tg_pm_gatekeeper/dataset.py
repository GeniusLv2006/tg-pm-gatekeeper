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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


DATASET_SCHEMA_VERSION = 1
MANUAL_LABELS = {"spam", "legitimate", "uncertain"}
WEAK_LABELS = {"spam_candidate", "legitimate_candidate", "uncertain"}


@dataclass(frozen=True, slots=True)
class TrainingSample:
    id: int
    sender_token: str
    payload: dict[str, object]
    weak_label: str
    manual_label: str | None
    created_at: int
    expires_at: int


class DatasetProtector:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("dataset key must contain at least 32 bytes")
        self._encryption_key = self._derive(key, b"dataset-content")
        self._enforcement_key = self._derive(key, b"enforcement-review-content")
        self._sender_key = self._derive(key, b"dataset-sender")
        self._message_key = self._derive(key, b"dataset-message")

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
            nonce, plaintext, b"tg-pm-gatekeeper:dataset:v1"
        )
        return b"\x01" + nonce + ciphertext

    def open(self, envelope: bytes) -> dict[str, object]:
        if len(envelope) < 30 or envelope[0] != 1:
            raise ValueError("invalid dataset envelope")
        try:
            plaintext = AESGCM(self._encryption_key).decrypt(
                envelope[1:13], envelope[13:], b"tg-pm-gatekeeper:dataset:v1"
            )
            value = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise ValueError("invalid dataset envelope") from exc
        if not isinstance(value, dict):
            raise ValueError("invalid dataset payload")
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


class TrainingStore:
    def __init__(self, path: Path, protector: DatasetProtector) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        self.protector = protector
        self._connection = sqlite3.connect(path, timeout=5)
        os.chmod(path, 0o600)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, DATASET_SCHEMA_VERSION}:
            self._connection.close()
            raise ValueError(f"unsupported dataset schema version: {version}")
        with self._connection:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_token TEXT NOT NULL,
                    message_token TEXT NOT NULL UNIQUE,
                    envelope BLOB NOT NULL,
                    weak_label TEXT NOT NULL,
                    manual_label TEXT,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS samples_expiry_idx ON samples(expires_at);
                CREATE INDEX IF NOT EXISTS samples_sender_idx ON samples(sender_token);
                """
            )
            self._connection.execute(f"PRAGMA user_version={DATASET_SCHEMA_VERSION}")

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def collect(
        self,
        *,
        sender_id: int,
        message_id: int,
        payload: dict[str, object],
        weak_label: str,
        retention_days: int,
        max_per_sender: int,
        now: int | None = None,
    ) -> int | None:
        if weak_label not in WEAK_LABELS:
            raise ValueError("invalid weak label")
        timestamp = int(time.time()) if now is None else now
        sender_token = self.protector.sender_token(sender_id)
        message_token = self.protector.message_token(sender_id, message_id)
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM samples WHERE expires_at<=?", (timestamp,)
            )
            if self._connection.execute(
                "SELECT 1 FROM samples WHERE message_token=?", (message_token,)
            ).fetchone():
                return None
            count = self._connection.execute(
                "SELECT COUNT(*) FROM samples WHERE sender_token=? AND expires_at>?",
                (sender_token, timestamp),
            ).fetchone()[0]
            if int(count) >= max_per_sender:
                return None
            cursor = self._connection.execute(
                "INSERT INTO samples(sender_token,message_token,envelope,weak_label,"
                "created_at,expires_at) VALUES (?,?,?,?,?,?)",
                (
                    sender_token,
                    message_token,
                    self.protector.seal(payload),
                    weak_label,
                    timestamp,
                    timestamp + retention_days * 86400,
                ),
            )
            return int(cursor.lastrowid)

    def samples(self, *, limit: int = 100, offset: int = 0) -> list[TrainingSample]:
        now = int(time.time())
        with self._lock:
            rows = self._connection.execute(
                "SELECT id,sender_token,envelope,weak_label,manual_label,created_at,"
                "expires_at FROM samples WHERE expires_at>? ORDER BY created_at DESC "
                "LIMIT ? OFFSET ?",
                (now, limit, offset),
            ).fetchall()
        return [self._sample(row) for row in rows]

    def summaries(self, *, limit: int = 100, offset: int = 0) -> list[TrainingSample]:
        now = int(time.time())
        with self._lock:
            rows = self._connection.execute(
                "SELECT id,sender_token,weak_label,manual_label,created_at,expires_at "
                "FROM samples WHERE expires_at>? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (now, limit, offset),
            ).fetchall()
        return [
            TrainingSample(
                id=int(row["id"]),
                sender_token=str(row["sender_token"]),
                payload={},
                weak_label=str(row["weak_label"]),
                manual_label=(
                    str(row["manual_label"]) if row["manual_label"] else None
                ),
                created_at=int(row["created_at"]),
                expires_at=int(row["expires_at"]),
            )
            for row in rows
        ]

    def sample(self, sample_id: int) -> TrainingSample | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT id,sender_token,envelope,weak_label,manual_label,created_at,"
                "expires_at FROM samples WHERE id=? AND expires_at>?",
                (sample_id, int(time.time())),
            ).fetchone()
        return self._sample(row) if row else None

    def _sample(self, row: sqlite3.Row) -> TrainingSample:
        return TrainingSample(
            id=int(row["id"]),
            sender_token=str(row["sender_token"]),
            payload=self.protector.open(bytes(row["envelope"])),
            weak_label=str(row["weak_label"]),
            manual_label=(str(row["manual_label"]) if row["manual_label"] else None),
            created_at=int(row["created_at"]),
            expires_at=int(row["expires_at"]),
        )

    def label(self, sample_id: int, label: str) -> bool:
        if label not in MANUAL_LABELS:
            raise ValueError("invalid manual label")
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE samples SET manual_label=? WHERE id=? AND expires_at>?",
                (label, sample_id, int(time.time())),
            )
        return cursor.rowcount == 1

    def set_weak_label_for_sender(self, sender_id: int, label: str) -> int:
        if label not in WEAK_LABELS:
            raise ValueError("invalid weak label")
        token = self.protector.sender_token(sender_id)
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE samples SET weak_label=? WHERE sender_token=? AND expires_at>?",
                (label, token, int(time.time())),
            )
        return cursor.rowcount

    def update_sender_outcome(
        self, sender_id: int, *, weak_label: str, actual_action: str
    ) -> int:
        if weak_label not in WEAK_LABELS:
            raise ValueError("invalid weak label")
        token = self.protector.sender_token(sender_id)
        now = int(time.time())
        updated = 0
        with self._lock, self._connection:
            rows = self._connection.execute(
                "SELECT id,envelope FROM samples WHERE sender_token=? AND expires_at>?",
                (token, now),
            ).fetchall()
            for row in rows:
                payload = self.protector.open(bytes(row["envelope"]))
                payload["actual_action"] = actual_action
                self._connection.execute(
                    "UPDATE samples SET envelope=?,weak_label=? WHERE id=?",
                    (self.protector.seal(payload), weak_label, row["id"]),
                )
                updated += 1
        return updated

    def delete(self, sample_id: int) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM samples WHERE id=?", (sample_id,)
            )
        return cursor.rowcount == 1

    def purge(self) -> int:
        with self._lock, self._connection:
            cursor = self._connection.execute("DELETE FROM samples")
        return cursor.rowcount

    def prune(self, now: int | None = None) -> int:
        timestamp = int(time.time()) if now is None else now
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM samples WHERE expires_at<=?", (timestamp,)
            )
        return cursor.rowcount

    def statistics(self) -> dict[str, int]:
        now = int(time.time())
        with self._lock:
            rows = self._connection.execute(
                "SELECT COALESCE(manual_label,'unlabeled') AS label, COUNT(*) AS count "
                "FROM samples WHERE expires_at>? GROUP BY label",
                (now,),
            ).fetchall()
            weak = self._connection.execute(
                "SELECT weak_label,COUNT(*) AS count FROM samples WHERE expires_at>? "
                "GROUP BY weak_label",
                (now,),
            ).fetchall()
            expiring = self._connection.execute(
                "SELECT COUNT(*) FROM samples WHERE expires_at>? AND expires_at<=?",
                (now, now + 86400),
            ).fetchone()[0]
        result = {str(row["label"]): int(row["count"]) for row in rows}
        result.update({f"weak_{row['weak_label']}": int(row["count"]) for row in weak})
        result["total"] = sum(int(row["count"]) for row in rows)
        result["expiring_24h"] = int(expiring)
        result["exportable_gold"] = result.get("spam", 0) + result.get("legitimate", 0)
        return result

    def export(self, path: Path, *, include_weak: bool = False) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        count = 0
        groups: dict[str, str] = {}
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                for sample in reversed(self.samples(limit=1_000_000)):
                    label = sample.manual_label
                    label_source = "manual"
                    if label not in {"spam", "legitimate"}:
                        if not include_weak:
                            continue
                        label = sample.weak_label
                        label_source = "weak"
                    group = groups.setdefault(
                        sample.sender_token, f"sender-{len(groups) + 1:06d}"
                    )
                    row = {
                        **sample.payload,
                        "label": label,
                        "label_source": label_source,
                        "sender_group": group,
                    }
                    output.write(json.dumps(row, ensure_ascii=False) + "\n")
                    count += 1
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return count
