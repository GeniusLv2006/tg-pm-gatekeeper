# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import hashlib
import hmac
import json
import secrets

import pyaes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class IdentifierProtector:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("HMAC key must contain at least 32 bytes")
        self._key = key

    def _digest(self, purpose: str, value: str) -> str:
        payload = f"v1:{purpose}:{value}".encode("utf-8")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def sender_key(self, telegram_user_id: int) -> str:
        return self._digest("sender", str(telegram_user_id))

    def answer_digest(self, sender_key: str, challenge_id: str, answer: str) -> str:
        return self._digest("answer", f"{sender_key}:{challenge_id}:{answer}")

    def seal_review_reference(
        self, telegram_user_id: int, access_hash: int, message_id: int
    ) -> bytes:
        plaintext = json.dumps(
            [telegram_user_id, access_hash, message_id], separators=(",", ":")
        ).encode("ascii")
        nonce = secrets.token_bytes(16)
        encryption_key = hmac.new(
            self._key, b"v1:review:encryption", hashlib.sha256
        ).digest()
        authentication_key = hmac.new(
            self._key, b"v1:review:authentication", hashlib.sha256
        ).digest()
        counter = pyaes.Counter(int.from_bytes(nonce, "big"))
        ciphertext = pyaes.AESModeOfOperationCTR(
            encryption_key, counter=counter
        ).encrypt(plaintext)
        envelope = b"\x01" + nonce + ciphertext
        tag = hmac.new(authentication_key, envelope, hashlib.sha256).digest()
        return envelope + tag

    def open_review_reference(self, envelope: bytes) -> tuple[int, int, int]:
        if len(envelope) < 50 or envelope[0] != 1:
            raise ValueError("invalid review reference")
        payload, supplied_tag = envelope[:-32], envelope[-32:]
        authentication_key = hmac.new(
            self._key, b"v1:review:authentication", hashlib.sha256
        ).digest()
        expected_tag = hmac.new(authentication_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise ValueError("invalid review reference")
        nonce, ciphertext = payload[1:17], payload[17:]
        encryption_key = hmac.new(
            self._key, b"v1:review:encryption", hashlib.sha256
        ).digest()
        counter = pyaes.Counter(int.from_bytes(nonce, "big"))
        plaintext = pyaes.AESModeOfOperationCTR(
            encryption_key, counter=counter
        ).decrypt(ciphertext)
        try:
            values = json.loads(plaintext.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid review reference") from exc
        if (
            not isinstance(values, list)
            or len(values) != 3
            or not all(isinstance(value, int) for value in values)
        ):
            raise ValueError("invalid review reference")
        return values[0], values[1], values[2]

    @staticmethod
    def matches(expected: str, actual: str) -> bool:
        return hmac.compare_digest(expected, actual)


class ActiveCaseProtector:
    """Encrypt Active Case content with a dedicated key and domain."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("review key must contain at least 32 bytes")
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"active-case-content:v1",
        ).derive(key)

    def seal(self, payload: dict[str, object]) -> bytes:
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ciphertext = AESGCM(self._key).encrypt(
            nonce, plaintext, b"tg-pm-gatekeeper:active-case:v1"
        )
        return b"\x01" + nonce + ciphertext

    def open(self, envelope: bytes) -> dict[str, object]:
        if len(envelope) < 30 or envelope[0] != 1:
            raise ValueError("invalid active case envelope")
        try:
            plaintext = AESGCM(self._key).decrypt(
                envelope[1:13],
                envelope[13:],
                b"tg-pm-gatekeeper:active-case:v1",
            )
            value = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise ValueError("invalid active case envelope") from exc
        if not isinstance(value, dict):
            raise ValueError("invalid active case envelope")
        return value
