# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from __future__ import annotations

import hashlib
import hmac
import json
import secrets

import pyaes


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
