from __future__ import annotations

import hashlib
import hmac


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

    @staticmethod
    def matches(expected: str, actual: str) -> bool:
        return hmac.compare_digest(expected, actual)
