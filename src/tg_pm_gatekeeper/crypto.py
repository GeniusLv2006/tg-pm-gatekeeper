# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import hashlib
import hmac
import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

REFERENCE_VERSION = 0x02
LEGACY_REFERENCE_VERSION = 0x01

# Each reference purpose seals a fixed number of integers under its own key.
_REFERENCE_PURPOSES = {"review": 3, "restriction": 2}
_GCM_NONCE_BYTES = 12
_GCM_TAG_BYTES = 16


def _parse_reference_values(
    plaintext: bytes, purpose: str, expected_values: int
) -> list[int]:
    try:
        values = json.loads(plaintext.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {purpose} reference") from exc
    if (
        not isinstance(values, list)
        or len(values) != expected_values
        or not all(isinstance(value, int) for value in values)
    ):
        raise ValueError(f"invalid {purpose} reference")
    return values


def _open_legacy_reference(
    key: bytes, envelope: bytes, purpose: str, expected_values: int
) -> list[int]:
    """Open a version 1 AES-256-CTR plus HMAC-SHA-256 reference.

    Only the schema migration that re-seals stored references calls this; live
    code reads and writes version 2 envelopes exclusively.
    """
    if len(envelope) < 50 or envelope[0] != LEGACY_REFERENCE_VERSION:
        raise ValueError(f"invalid {purpose} reference")
    payload, supplied_tag = envelope[:-32], envelope[-32:]
    authentication_key = hmac.new(
        key, f"v1:{purpose}:authentication".encode("ascii"), hashlib.sha256
    ).digest()
    expected_tag = hmac.new(authentication_key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise ValueError(f"invalid {purpose} reference")
    nonce, ciphertext = payload[1:17], payload[17:]
    encryption_key = hmac.new(
        key, f"v1:{purpose}:encryption".encode("ascii"), hashlib.sha256
    ).digest()
    # The version 1 counter block is the full 128-bit nonce, incremented
    # big-endian, which is exactly AES-CTR with the nonce as initial block.
    decryptor = Cipher(algorithms.AES(encryption_key), modes.CTR(nonce)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return _parse_reference_values(plaintext, purpose, expected_values)


class IdentifierProtector:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("HMAC key must contain at least 32 bytes")
        self._key = key
        self._reference_ciphers = {
            purpose: AESGCM(
                HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=f"tg-pm-gatekeeper:{purpose}-reference:v2".encode("ascii"),
                ).derive(key)
            )
            for purpose in _REFERENCE_PURPOSES
        }

    def _digest(self, purpose: str, value: str) -> str:
        payload = f"v1:{purpose}:{value}".encode("utf-8")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def sender_key(self, telegram_user_id: int) -> str:
        return self._digest("sender", str(telegram_user_id))

    def answer_digest(self, sender_key: str, challenge_id: str, answer: str) -> str:
        return self._digest("answer", f"{sender_key}:{challenge_id}:{answer}")

    def campaign_fingerprint(self, canonical_payload: str) -> str:
        return self._digest("campaign", canonical_payload)

    def seal_review_reference(
        self, telegram_user_id: int, access_hash: int, message_id: int
    ) -> bytes:
        return self._seal_reference(
            [telegram_user_id, access_hash, message_id], "review"
        )

    def seal_restriction_reference(
        self, telegram_user_id: int, access_hash: int
    ) -> bytes:
        return self._seal_reference([telegram_user_id, access_hash], "restriction")

    @staticmethod
    def _reference_aad(purpose: str) -> bytes:
        return f"tg-pm-gatekeeper:{purpose}-reference:v2".encode("ascii")

    def _seal_reference(self, values: list[int], purpose: str) -> bytes:
        plaintext = json.dumps(values, separators=(",", ":")).encode("ascii")
        nonce = secrets.token_bytes(_GCM_NONCE_BYTES)
        ciphertext = self._reference_ciphers[purpose].encrypt(
            nonce, plaintext, self._reference_aad(purpose)
        )
        return bytes([REFERENCE_VERSION]) + nonce + ciphertext

    def open_review_reference(self, envelope: bytes) -> tuple[int, int, int]:
        values = self._open_reference(envelope, "review", 3)
        return values[0], values[1], values[2]

    def open_restriction_reference(self, envelope: bytes) -> tuple[int, int]:
        values = self._open_reference(envelope, "restriction", 2)
        return values[0], values[1]

    def _open_reference(
        self, envelope: bytes, purpose: str, expected_values: int
    ) -> list[int]:
        if (
            len(envelope) <= 1 + _GCM_NONCE_BYTES + _GCM_TAG_BYTES
            or envelope[0] != REFERENCE_VERSION
        ):
            raise ValueError(f"invalid {purpose} reference")
        nonce = envelope[1 : 1 + _GCM_NONCE_BYTES]
        try:
            plaintext = self._reference_ciphers[purpose].decrypt(
                nonce, envelope[1 + _GCM_NONCE_BYTES :], self._reference_aad(purpose)
            )
        except InvalidTag as exc:
            raise ValueError(f"invalid {purpose} reference") from exc
        return _parse_reference_values(plaintext, purpose, expected_values)

    def reseal_legacy_reference(self, envelope: bytes) -> bytes | None:
        """Re-seal a version 1 reference as version 2 under the same purpose.

        The purpose is recovered from whichever domain-separated key
        authenticates the envelope, so callers need not know which column held
        which purpose. Returns None when no purpose authenticates it.
        """
        for purpose, expected_values in _REFERENCE_PURPOSES.items():
            try:
                values = _open_legacy_reference(
                    self._key, envelope, purpose, expected_values
                )
            except ValueError:
                continue
            return self._seal_reference(values, purpose)
        return None

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
