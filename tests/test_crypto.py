# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import unittest

from tg_pm_gatekeeper.crypto import (
    REFERENCE_VERSION,
    ActiveCaseProtector,
    IdentifierProtector,
)

from .legacy_references import (
    LEGACY_KEY,
    LEGACY_RESTRICTION_REFERENCE,
    LEGACY_RESTRICTION_VALUES,
    LEGACY_REVIEW_REFERENCE,
    LEGACY_REVIEW_VALUES,
)


class CryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protector = IdentifierProtector(b"k" * 32)

    def test_review_reference_round_trip(self) -> None:
        sealed = self.protector.seal_review_reference(123456789, -987654321, 42)
        self.assertNotIn(b"123456789", sealed)
        self.assertEqual(
            self.protector.open_review_reference(sealed),
            (123456789, -987654321, 42),
        )

    def test_review_reference_rejects_tampering(self) -> None:
        sealed = bytearray(
            self.protector.seal_review_reference(123456789, -987654321, 42)
        )
        sealed[20] ^= 1
        with self.assertRaises(ValueError):
            self.protector.open_review_reference(bytes(sealed))

    def test_restriction_reference_is_minimal_and_domain_separated(self) -> None:
        sealed = self.protector.seal_restriction_reference(123456789, -987654321)
        self.assertNotIn(b"123456789", sealed)
        self.assertEqual(
            self.protector.open_restriction_reference(sealed),
            (123456789, -987654321),
        )
        with self.assertRaises(ValueError):
            self.protector.open_review_reference(sealed)

    def test_references_are_version_2_aes_gcm_envelopes(self) -> None:
        review = self.protector.seal_review_reference(123456789, -987654321, 42)
        restriction = self.protector.seal_restriction_reference(123456789, -987654321)
        for sealed, plaintext in (
            (review, b"[123456789,-987654321,42]"),
            (restriction, b"[123456789,-987654321]"),
        ):
            self.assertEqual(sealed[0], REFERENCE_VERSION)
            self.assertEqual(len(sealed), 1 + 12 + len(plaintext) + 16)
        self.assertNotEqual(
            self.protector.seal_review_reference(1, 2, 3),
            self.protector.seal_review_reference(1, 2, 3),
        )

    def test_review_reference_does_not_open_as_restriction(self) -> None:
        sealed = self.protector.seal_review_reference(123456789, -987654321, 42)
        with self.assertRaises(ValueError):
            self.protector.open_restriction_reference(sealed)

    def test_reference_rejects_other_key_truncation_and_bad_version(self) -> None:
        sealed = self.protector.seal_review_reference(123456789, -987654321, 42)
        with self.assertRaises(ValueError):
            IdentifierProtector(b"x" * 32).open_review_reference(sealed)
        for broken in (sealed[:-1], sealed[:29], b"\x03" + sealed[1:], b""):
            with self.subTest(length=len(broken)), self.assertRaises(ValueError):
                self.protector.open_review_reference(broken)

    def test_live_code_no_longer_opens_version_1_references(self) -> None:
        protector = IdentifierProtector(LEGACY_KEY)
        with self.assertRaises(ValueError):
            protector.open_review_reference(LEGACY_REVIEW_REFERENCE)
        with self.assertRaises(ValueError):
            protector.open_restriction_reference(LEGACY_RESTRICTION_REFERENCE)

    def test_legacy_references_reseal_under_their_own_purpose(self) -> None:
        protector = IdentifierProtector(LEGACY_KEY)
        review = protector.reseal_legacy_reference(LEGACY_REVIEW_REFERENCE)
        restriction = protector.reseal_legacy_reference(LEGACY_RESTRICTION_REFERENCE)
        assert review is not None and restriction is not None

        self.assertEqual(review[0], REFERENCE_VERSION)
        self.assertEqual(protector.open_review_reference(review), LEGACY_REVIEW_VALUES)
        with self.assertRaises(ValueError):
            protector.open_restriction_reference(review)

        self.assertEqual(restriction[0], REFERENCE_VERSION)
        self.assertEqual(
            protector.open_restriction_reference(restriction),
            LEGACY_RESTRICTION_VALUES,
        )
        with self.assertRaises(ValueError):
            protector.open_review_reference(restriction)

    def test_unauthenticated_legacy_reference_is_not_resealed(self) -> None:
        protector = IdentifierProtector(LEGACY_KEY)
        tampered = bytearray(LEGACY_REVIEW_REFERENCE)
        tampered[20] ^= 1
        for envelope in (
            bytes(tampered),
            LEGACY_REVIEW_REFERENCE[:-1],
            b"\x01",
            protector.seal_review_reference(1, 2, 3),
        ):
            with self.subTest(envelope=envelope[:4].hex()):
                self.assertIsNone(protector.reseal_legacy_reference(envelope))
        self.assertIsNone(
            IdentifierProtector(b"x" * 32).reseal_legacy_reference(
                LEGACY_REVIEW_REFERENCE
            )
        )

    def test_active_case_content_round_trip_and_tamper_rejection(self) -> None:
        protector = ActiveCaseProtector(b"r" * 32)
        payload = {"text": "private-canary", "severity": "critical"}
        sealed = protector.seal(payload)

        self.assertNotIn(b"private-canary", sealed)
        self.assertEqual(protector.open(sealed), payload)
        tampered = bytearray(sealed)
        tampered[-1] ^= 1
        with self.assertRaises(ValueError):
            protector.open(bytes(tampered))

    def test_active_case_key_is_domain_separated(self) -> None:
        payload = {"text": "private-canary"}
        envelope = ActiveCaseProtector(b"r" * 32).seal(payload)

        with self.assertRaises(ValueError):
            ActiveCaseProtector(b"s" * 32).open(envelope)


if __name__ == "__main__":
    unittest.main()
