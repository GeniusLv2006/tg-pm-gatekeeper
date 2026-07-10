# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import unittest

from tg_pm_gatekeeper.crypto import ActiveCaseProtector, IdentifierProtector


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
