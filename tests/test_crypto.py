# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from __future__ import annotations

import unittest

from tg_pm_gatekeeper.crypto import IdentifierProtector


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


if __name__ == "__main__":
    unittest.main()
