# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Version 1 references produced by the retired pyaes AES-CTR implementation.

Generated once with key b"k" * 32 and fixed nonces bytes(range(16)) and
bytes(range(16, 32)), so the migration is tested against real old ciphertext
rather than output of the code under test.
"""

from __future__ import annotations

LEGACY_KEY = b"k" * 32

LEGACY_REVIEW_REFERENCE = bytes.fromhex(
    "01000102030405060708090a0b0c0d0e0f6b6272f1c34bb5aeccaf0d5f12d571276dc5"
    "caddccbfcb7ea013eade80d0be11d9dc4693b589d458eff8b0c05b1fdbf67352b85b22"
    "9879a4b8"
)
LEGACY_REVIEW_VALUES = (123456789, -987654321, 42)

LEGACY_RESTRICTION_REFERENCE = bytes.fromhex(
    "01101112131415161718191a1b1c1d1e1f218053067d913ea1b02877e174bc0c1d2863"
    "92750031196f9e53e871ed3fcbbafde01c488b9210dd5154277565d2c11930d0690872"
    "17"
)
LEGACY_RESTRICTION_VALUES = (123456789, -987654321)
