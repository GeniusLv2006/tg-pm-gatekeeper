# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import re
import sqlite3
import unittest
from enum import StrEnum

from tg_pm_gatekeeper.states import ActionStatus, ReviewStatus, SenderStatus
from tg_pm_gatekeeper.store import SCHEMA, SENDER_STATE_SCHEMA, SenderState


class StatusSchemaTests(unittest.TestCase):
    def check_values(self, table: str) -> set[str]:
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(SENDER_STATE_SCHEMA + SCHEMA)
            (sql,) = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
        finally:
            connection.close()
        match = re.search(r"\bstatus\b[^,]*?CHECK \(status IN \(([^)]*)\)\)", sql, re.S)
        self.assertIsNotNone(match, table)
        assert match is not None
        return set(re.findall(r"'([a-z_]+)'", match.group(1)))

    def test_enums_match_schema_constraints(self) -> None:
        cases: tuple[tuple[str, type[StrEnum]], ...] = (
            ("sender_state", SenderStatus),
            ("review_queue", ReviewStatus),
            ("pending_actions", ActionStatus),
        )
        for table, enum in cases:
            with self.subTest(table=table):
                self.assertEqual(self.check_values(table), {item.value for item in enum})

    def test_dataclasses_coerce_stored_status(self) -> None:
        state = SenderState(
            "suppressed", None, None, None, None, None, None, None, None,
            False, 0, None, None, 1, 0,
        )
        self.assertIs(state.status, SenderStatus.SUPPRESSED)
        with self.assertRaises(ValueError):
            SenderState(
                "blocked", None, None, None, None, None, None, None, None,
                False, 0, None, None, 1, 0,
            )


if __name__ == "__main__":
    unittest.main()
