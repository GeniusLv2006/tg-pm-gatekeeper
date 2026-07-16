# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.restriction_actions import (
    RestrictionActions,
    RestrictionReleaseResult,
)
from tg_pm_gatekeeper.service import GatekeeperService
from tg_pm_gatekeeper.store import DialogSnapshot, StateStore


class FakeTelegramClient:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.requests: list[object] = []

    async def __call__(self, request):
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("synthetic failure")


class RestrictionActionsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")
        self.protector = IdentifierProtector(b"k" * 32)
        self.service = GatekeeperService(self.store, self.protector)
        self.cancelled: list[str] = []

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    async def test_allow_restores_state_and_cancels_pending_work(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        review_reference = self.protector.seal_review_reference(
            123456789, -987654321, 42
        )
        restriction_reference = self.protector.seal_restriction_reference(
            123456789, -987654321
        )
        self.store.save_dialog_snapshot(
            sender_key,
            DialogSnapshot(folder_id=1, silent=True, mute_until=None),
        )
        state = self.store.suppress(
            sender_key,
            "critical_rule",
            until=None,
            reference=review_reference,
            restriction_reference=restriction_reference,
        )
        action_id = self.store.schedule_action(
            sender_key,
            reason="critical_rule",
            reference=review_reference,
            execute_at=9999999999,
            expected_revision=state.revision,
        )
        client = FakeTelegramClient()
        actions = RestrictionActions(
            self.store,
            self.service,
            client,
            cancel_timeout=self.cancelled.append,
        )

        result = await actions.allow(sender_key)

        self.assertEqual(result, RestrictionReleaseResult.ALLOWED)
        self.assertEqual(self.store.sender(sender_key).status, "allowed")
        self.assertIsNone(self.store.dialog_snapshot(sender_key))
        action = self.store._connection.execute(
            "SELECT status FROM pending_actions WHERE id=?",
            (action_id,),
        ).fetchone()
        self.assertEqual(action["status"], "cancelled")
        self.assertEqual(self.cancelled, [sender_key])
        self.assertEqual(len(client.requests), 2)

    async def test_restore_failure_leaves_restriction_unchanged(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        self.store.quarantine(
            sender_key,
            restriction_reference=self.protector.seal_restriction_reference(
                123456789, -987654321
            ),
        )
        actions = RestrictionActions(
            self.store,
            self.service,
            FakeTelegramClient(fail=True),
            cancel_timeout=self.cancelled.append,
        )

        result = await actions.allow(sender_key)

        self.assertEqual(result, RestrictionReleaseResult.TELEGRAM_ACTION_FAILED)
        self.assertEqual(self.store.sender(sender_key).status, "quarantined")
        self.assertEqual(self.cancelled, [])

    async def test_missing_control_identity_fails_closed(self) -> None:
        self.store.quarantine("legacy-sender")
        actions = RestrictionActions(
            self.store,
            self.service,
            FakeTelegramClient(),
        )

        result = await actions.allow("legacy-sender")

        self.assertEqual(result, RestrictionReleaseResult.IDENTITY_UNAVAILABLE)
        self.assertEqual(self.store.sender("legacy-sender").status, "quarantined")
