from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.rules import MessageFacts
from tg_pm_gatekeeper.service import Challenge, GatekeeperService, IncomingMessage
from tg_pm_gatekeeper.store import StateStore


class FakeActions:
    def __init__(self, quarantine_success: bool = True) -> None:
        self.sent: list[str] = []
        self.quarantines = 0
        self.scheduled: list[tuple[str, int]] = []
        self.cancelled: list[str] = []
        self.restores = 0
        self.quarantine_success = quarantine_success

    async def send_text(self, text: str) -> None:
        self.sent.append(text)

    async def archive_and_mute(self) -> bool:
        self.quarantines += 1
        return self.quarantine_success

    async def restore_from_pending(self) -> bool:
        self.restores += 1
        return self.quarantine_success

    def schedule_timeout(self, sender_key: str, expires_at: int) -> None:
        self.scheduled.append((sender_key, expires_at))

    def cancel_timeout(self, sender_key: str) -> None:
        self.cancelled.append(sender_key)


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")
        self.protector = IdentifierProtector(b"k" * 32)
        self.now = 1_000
        self.service = GatekeeperService(
            self.store,
            self.protector,
            challenge_ttl_seconds=60,
            challenge_max_attempts=2,
            challenge_factory=lambda: Challenge("challenge", "12", "6 + 6 = ?"),
            clock=lambda: self.now,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def message(
        self,
        message_id: int,
        text: str = "hello",
        facts: MessageFacts | None = None,
        *,
        review_reference: bytes | None = None,
    ) -> IncomingMessage:
        return IncomingMessage(
            123456789,
            message_id,
            text,
            facts or MessageFacts(text=text),
            review_reference=review_reference,
        )

    async def test_observe_mode_never_sends_or_quarantines(self) -> None:
        actions = FakeActions()
        outcome = await self.service.handle(
            self.message(
                1,
                text="private-message-canary",
                facts=MessageFacts(text="private-message-canary", has_link_button=True),
            ),
            actions,
        )
        self.assertEqual(outcome, "would_quarantine")
        self.assertEqual(actions.sent, [])
        self.assertEqual(actions.quarantines, 0)
        database = (Path(self.temp.name) / "state.sqlite3").read_bytes()
        self.assertNotIn(b"private-message-canary", database)

    async def test_observe_mode_enqueues_review_without_message_content(self) -> None:
        reference = self.protector.seal_review_reference(123456789, 456, 1)
        outcome = await self.service.handle(
            self.message(
                1,
                text="private-message-canary",
                facts=MessageFacts(
                    text="private-message-canary", has_link_button=True
                ),
                review_reference=reference,
            ),
            FakeActions(),
        )
        self.assertEqual(outcome, "would_quarantine")
        item = self.store.review_items()[0]
        self.assertEqual(item.classification, "would_quarantine")
        self.assertIn("HR-01_LINK_BUTTON", item.rule_codes)
        self.assertEqual(
            self.protector.open_review_reference(item.reference or b""),
            (123456789, 456, 1),
        )
        database = (Path(self.temp.name) / "state.sqlite3").read_bytes()
        self.assertNotIn(b"private-message-canary", database)

    async def test_enforce_challenge_and_correct_answer(self) -> None:
        self.store.set_mode("enforce")
        actions = FakeActions()
        self.assertEqual(
            await self.service.handle(self.message(1), actions), "challenged"
        )
        self.assertEqual(actions.sent, ["6 + 6 = ?"])
        self.assertEqual(
            await self.service.handle(self.message(2, "12"), actions), "allowed"
        )
        self.assertEqual(actions.restores, 1)
        self.assertEqual(
            self.store.sender(self.protector.sender_key(123456789)).status, "allowed"
        )

    async def test_hard_rule_archives_without_challenge(self) -> None:
        self.store.set_mode("enforce")
        actions = FakeActions()
        outcome = await self.service.handle(
            self.message(1, facts=MessageFacts(has_link_button=True)), actions
        )
        self.assertEqual(outcome, "quarantined")
        self.assertEqual(actions.quarantines, 1)
        self.assertEqual(actions.sent, [])

    async def test_quarantined_sender_does_not_reenter_review_queue(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        self.store.quarantine(sender_key, self.now)
        reference = self.protector.seal_review_reference(123456789, 456, 1)
        outcome = await self.service.handle(
            self.message(
                1,
                facts=MessageFacts(has_link_button=True),
                review_reference=reference,
            ),
            FakeActions(),
        )
        self.assertEqual(outcome, "already_quarantined")
        self.assertEqual(self.store.review_items(), [])

    async def test_action_failure_is_fail_safe(self) -> None:
        self.store.set_mode("enforce")
        actions = FakeActions(quarantine_success=False)
        outcome = await self.service.handle(
            self.message(1, facts=MessageFacts(has_link_button=True)), actions
        )
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(
            self.store.sender(self.protector.sender_key(123456789)).status, "unknown"
        )

    async def test_duplicate_message_has_no_second_action(self) -> None:
        self.store.set_mode("enforce")
        actions = FakeActions()
        await self.service.handle(self.message(1), actions)
        self.assertEqual(
            await self.service.handle(self.message(1), actions), "duplicate"
        )
        self.assertEqual(len(actions.sent), 1)

    async def test_gatekeeper_challenge_does_not_create_trusted_history_bypass(
        self,
    ) -> None:
        self.store.set_mode("enforce")
        sender_key = self.protector.sender_key(123456789)
        digest = self.protector.answer_digest(sender_key, "challenge", "12")
        self.store.set_challenge(
            sender_key, "challenge", digest, self.now + 600, self.now
        )
        actions = FakeActions()
        message = IncomingMessage(
            123456789,
            2,
            "11",
            MessageFacts(text="11"),
            has_trusted_history=True,
        )
        self.assertEqual(
            await self.service.handle(message, actions), "challenge_incorrect"
        )
        self.assertEqual(self.store.sender(sender_key).status, "challenged")

    async def test_non_numeric_content_does_not_consume_attempt(self) -> None:
        self.store.set_mode("enforce")
        sender_key = self.protector.sender_key(123456789)
        digest = self.protector.answer_digest(sender_key, "challenge", "12")
        self.store.set_challenge(
            sender_key, "challenge", digest, self.now + 60, self.now
        )
        actions = FakeActions()
        self.assertEqual(
            await self.service.handle(self.message(2, "not an answer"), actions),
            "challenge_pending",
        )
        self.assertEqual(self.store.sender(sender_key).attempts, 0)
        self.assertEqual(actions.sent, [])


if __name__ == "__main__":
    unittest.main()
