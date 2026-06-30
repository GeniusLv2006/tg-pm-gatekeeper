from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.rules import MessageFacts
from tg_pm_gatekeeper.service import (
    DIGITS_REQUIRED_TEXT,
    REPLY_REQUIRED_TEXT,
    Challenge,
    GatekeeperService,
    IncomingMessage,
    challenge_prompt,
)
from tg_pm_gatekeeper.store import StateStore


class FakeActions:
    def __init__(
        self,
        *,
        archive_success: bool = True,
        restore_success: bool = True,
        send_success: bool = True,
    ) -> None:
        self.sent: list[tuple[str, int | None]] = []
        self.quarantines = 0
        self.scheduled: list[tuple[str, int, int]] = []
        self.cancelled: list[str] = []
        self.restores = 0
        self.archive_success = archive_success
        self.restore_success = restore_success
        self.send_success = send_success
        self.next_message_id = 100
        self.send_started: asyncio.Event | None = None
        self.release_send: asyncio.Event | None = None

    async def send_text(
        self, text: str, *, reply_to_message_id: int | None = None
    ) -> int:
        if self.send_started is not None:
            self.send_started.set()
        if self.release_send is not None:
            await self.release_send.wait()
        if not self.send_success:
            raise RuntimeError("send failed")
        self.sent.append((text, reply_to_message_id))
        message_id = self.next_message_id
        self.next_message_id += 1
        return message_id

    async def archive_and_mute(self) -> bool:
        self.quarantines += 1
        return self.archive_success

    async def restore_from_pending(self) -> bool:
        self.restores += 1
        return self.restore_success

    def schedule_timeout(
        self, sender_key: str, expires_at: int, *, grace_seconds: int = 5
    ) -> None:
        self.scheduled.append((sender_key, expires_at, grace_seconds))

    def cancel_timeout(self, sender_key: str) -> None:
        self.cancelled.append(sender_key)


class SendBarrier:
    def __init__(self, target: int) -> None:
        self.target = target
        self.count = 0
        self.event = asyncio.Event()

    async def wait(self) -> None:
        self.count += 1
        if self.count >= self.target:
            self.event.set()
        await self.event.wait()


class BarrierActions(FakeActions):
    def __init__(self, barrier: SendBarrier) -> None:
        super().__init__()
        self.barrier = barrier

    async def send_text(
        self, text: str, *, reply_to_message_id: int | None = None
    ) -> int:
        await self.barrier.wait()
        return await super().send_text(text, reply_to_message_id=reply_to_message_id)


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp.name) / "state.sqlite3"
        self.store = StateStore(self.database_path)
        self.protector = IdentifierProtector(b"k" * 32)
        self.now = 1_000
        self.service = self.make_service()

    def make_service(self, *, outbound_limit: int = 10) -> GatekeeperService:
        return GatekeeperService(
            self.store,
            self.protector,
            challenge_ttl_seconds=60,
            challenge_max_attempts=2,
            outbound_limit_per_hour=outbound_limit,
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
        sender_id: int = 123456789,
        sent_at: int | None = None,
        reply_to_message_id: int | None = None,
        trusted: bool = False,
        review_reference: bytes | None = None,
    ) -> IncomingMessage:
        return IncomingMessage(
            sender_id=sender_id,
            message_id=message_id,
            text=text,
            facts=facts or MessageFacts(text=text),
            sent_at=self.now if sent_at is None else sent_at,
            reply_to_message_id=reply_to_message_id,
            has_trusted_history=trusted,
            review_reference=review_reference,
        )

    def set_active_challenge(self, *, sender_id: int = 123456789) -> str:
        sender_key = self.protector.sender_key(sender_id)
        digest = self.protector.answer_digest(sender_key, "challenge", "12")
        self.store.set_challenge(
            sender_key, "challenge", digest, self.now + 60, 100, self.now
        )
        return sender_key

    def test_nondefault_ttl_is_rendered_in_prompt(self) -> None:
        prompt = challenge_prompt(Challenge("id", "12", "6 + 6 = ?"), 90)
        self.assertIn("within 90 seconds", prompt)
        self.assertNotIn("within 1 minute", prompt)
        one_second = challenge_prompt(Challenge("id", "12", "6 + 6 = ?"), 1)
        self.assertIn("within 1 second", one_second)

    async def test_observe_mode_never_sends_or_quarantines(self) -> None:
        actions = FakeActions()
        outcome = await self.service.handle(
            self.message(
                1,
                text="private-message-canary",
                facts=MessageFacts(
                    text="private-message-canary",
                    has_link_button=True,
                    link_button_count=2,
                ),
            ),
            actions,
        )
        self.assertEqual(outcome, "would_quarantine")
        self.assertEqual(actions.sent, [])
        self.assertEqual(actions.quarantines, 0)
        self.assertNotIn(b"private-message-canary", self.database_path.read_bytes())

    async def test_challenge_prompt_requires_reply_and_passes_to_provisional(self) -> None:
        self.store.set_mode("enforce")
        actions = FakeActions()
        self.assertEqual(
            await self.service.handle(self.message(1), actions), "challenged"
        )
        prompt = actions.sent[0][0]
        self.assertIn("Verification required", prompt)
        self.assertIn("within 1 minute", prompt)
        self.assertIn("Telegram's Reply action", prompt)
        self.assertIn("Send only the answer: 6 + 6 = ?", prompt)
        self.assertIn("A separate message will not be accepted.", prompt)
        self.assertEqual(
            await self.service.handle(
                self.message(2, "12", reply_to_message_id=100), actions
            ),
            "provisional",
        )
        sender_key = self.protector.sender_key(123456789)
        self.assertEqual(self.store.sender(sender_key).status, "provisional")
        self.assertEqual(actions.restores, 1)
        self.assertIn("conversation has been restored", actions.sent[-1][0])

    async def test_standalone_answer_does_not_consume_attempt_and_guides_once(self) -> None:
        sender_key = self.set_active_challenge()
        actions = FakeActions()
        for message_id in (2, 3):
            self.assertEqual(
                await self.service.handle(self.message(message_id, "12"), actions),
                "challenge_pending",
            )
        self.assertEqual(self.store.sender(sender_key).attempts, 0)
        self.assertEqual([text for text, _ in actions.sent], [REPLY_REQUIRED_TEXT])
        self.assertNotIn("example", actions.sent[0][0].casefold())

    async def test_non_numeric_reply_does_not_consume_attempt(self) -> None:
        sender_key = self.set_active_challenge()
        actions = FakeActions()
        for message_id in (2, 3):
            outcome = await self.service.handle(
                self.message(
                    message_id, "not an answer", reply_to_message_id=100
                ),
                actions,
            )
            self.assertEqual(outcome, "challenge_pending")
        self.assertEqual(self.store.sender(sender_key).attempts, 0)
        self.assertEqual([text for text, _ in actions.sent], [DIGITS_REQUIRED_TEXT] * 2)
        self.assertNotIn("12", DIGITS_REQUIRED_TEXT)

    async def test_fullwidth_digits_and_leading_zero_are_canonicalized(self) -> None:
        sender_key = self.set_active_challenge()
        actions = FakeActions()
        outcome = await self.service.handle(
            self.message(2, "０１２", reply_to_message_id=100), actions
        )
        self.assertEqual(outcome, "provisional")
        self.assertEqual(self.store.sender(sender_key).status, "provisional")

    async def test_many_leading_zeroes_are_canonicalized(self) -> None:
        sender_key = self.set_active_challenge()
        outcome = await self.service.handle(
            self.message(2, "0000000012", reply_to_message_id=100), FakeActions()
        )
        self.assertEqual(outcome, "provisional")
        self.assertEqual(self.store.sender(sender_key).status, "provisional")

    async def test_signed_number_is_format_error_without_attempt(self) -> None:
        sender_key = self.set_active_challenge()
        outcome = await self.service.handle(
            self.message(2, "+12", reply_to_message_id=100), FakeActions()
        )
        self.assertEqual(outcome, "challenge_pending")
        self.assertEqual(self.store.sender(sender_key).attempts, 0)

    async def test_incorrect_answers_exhaust_attempts_without_new_telegram_action(self) -> None:
        sender_key = self.set_active_challenge()
        actions = FakeActions()
        first = await self.service.handle(
            self.message(2, "11", reply_to_message_id=100), actions
        )
        second = await self.service.handle(
            self.message(3, "10", reply_to_message_id=100), actions
        )
        self.assertEqual((first, second), ("challenge_incorrect", "quarantined"))
        self.assertEqual(self.store.sender(sender_key).status, "quarantined")
        self.assertEqual(actions.quarantines, 0)
        self.assertIn("1 attempt remaining", actions.sent[0][0])

    async def test_message_sent_before_deadline_can_pass_after_processing_delay(self) -> None:
        sender_key = self.set_active_challenge()
        self.now = 1_100
        outcome = await self.service.handle(
            self.message(
                2, "12", sent_at=1_059, reply_to_message_id=100
            ),
            FakeActions(),
        )
        self.assertEqual(outcome, "provisional")
        self.assertEqual(self.store.sender(sender_key).status, "provisional")

    async def test_message_sent_after_deadline_is_quarantined(self) -> None:
        sender_key = self.set_active_challenge()
        outcome = await self.service.handle(
            self.message(2, "12", sent_at=1_061, reply_to_message_id=100),
            FakeActions(),
        )
        self.assertEqual(outcome, "quarantined")
        self.assertEqual(self.store.sender(sender_key).status, "quarantined")

    async def test_archive_failure_rolls_challenge_back(self) -> None:
        self.store.set_mode("enforce")
        sender_key = self.protector.sender_key(123456789)
        actions = FakeActions(archive_success=False)
        outcome = await self.service.handle(self.message(1), actions)
        state = self.store.sender(sender_key)
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(state.status, "unknown")
        self.assertIsNone(state.challenge_message_id)
        self.assertEqual(actions.scheduled, [])

    async def test_send_failure_rolls_challenge_back(self) -> None:
        self.store.set_mode("enforce")
        sender_key = self.protector.sender_key(123456789)
        outcome = await self.service.handle(
            self.message(1), FakeActions(send_success=False)
        )
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(self.store.sender(sender_key).status, "unknown")

    async def test_rate_limit_fallback_archives_and_enqueues_review(self) -> None:
        self.store.set_mode("enforce")
        service = self.make_service(outbound_limit=1)
        self.store.claim_outbound_slot(1, self.now)
        reference = self.protector.seal_review_reference(123456789, 456, 1)
        actions = FakeActions()
        outcome = await service.handle(
            self.message(1, review_reference=reference), actions
        )
        sender_key = self.protector.sender_key(123456789)
        self.assertEqual(outcome, "quarantined_rate_limited")
        self.assertEqual(self.store.sender(sender_key).status, "quarantined")
        self.assertEqual(self.store.review_items()[0].classification, "challenge_unavailable")

    async def test_rate_limit_archive_failure_stays_unknown_and_enqueues_review(self) -> None:
        self.store.set_mode("enforce")
        service = self.make_service(outbound_limit=1)
        self.store.claim_outbound_slot(1, self.now)
        reference = self.protector.seal_review_reference(123456789, 456, 1)
        outcome = await service.handle(
            self.message(1, review_reference=reference),
            FakeActions(archive_success=False),
        )
        sender_key = self.protector.sender_key(123456789)
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(self.store.sender(sender_key).status, "unknown")
        self.assertEqual(
            self.store.review_items()[0].classification,
            "challenge_unavailable_action_failed",
        )

    async def test_provisional_sender_is_still_screened(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        self.store.mark_provisional(sender_key, self.now)
        self.store.set_mode("enforce")
        outcome = await self.service.handle(
            self.message(
                1,
                facts=MessageFacts(has_link_button=True, link_button_count=2),
            ),
            FakeActions(),
        )
        self.assertEqual(outcome, "quarantined")

    async def test_owner_reply_promotes_provisional_sender(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        self.store.mark_provisional(sender_key, self.now)
        outcome = await self.service.handle(
            self.message(1, trusted=True), FakeActions()
        )
        self.assertEqual(outcome, "allowed")
        self.assertEqual(self.store.sender(sender_key).status, "allowed")

    async def test_same_sender_concurrency_issues_only_one_challenge(self) -> None:
        self.store.set_mode("enforce")
        actions = FakeActions()
        actions.send_started = asyncio.Event()
        actions.release_send = asyncio.Event()
        first = asyncio.create_task(self.service.handle(self.message(1), actions))
        await actions.send_started.wait()
        second = asyncio.create_task(self.service.handle(self.message(2), actions))
        actions.release_send.set()
        outcomes = await asyncio.gather(first, second)
        prompts = [text for text, _ in actions.sent if text.startswith("Verification required")]
        self.assertEqual(len(prompts), 1)
        self.assertEqual(outcomes[0], "challenged")
        self.assertEqual(outcomes[1], "challenge_pending")

    async def test_different_senders_can_issue_challenges_in_parallel(self) -> None:
        self.store.set_mode("enforce")
        barrier = SendBarrier(2)
        first_actions = BarrierActions(barrier)
        second_actions = BarrierActions(barrier)
        outcomes = await asyncio.wait_for(
            asyncio.gather(
                self.service.handle(self.message(1, sender_id=1), first_actions),
                self.service.handle(self.message(1, sender_id=2), second_actions),
            ),
            timeout=1,
        )
        self.assertEqual(outcomes, ["challenged", "challenged"])

    async def test_concurrent_correct_and_wrong_answers_cannot_requarantine(self) -> None:
        sender_key = self.set_active_challenge()
        actions = FakeActions()
        outcomes = await asyncio.gather(
            self.service.handle(
                self.message(2, "12", reply_to_message_id=100), actions
            ),
            self.service.handle(
                self.message(3, "11", reply_to_message_id=100), actions
            ),
        )
        self.assertEqual(outcomes, ["provisional", "provisional"])
        self.assertEqual(self.store.sender(sender_key).status, "provisional")

    async def test_timeout_finalizes_even_after_mode_switch_to_observe(self) -> None:
        sender_key = self.set_active_challenge()
        self.store.set_mode("observe")
        self.assertTrue(
            await self.service.expire_challenge(
                sender_key, self.now + 60, now=self.now + 65
            )
        )
        self.assertEqual(self.store.sender(sender_key).status, "quarantined")

    async def test_incomplete_challenge_recovery_activates_and_schedules(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_review_reference(123456789, 456, 1)
        digest = self.protector.answer_digest(sender_key, "challenge", "12")
        self.store.begin_challenge_issue(
            sender_key,
            "challenge",
            digest,
            self.now + 60,
            "Verification required",
            reference,
            self.now,
        )
        actions = FakeActions()
        recovered = await self.service.recover_incomplete_challenge(
            sender_key, actions, recovered_message_id=88
        )
        self.assertTrue(recovered)
        self.assertEqual(self.store.sender(sender_key).status, "challenged")
        self.assertEqual(actions.scheduled[0][2], 30)

    async def test_recovery_archive_failure_resets_unknown(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        digest = self.protector.answer_digest(sender_key, "challenge", "12")
        self.store.begin_challenge_issue(
            sender_key,
            "challenge",
            digest,
            self.now + 60,
            "Verification required",
            None,
            self.now,
        )
        recovered = await self.service.recover_incomplete_challenge(
            sender_key,
            FakeActions(archive_success=False),
            recovered_message_id=88,
        )
        self.assertFalse(recovered)
        self.assertEqual(self.store.sender(sender_key).status, "unknown")

    async def test_restore_failure_keeps_active_challenge(self) -> None:
        sender_key = self.set_active_challenge()
        outcome = await self.service.handle(
            self.message(2, "12", reply_to_message_id=100),
            FakeActions(restore_success=False),
        )
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(self.store.sender(sender_key).status, "challenged")

    async def test_duplicate_message_has_no_second_action(self) -> None:
        self.store.set_mode("enforce")
        actions = FakeActions()
        await self.service.handle(self.message(1), actions)
        self.assertEqual(
            await self.service.handle(self.message(1), actions), "duplicate"
        )


if __name__ == "__main__":
    unittest.main()
