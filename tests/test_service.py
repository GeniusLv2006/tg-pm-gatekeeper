# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.dataset import DatasetProtector, TrainingStore
from tg_pm_gatekeeper.rules import MessageFacts
from tg_pm_gatekeeper.service import (
    DIGITS_REQUIRED_TEXT,
    REPLY_REQUIRED_TEXT,
    VERIFICATION_FAILED_TEXT,
    VERIFICATION_TIMEOUT_TEXT,
    Challenge,
    GatekeeperService,
    IncomingMessage,
    TextStyleSpan,
    challenge_prompt,
    challenge_prompt_formatting,
    new_challenge,
)
from tg_pm_gatekeeper.store import StateStore


TEST_SENDER_ID = 900_000_001


class FakeActions:
    def __init__(
        self,
        *,
        archive_success: bool = True,
        restore_success: bool = True,
        send_success: bool = True,
    ) -> None:
        self.sent: list[tuple[str, int | None]] = []
        self.formattings: list[tuple[TextStyleSpan, ...]] = []
        self.quarantines = 0
        self.scheduled: list[tuple[str, int, int]] = []
        self.cancelled: list[str] = []
        self.deletions: list[tuple[str, int, int]] = []
        self.deleted_messages: list[int] = []
        self.deleted_message_batches: list[tuple[int, ...]] = []
        self.deleted_dialogs = 0
        self.dialog_deletions: list[tuple[int, int]] = []
        self.resets: list[tuple[str, int, int]] = []
        self.restores = 0
        self.archive_success = archive_success
        self.restore_success = restore_success
        self.send_success = send_success
        self.next_message_id = 100
        self.send_started: asyncio.Event | None = None
        self.release_send: asyncio.Event | None = None
        self.after_send = None

    async def send_text(
        self,
        text: str,
        *,
        reply_to_message_id: int | None = None,
        formatting: tuple[TextStyleSpan, ...] = (),
    ) -> int:
        if self.send_started is not None:
            self.send_started.set()
        if self.release_send is not None:
            await self.release_send.wait()
        if not self.send_success:
            raise RuntimeError("send failed")
        self.sent.append((text, reply_to_message_id))
        self.formattings.append(formatting)
        if self.after_send is not None:
            self.after_send()
        message_id = self.next_message_id
        self.next_message_id += 1
        return message_id

    async def archive_and_mute(self) -> bool:
        self.quarantines += 1
        return self.archive_success

    async def restore_from_pending(self) -> bool:
        self.restores += 1
        return self.restore_success

    async def delete_message(self, message_id: int) -> bool:
        self.deleted_messages.append(message_id)
        return True

    async def delete_messages(self, message_ids: tuple[int, ...]) -> bool:
        self.deleted_message_batches.append(message_ids)
        return True

    async def delete_dialog(self) -> bool:
        self.deleted_dialogs += 1
        return True

    def schedule_dialog_deletion(self, action_id: int, delete_at: int) -> None:
        self.dialog_deletions.append((action_id, delete_at))

    def schedule_timeout(
        self, sender_key: str, expires_at: int, *, grace_seconds: int = 5
    ) -> None:
        self.scheduled.append((sender_key, expires_at, grace_seconds))

    def cancel_timeout(self, sender_key: str) -> None:
        self.cancelled.append(sender_key)

    def schedule_test_message_deletion(
        self, sender_key: str, since: int, delete_at: int
    ) -> None:
        self.deletions.append((sender_key, since, delete_at))

    def schedule_test_state_reset(
        self, sender_key: str, expected_updated_at: int, reset_at: int
    ) -> None:
        self.resets.append((sender_key, expected_updated_at, reset_at))


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
        self,
        text: str,
        *,
        reply_to_message_id: int | None = None,
        formatting: tuple[TextStyleSpan, ...] = (),
    ) -> int:
        await self.barrier.wait()
        return await super().send_text(
            text,
            reply_to_message_id=reply_to_message_id,
            formatting=formatting,
        )


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp.name) / "state.sqlite3"
        self.store = StateStore(self.database_path)
        self.protector = IdentifierProtector(b"k" * 32)
        self.review_protector = DatasetProtector(b"r" * 32)
        self.now = 1_000
        self.service = self.make_service()

    def make_service(
        self,
        *,
        outbound_limit: int = 10,
        test_sender_id: int | None = None,
        training_store: TrainingStore | None = None,
        dataset_collection: bool = True,
    ) -> GatekeeperService:
        return GatekeeperService(
            self.store,
            self.protector,
            challenge_ttl_seconds=60,
            challenge_max_attempts=2,
            outbound_limit_per_hour=outbound_limit,
            test_sender_id=test_sender_id,
            training_store=training_store,
            review_content_protector=self.review_protector,
            dataset_collection=dataset_collection,
            challenge_factory=lambda: Challenge("challenge", "12", "7 + 5 = ?"),
            clock=lambda: self.now,
        )

    async def test_disabled_collection_does_not_add_samples(self) -> None:
        training_store = TrainingStore(
            Path(self.temp.name) / "training.sqlite3",
            DatasetProtector(b"d" * 32),
        )
        self.addCleanup(training_store.close)
        service = self.make_service(
            training_store=training_store,
            dataset_collection=False,
        )

        await service.handle(self.message(1), FakeActions())

        self.assertEqual(training_store.statistics()["total"], 0)

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
        is_contact: bool = False,
        review_reference: bytes | None = None,
    ) -> IncomingMessage:
        if review_reference is None:
            review_reference = self.protector.seal_review_reference(
                sender_id, 987654321, message_id
            )
        return IncomingMessage(
            sender_id=sender_id,
            message_id=message_id,
            text=text,
            facts=facts or MessageFacts(text=text),
            sent_at=self.now if sent_at is None else sent_at,
            reply_to_message_id=reply_to_message_id,
            has_trusted_history=trusted,
            is_contact=is_contact,
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
        prompt = challenge_prompt(Challenge("id", "56", "8 × 7 = ?"), 90)
        self.assertIn("within 90 seconds", prompt)
        self.assertNotIn("within 1 minute", prompt)
        one_second = challenge_prompt(Challenge("id", "56", "8 × 7 = ?"), 1)
        self.assertIn("within 1 second", one_second)

    def test_legacy_recovery_prompt_keeps_safe_title_formatting(self) -> None:
        legacy = (
            "Verification required\n\nPlease reply directly to this message within "
            "1 minute using Telegram's Reply action.\nSend only the answer: "
            "8 × 7 = ?\nA separate message will not be accepted."
        )
        spans = challenge_prompt_formatting(legacy)
        self.assertEqual(len(spans), 1)
        self.assertEqual(
            legacy[spans[0].offset : spans[0].offset + spans[0].length],
            "Verification required",
        )

    def test_challenge_generator_covers_bounded_operation_families(self) -> None:
        cases = (
            ([0, 0, 23], "2 + 25 = ?", "27"),
            ([1, 24, 19], "45 - 20 = ?", "25"),
            ([2, 8, 0], "10 × 2 = ?", "20"),
        )
        for values, expression, answer in cases:
            with self.subTest(expression=expression):
                sequence = iter(values)

                def deterministic_randbelow(upper: int) -> int:
                    value = next(sequence)
                    self.assertGreaterEqual(value, 0)
                    self.assertLess(value, upper)
                    return value

                challenge = new_challenge(
                    randbelow=deterministic_randbelow,
                    token_hex=lambda length: "a" * (length * 2),
                )
                self.assertEqual(challenge.challenge_id, "a" * 32)
                self.assertEqual(challenge.expression, expression)
                self.assertEqual(challenge.answer, answer)

    async def test_monitor_mode_never_sends_or_deletes(self) -> None:
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
        self.assertEqual(outcome, "would_delete")
        self.assertEqual(actions.sent, [])
        self.assertEqual(actions.quarantines, 0)
        self.assertNotIn(b"private-message-canary", self.database_path.read_bytes())

    async def test_monitor_collects_encrypted_unknown_sample_but_excludes_test_sender(
        self,
    ) -> None:
        self.now = int(time.time())
        training_path = Path(self.temp.name) / "training.sqlite3"
        training = TrainingStore(training_path, DatasetProtector(b"d" * 32))
        self.addCleanup(training.close)
        service = self.make_service(
            test_sender_id=TEST_SENDER_ID, training_store=training
        )
        self.assertEqual(
            await service.handle(
                self.message(
                    10,
                    "dataset-private-canary",
                    facts=MessageFacts(
                        text="dataset-private-canary",
                        quote_text="quoted-private-canary",
                    ),
                ),
                FakeActions(),
            ),
            "would_challenge",
        )
        self.assertEqual(training.statistics()["total"], 1)
        sample = training.samples()[0]
        self.assertEqual(sample.payload["schema_version"], 2)
        self.assertEqual(sample.payload["quote_text"], "quoted-private-canary")
        self.assertTrue(sample.payload["features"]["has_quote"])
        self.assertNotIn(b"dataset-private-canary", training_path.read_bytes())
        await service.handle(
            self.message(11, "test-private-canary", sender_id=TEST_SENDER_ID),
            FakeActions(),
        )
        self.assertEqual(training.statistics()["total"], 1)
        self.assertEqual(
            self.store._connection.execute(
                "SELECT COUNT(*) FROM enforcement_reviews"
            ).fetchone()[0],
            0,
        )

    async def test_suppressed_sender_retains_encrypted_original_review_snapshot(
        self,
    ) -> None:
        self.store.set_mode("protect")
        facts = MessageFacts(text="original-private-canary", quote_text="quoted-private-canary")
        actions = FakeActions()
        self.assertEqual(
            await self.service.handle(
                self.message(1, "original-private-canary", facts=facts), actions
            ),
            "challenged",
        )
        self.assertEqual(
            await self.service.handle(
                self.message(2, "11", reply_to_message_id=100), actions
            ),
            "challenge_incorrect",
        )
        self.assertEqual(
            await self.service.handle(
                self.message(3, "10", reply_to_message_id=100), actions
            ),
            "suppressed",
        )
        sender_key = self.protector.sender_key(123456789)
        item = self.store.enforcement_review(sender_key, now=self.now)
        self.assertIsNotNone(item)
        payload = self.review_protector.open_enforcement(item.envelope)
        self.assertEqual(payload["text"], "original-private-canary")
        self.assertEqual(payload["quote_text"], "quoted-private-canary")
        database = self.database_path.read_bytes()
        self.assertNotIn(b"original-private-canary", database)
        self.assertNotIn(b"quoted-private-canary", database)

    async def test_successful_verification_erases_review_snapshot(self) -> None:
        self.store.set_mode("protect")
        actions = FakeActions()
        await self.service.handle(self.message(1, "private-canary"), actions)
        sender_key = self.protector.sender_key(123456789)
        raw_count = self.store._connection.execute(
            "SELECT COUNT(*) FROM enforcement_reviews"
        ).fetchone()[0]
        self.assertEqual(raw_count, 1)
        self.assertEqual(
            await self.service.handle(
                self.message(2, "12", reply_to_message_id=100), actions
            ),
            "provisional",
        )
        self.assertIsNone(self.store.enforcement_review(sender_key, now=self.now))
        raw_count = self.store._connection.execute(
            "SELECT COUNT(*) FROM enforcement_reviews"
        ).fetchone()[0]
        self.assertEqual(raw_count, 0)

    async def test_promotional_webpage_preview_is_challenged_in_protect_mode(
        self,
    ) -> None:
        self.store.set_mode("protect")
        actions = FakeActions()
        outcome = await self.service.handle(
            self.message(
                1,
                text="T.me/+invite",
                facts=MessageFacts(
                    text="T.me/+invite",
                    preview_text="汇盈社区 高返70% 合约跟单 免费跟单，交易所返佣",
                    urls=("https://t.me/+invite",),
                    domains=("t.me",),
                ),
            ),
            actions,
        )
        self.assertEqual(outcome, "challenged")
        self.assertEqual(actions.quarantines, 1)
        sender_key = self.protector.sender_key(123456789)
        self.assertEqual(self.store.sender(sender_key).status, "challenged")

    async def test_critical_rule_schedules_silent_persistent_delete(self) -> None:
        self.store.set_mode("protect")
        actions = FakeActions()
        outcome = await self.service.handle(
            self.message(
                1,
                facts=MessageFacts(has_link_button=True, link_button_count=2),
            ),
            actions,
        )
        sender_key = self.protector.sender_key(123456789)
        self.assertEqual(outcome, "suppressed")
        self.assertEqual(
            self.store.sender(sender_key).suppression_reason, "critical_rule"
        )
        self.assertEqual(actions.sent, [])
        self.assertEqual(actions.dialog_deletions, [(1, self.now)])
        self.assertEqual(len(self.store.pending_actions()), 1)

    async def test_expired_suppression_returns_sender_to_challenge(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        self.store.suppress(
            sender_key,
            "challenge_timeout",
            until=self.now + 10,
            reference=self.protector.seal_review_reference(123456789, 987654321, 1),
            now=self.now,
        )
        self.store.set_mode("protect")
        self.now += 11
        outcome = await self.service.handle(self.message(2), FakeActions())
        self.assertEqual(outcome, "challenged")
        self.assertEqual(self.store.sender(sender_key).status, "challenged")

    async def test_challenge_prompt_requires_reply_and_passes_to_provisional(
        self,
    ) -> None:
        self.store.set_mode("protect")
        actions = FakeActions()
        self.assertEqual(
            await self.service.handle(self.message(1), actions), "challenged"
        )
        prompt = actions.sent[0][0]
        self.assertIn("⚠️ Verification Required", prompt)
        self.assertIn("within 1 minute", prompt)
        self.assertIn("Answer: 7 + 5 = ?", prompt)
        self.assertIn("Attempts allowed: 2", prompt)
        self.assertIn("Long-press this message, choose Reply", prompt)
        formatted_fragments = {
            prompt[span.offset : span.offset + span.length]
            for span in actions.formattings[0]
        }
        self.assertEqual(
            formatted_fragments,
            {"⚠️ Verification Required", "1 minute", "7 + 5 = ?", "2"},
        )
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

    async def test_challenge_ttl_starts_after_prompt_delivery(self) -> None:
        self.store.set_mode("protect")
        actions = FakeActions()
        actions.after_send = lambda: setattr(self, "now", 1_010)
        self.assertEqual(
            await self.service.handle(self.message(1), actions), "challenged"
        )
        sender_key = self.protector.sender_key(123456789)
        self.assertEqual(self.store.sender(sender_key).challenge_expires_at, 1_070)
        self.assertEqual(actions.scheduled[0][1:], (1_070, 30))

    async def test_dedicated_test_sender_always_challenges_and_resets_after_pass(
        self,
    ) -> None:
        service = self.make_service(test_sender_id=TEST_SENDER_ID)
        actions = FakeActions()
        self.assertEqual(
            await service.handle(
                self.message(
                    1,
                    sender_id=TEST_SENDER_ID,
                    trusted=True,
                    is_contact=True,
                    facts=MessageFacts(
                        text="test",
                        has_link_button=True,
                        link_button_count=2,
                    ),
                ),
                actions,
            ),
            "challenged",
        )
        self.assertEqual(
            await service.handle(
                self.message(
                    2,
                    "12",
                    sender_id=TEST_SENDER_ID,
                    reply_to_message_id=100,
                ),
                actions,
            ),
            "provisional",
        )
        sender_key = self.protector.sender_key(TEST_SENDER_ID)
        self.assertEqual(actions.resets, [(sender_key, self.now, self.now + 60)])
        self.now += 60
        self.assertTrue(await service.reset_test_sender(sender_key, self.now - 60))
        self.assertEqual(self.store.sender(sender_key).status, "unknown")
        self.assertEqual(
            await service.handle(
                self.message(3, sender_id=TEST_SENDER_ID, trusted=True), actions
            ),
            "challenged",
        )

    async def test_dedicated_test_sender_wrong_answer_deletes_dialog_and_resets(
        self,
    ) -> None:
        service = self.make_service(test_sender_id=TEST_SENDER_ID)
        sender_key = self.set_active_challenge(sender_id=TEST_SENDER_ID)
        actions = FakeActions()
        self.assertEqual(
            await service.handle(
                self.message(
                    2,
                    "11",
                    sender_id=TEST_SENDER_ID,
                    reply_to_message_id=100,
                ),
                actions,
            ),
            "challenge_incorrect",
        )
        self.assertEqual(
            await service.handle(
                self.message(
                    3,
                    "10",
                    sender_id=TEST_SENDER_ID,
                    reply_to_message_id=100,
                ),
                actions,
            ),
            "quarantined",
        )
        self.assertEqual(actions.sent[-1][0], VERIFICATION_FAILED_TEXT)
        self.assertIn(
            "This conversation will be deleted in 10 seconds.",
            actions.sent[-1][0],
        )
        self.assertEqual(actions.deleted_dialogs, 0)
        self.assertEqual(actions.dialog_deletions, [(1, self.now + 10)])
        self.assertTrue(self.store.pending_actions()[0].mode_independent)
        self.assertEqual(actions.deletions, [])
        self.assertEqual(actions.resets, [(sender_key, self.now, self.now + 60)])

    async def test_dedicated_test_sender_bypasses_outbound_limit(self) -> None:
        service = self.make_service(outbound_limit=1, test_sender_id=TEST_SENDER_ID)
        self.store.claim_outbound_slot(1, self.now)
        outcome = await service.handle(
            self.message(1, sender_id=TEST_SENDER_ID), FakeActions()
        )
        self.assertEqual(outcome, "challenged")

    async def test_standalone_answer_does_not_consume_attempt_and_guides_once(
        self,
    ) -> None:
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
                self.message(message_id, "not an answer", reply_to_message_id=100),
                actions,
            )
            self.assertEqual(outcome, "challenge_pending")
        self.assertEqual(self.store.sender(sender_key).attempts, 0)
        self.assertEqual([text for text, _ in actions.sent], [DIGITS_REQUIRED_TEXT])
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

    async def test_correct_answer_deletes_the_complete_verification_flow(self) -> None:
        sender_key = self.set_active_challenge()
        self.store.record_automated_message(sender_key, 100, self.now)
        actions = FakeActions()
        actions.next_message_id = 102
        self.assertEqual(
            await self.service.handle(
                self.message(101, "11", reply_to_message_id=100), actions
            ),
            "challenge_incorrect",
        )
        self.assertEqual(
            await self.service.handle(
                self.message(103, "12", reply_to_message_id=100), actions
            ),
            "provisional",
        )
        self.assertEqual(actions.deleted_message_batches, [(100, 102, 103)])
        self.assertEqual(actions.deleted_dialogs, 0)

    async def test_signed_number_is_format_error_without_attempt(self) -> None:
        sender_key = self.set_active_challenge()
        outcome = await self.service.handle(
            self.message(2, "+12", reply_to_message_id=100), FakeActions()
        )
        self.assertEqual(outcome, "challenge_pending")
        self.assertEqual(self.store.sender(sender_key).attempts, 0)

    async def test_incorrect_answers_schedule_delayed_dialog_deletion(self) -> None:
        sender_key = self.set_active_challenge()
        actions = FakeActions()
        first = await self.service.handle(
            self.message(2, "11", reply_to_message_id=100), actions
        )
        second = await self.service.handle(
            self.message(3, "10", reply_to_message_id=100), actions
        )
        self.assertEqual((first, second), ("challenge_incorrect", "suppressed"))
        self.assertEqual(self.store.sender(sender_key).status, "suppressed")
        self.assertEqual(actions.quarantines, 0)
        self.assertEqual(actions.deleted_dialogs, 0)
        self.assertEqual(actions.dialog_deletions, [(1, self.now + 10)])
        self.assertEqual(actions.sent[-1][0], VERIFICATION_FAILED_TEXT)
        self.assertIn("1 attempt remaining", actions.sent[0][0])

    async def test_failed_warning_does_not_schedule_silent_dialog_deletion(
        self,
    ) -> None:
        sender_key = self.set_active_challenge()
        actions = FakeActions(send_success=False)
        await self.service.handle(
            self.message(2, "11", reply_to_message_id=100), actions
        )
        outcome = await self.service.handle(
            self.message(3, "10", reply_to_message_id=100), actions
        )
        self.assertEqual(outcome, "quarantined")
        self.assertEqual(self.store.sender(sender_key).status, "quarantined")
        self.assertEqual(actions.dialog_deletions, [])

    async def test_message_sent_before_deadline_can_pass_after_processing_delay(
        self,
    ) -> None:
        sender_key = self.set_active_challenge()
        self.now = 1_100
        outcome = await self.service.handle(
            self.message(2, "12", sent_at=1_059, reply_to_message_id=100),
            FakeActions(),
        )
        self.assertEqual(outcome, "provisional")
        self.assertEqual(self.store.sender(sender_key).status, "provisional")

    async def test_message_sent_after_deadline_is_suppressed(self) -> None:
        sender_key = self.set_active_challenge()
        outcome = await self.service.handle(
            self.message(2, "12", sent_at=1_061, reply_to_message_id=100),
            FakeActions(),
        )
        self.assertEqual(outcome, "suppressed")
        self.assertEqual(self.store.sender(sender_key).status, "suppressed")

    async def test_archive_failure_rolls_challenge_back(self) -> None:
        self.store.set_mode("protect")
        sender_key = self.protector.sender_key(123456789)
        actions = FakeActions(archive_success=False)
        outcome = await self.service.handle(self.message(1), actions)
        state = self.store.sender(sender_key)
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(state.status, "unknown")
        self.assertIsNone(state.challenge_message_id)
        self.assertEqual(actions.scheduled, [])
        self.assertEqual(actions.deleted_messages, [100])

    async def test_activation_error_restores_archive_before_reset(self) -> None:
        self.store.set_mode("protect")
        sender_key = self.protector.sender_key(123456789)
        actions = FakeActions()
        with patch.object(
            self.store, "activate_challenge", side_effect=RuntimeError("database")
        ):
            outcome = await self.service.handle(self.message(1), actions)
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(actions.restores, 1)
        self.assertEqual(self.store.sender(sender_key).status, "unknown")

    async def test_activation_error_keeps_recoverable_state_if_restore_fails(
        self,
    ) -> None:
        self.store.set_mode("protect")
        sender_key = self.protector.sender_key(123456789)
        actions = FakeActions(restore_success=False)
        with patch.object(
            self.store, "activate_challenge", side_effect=RuntimeError("database")
        ):
            outcome = await self.service.handle(self.message(1), actions)
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(actions.restores, 3)
        self.assertEqual(self.store.sender(sender_key).status, "challenge_archiving")

    async def test_send_failure_rolls_challenge_back(self) -> None:
        self.store.set_mode("protect")
        sender_key = self.protector.sender_key(123456789)
        outcome = await self.service.handle(
            self.message(1), FakeActions(send_success=False)
        )
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(self.store.sender(sender_key).status, "unknown")

    async def test_rate_limit_fallback_archives_and_enqueues_review(self) -> None:
        self.store.set_mode("protect")
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
        self.assertEqual(
            self.store.review_items(now=self.now)[0].classification,
            "challenge_unavailable",
        )

    async def test_rate_limit_archive_failure_stays_unknown_and_enqueues_review(
        self,
    ) -> None:
        self.store.set_mode("protect")
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
            self.store.review_items(now=self.now)[0].classification,
            "challenge_unavailable_action_failed",
        )

    async def test_provisional_sender_is_still_screened(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        self.store.mark_provisional(sender_key, self.now)
        self.store.set_mode("protect")
        outcome = await self.service.handle(
            self.message(
                1,
                facts=MessageFacts(has_link_button=True, link_button_count=2),
            ),
            FakeActions(),
        )
        self.assertEqual(outcome, "suppressed")

    async def test_owner_reply_promotes_provisional_sender(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        self.store.mark_provisional(sender_key, self.now)
        outcome = await self.service.handle(
            self.message(1, trusted=True), FakeActions()
        )
        self.assertEqual(outcome, "allowed")
        self.assertEqual(self.store.sender(sender_key).status, "allowed")

    async def test_same_sender_concurrency_issues_only_one_challenge(self) -> None:
        self.store.set_mode("protect")
        actions = FakeActions()
        actions.send_started = asyncio.Event()
        actions.release_send = asyncio.Event()
        first = asyncio.create_task(self.service.handle(self.message(1), actions))
        await actions.send_started.wait()
        second = asyncio.create_task(self.service.handle(self.message(2), actions))
        actions.release_send.set()
        outcomes = await asyncio.gather(first, second)
        prompts = [
            text
            for text, _ in actions.sent
            if text.startswith("⚠️ Verification Required")
        ]
        self.assertEqual(len(prompts), 1)
        self.assertEqual(outcomes[0], "challenged")
        self.assertEqual(outcomes[1], "challenge_pending")

    async def test_different_senders_can_issue_challenges_in_parallel(self) -> None:
        self.store.set_mode("protect")
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

    async def test_concurrent_correct_and_wrong_answers_cannot_requarantine(
        self,
    ) -> None:
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

    async def test_timeout_cancels_delete_after_mode_switch_to_monitor(self) -> None:
        sender_key = self.set_active_challenge()
        self.store.set_mode("monitor")
        self.assertTrue(
            await self.service.expire_challenge(
                sender_key, self.now + 60, now=self.now + 65
            )
        )
        self.assertEqual(self.store.sender(sender_key).status, "suppressed")

    async def test_dedicated_test_sender_timeout_uses_failure_cleanup(self) -> None:
        service = self.make_service(test_sender_id=TEST_SENDER_ID)
        sender_key = self.set_active_challenge(sender_id=TEST_SENDER_ID)
        actions = FakeActions()
        self.assertTrue(
            await service.expire_challenge(
                sender_key,
                self.now + 60,
                now=self.now + 65,
                actions=actions,
            )
        )
        self.assertEqual(actions.sent[-1][0], VERIFICATION_TIMEOUT_TEXT)
        self.assertEqual(actions.deletions, [(sender_key, self.now, self.now + 75)])
        self.assertEqual(actions.resets, [(sender_key, self.now + 65, self.now + 125)])

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

    async def test_expired_recovery_deletes_stale_prompt(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        digest = self.protector.answer_digest(sender_key, "challenge", "12")
        self.store.begin_challenge_issue(
            sender_key,
            "challenge",
            digest,
            self.now - 1,
            "⚠️ Verification Required",
            None,
            self.now - 60,
        )
        actions = FakeActions()
        self.assertFalse(
            await self.service.recover_incomplete_challenge(
                sender_key, actions, recovered_message_id=88
            )
        )
        self.assertEqual(actions.deleted_messages, [88])
        self.assertEqual(self.store.sender(sender_key).status, "unknown")

    async def test_restore_failure_keeps_active_challenge(self) -> None:
        sender_key = self.set_active_challenge()
        reference = self.protector.seal_review_reference(123456789, 456, 2)
        actions = FakeActions(restore_success=False)
        outcome = await self.service.handle(
            self.message(
                2,
                "12",
                reply_to_message_id=100,
                review_reference=reference,
            ),
            actions,
        )
        self.assertEqual(outcome, "fail_safe")
        self.assertEqual(self.store.sender(sender_key).status, "challenged")
        self.assertEqual(
            self.store.review_items(now=self.now)[0].classification, "restore_failed"
        )
        self.assertEqual(actions.restores, 3)

    async def test_failed_reply_guidance_can_retry(self) -> None:
        sender_key = self.set_active_challenge()
        actions = FakeActions(send_success=False)
        self.assertEqual(
            await self.service.handle(self.message(2, "12"), actions),
            "challenge_pending",
        )
        self.assertFalse(self.store.sender(sender_key).guidance_sent)
        actions.send_success = True
        self.assertEqual(
            await self.service.handle(self.message(3, "12"), actions),
            "challenge_pending",
        )
        self.assertTrue(self.store.sender(sender_key).guidance_sent)
        self.assertEqual([text for text, _ in actions.sent], [REPLY_REQUIRED_TEXT])

    async def test_duplicate_message_has_no_second_action(self) -> None:
        self.store.set_mode("protect")
        actions = FakeActions()
        await self.service.handle(self.message(1), actions)
        self.assertEqual(
            await self.service.handle(self.message(1), actions), "duplicate"
        )


if __name__ == "__main__":
    unittest.main()
