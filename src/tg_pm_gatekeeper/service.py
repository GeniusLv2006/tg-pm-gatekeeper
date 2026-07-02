from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
import unicodedata
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from .crypto import IdentifierProtector
from .rules import MessageFacts, evaluate_hard_rules
from .store import SenderState, StateStore


LOG = logging.getLogger("gatekeeper.service")
DIGITS_RE = re.compile(r"^[0-9]+$")
CHALLENGE_PROCESSING_GRACE_SECONDS = 30
RESTORE_RETRY_DELAYS_SECONDS = (0.0, 0.1, 0.5)
REPLY_REQUIRED_TEXT = (
    "Reply required\n\nLong-press the verification message, choose Reply, and "
    "send only the answer. No attempt was used."
)
DIGITS_REQUIRED_TEXT = (
    "Digits only\n\nReply with digits only. No attempt was used."
)
VERIFICATION_PASSED_TEXT = (
    "Verification passed\n\nThis conversation has been restored."
)
VERIFICATION_FAILED_TEXT = (
    "Verification failed\n\nThis conversation remains archived and muted."
)
TEST_MESSAGE_DELETE_DELAY_SECONDS = 10
TEST_STATE_RESET_DELAY_SECONDS = 60


class MessageActions(Protocol):
    async def send_text(
        self,
        text: str,
        *,
        reply_to_message_id: int | None = None,
        formatting: tuple["TextStyleSpan", ...] = (),
    ) -> int: ...
    async def archive_and_mute(self) -> bool: ...
    async def restore_from_pending(self) -> bool: ...
    async def delete_message(self, message_id: int) -> bool: ...
    def schedule_timeout(
        self, sender_key: str, expires_at: int, *, grace_seconds: int = 5
    ) -> None: ...
    def cancel_timeout(self, sender_key: str) -> None: ...
    def schedule_test_message_deletion(
        self, sender_key: str, since: int, delete_at: int
    ) -> None: ...
    def schedule_test_state_reset(
        self, sender_key: str, expected_updated_at: int, reset_at: int
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class IncomingMessage:
    sender_id: int
    message_id: int
    text: str
    facts: MessageFacts
    sent_at: int
    reply_to_message_id: int | None = None
    is_contact: bool = False
    is_bot: bool = False
    is_service: bool = False
    has_trusted_history: bool = False
    review_reference: bytes | None = None


@dataclass(frozen=True, slots=True)
class Challenge:
    challenge_id: str
    answer: str
    expression: str


@dataclass(frozen=True, slots=True)
class TextStyleSpan:
    offset: int
    length: int
    style: Literal["bold", "italic", "code"] = "bold"


def emphasized(text: str, *fragments: str) -> tuple[TextStyleSpan, ...]:
    spans: list[TextStyleSpan] = []
    search_from = 0
    for fragment in fragments:
        offset = text.index(fragment, search_from)
        spans.append(TextStyleSpan(offset, len(fragment)))
        search_from = offset + len(fragment)
    return tuple(spans)


def new_challenge(
    randbelow: Callable[[int], int] = secrets.randbelow,
    token_hex: Callable[[int], str] = secrets.token_hex,
) -> Challenge:
    operation = randbelow(3)
    if operation == 0:
        left = randbelow(24) + 2
        right = randbelow(24) + 2
        answer = left + right
        expression = f"{left} + {right} = ?"
    elif operation == 1:
        answer = randbelow(25) + 1
        right = randbelow(20) + 1
        left = answer + right
        expression = f"{left} - {right} = ?"
    else:
        left = randbelow(9) + 2
        right = randbelow(9) + 2
        answer = left * right
        expression = f"{left} × {right} = ?"
    return Challenge(token_hex(16), str(answer), expression)


def challenge_prompt(
    challenge: Challenge, ttl_seconds: int, max_attempts: int = 2
) -> str:
    if ttl_seconds == 60:
        duration = "1 minute"
    else:
        unit = "second" if ttl_seconds == 1 else "seconds"
        duration = f"{ttl_seconds} {unit}"
    attempts = str(max_attempts)
    return (
        "⚠️ Verification Required\n\n"
        f"Reply to this message within {duration}.\n\n"
        f"Answer: {challenge.expression}\n"
        f"Attempts allowed: {attempts}\n\n"
        "Long-press this message, choose Reply, and send digits only."
    )


def challenge_prompt_formatting(prompt: str) -> tuple[TextStyleSpan, ...]:
    lines = prompt.splitlines()
    if (
        len(lines) < 6
        or not lines[2].startswith("Reply to this message within ")
        or not lines[4].startswith("Answer: ")
        or not lines[5].startswith("Attempts allowed: ")
    ):
        return emphasized(prompt, lines[0]) if lines else ()
    duration = (
        lines[2].removeprefix("Reply to this message within ").removesuffix(".")
    )
    expression = lines[4].removeprefix("Answer: ")
    attempts = lines[5].removeprefix("Attempts allowed: ")
    return emphasized(
        prompt,
        "⚠️ Verification Required",
        duration,
        expression,
        attempts,
    )


def notice_formatting(text: str) -> tuple[TextStyleSpan, ...]:
    title = text.partition("\n")[0]
    return emphasized(text, title)


def canonical_answer(text: str) -> str | None:
    normalized = unicodedata.normalize("NFKC", text).strip()
    if not DIGITS_RE.fullmatch(normalized):
        return None
    return str(int(normalized))


class SenderLockPool:
    def __init__(self) -> None:
        self._locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    def lock(self, sender_key: str) -> asyncio.Lock:
        lock = self._locks.get(sender_key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[sender_key] = lock
        return lock


class GatekeeperService:
    def __init__(
        self,
        store: StateStore,
        protector: IdentifierProtector,
        *,
        challenge_ttl_seconds: int = 60,
        challenge_max_attempts: int = 2,
        outbound_limit_per_hour: int = 10,
        review_retention_days: int = 7,
        denylist: frozenset[str] = frozenset(),
        test_sender_id: int | None = None,
        challenge_factory=new_challenge,
        clock=lambda: int(time.time()),
    ) -> None:
        self.store = store
        self.protector = protector
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.challenge_max_attempts = challenge_max_attempts
        self.outbound_limit_per_hour = outbound_limit_per_hour
        self.review_retention_days = min(review_retention_days, 7)
        self.denylist = denylist
        self.test_sender_id = test_sender_id
        self.test_sender_key = (
            protector.sender_key(test_sender_id) if test_sender_id is not None else None
        )
        self.challenge_factory = challenge_factory
        self.clock = clock
        self.sender_locks = SenderLockPool()

    def sender_lock(self, sender_key: str) -> asyncio.Lock:
        return self.sender_locks.lock(sender_key)

    async def handle(self, message: IncomingMessage, actions: MessageActions) -> str:
        sender_key = self.protector.sender_key(message.sender_id)
        async with self.sender_lock(sender_key):
            return await self._handle_locked(sender_key, message, actions)

    async def _handle_locked(
        self, sender_key: str, message: IncomingMessage, actions: MessageActions
    ) -> str:
        now = self.clock()
        is_test_sender = sender_key == self.test_sender_key
        if not self.store.claim_message(sender_key, message.message_id, now):
            return "duplicate"

        outcome = "fail_safe"
        try:
            state = self.store.sender(sender_key)
            if is_test_sender and state.status == "allowed":
                self.store.revoke(sender_key, now)
                state = self.store.sender(sender_key)
            elif (
                is_test_sender
                and state.status in {"provisional", "quarantined"}
                and state.updated_at + TEST_STATE_RESET_DELAY_SECONDS <= now
            ):
                self.store.reset_test_sender(sender_key, state.updated_at, now)
                state = self.store.sender(sender_key)
            if not is_test_sender and (
                message.is_service or message.is_bot or message.is_contact
            ):
                self.store.allow(sender_key, now)
                self.store.audit(sender_key, "TRUSTED_SENDER", "allowed", now)
                outcome = "allowed"
                return outcome
            if state.status == "allowed":
                outcome = "allowed"
                return outcome
            if (
                not is_test_sender
                and state.status in {"unknown", "provisional"}
                and message.has_trusted_history
            ):
                self.store.allow(sender_key, now)
                self.store.audit(sender_key, "TRUSTED_HISTORY", "allowed", now)
                outcome = "allowed"
                return outcome
            if state.status == "quarantined":
                outcome = "already_quarantined"
                return outcome
            if state.status in {"challenge_issuing", "challenge_archiving"}:
                outcome = "challenge_starting"
                return outcome

            recent_links = self.store.recent_link_messages(sender_key, now=now)
            decision = evaluate_hard_rules(
                message.facts,
                previous_link_messages=recent_links,
                denylist=self.denylist,
            )
            if message.facts.has_link:
                self.store.record_link_message(sender_key, now)

            if decision.hard_spam and not is_test_sender:
                for rule in decision.rule_codes:
                    self.store.audit(sender_key, rule, "matched", now)
                if state.status == "challenged":
                    self.store.quarantine(sender_key, now)
                    actions.cancel_timeout(sender_key)
                    self.store.audit(sender_key, "hard_rule", "already_archived", now)
                    outcome = "quarantined"
                else:
                    outcome = await self._quarantine(
                        sender_key, actions, now, "hard_rule"
                    )
                if outcome == "would_quarantine":
                    self._enqueue_review(
                        sender_key, message, outcome, decision.rule_codes, now
                    )
                return outcome

            if state.status == "provisional":
                outcome = "provisional"
                return outcome
            if state.status == "challenged":
                outcome = await self._handle_challenge(
                    sender_key, state, message, actions, now
                )
                return outcome

            if self.store.get_mode() == "observe" and not is_test_sender:
                self.store.audit(sender_key, "CHALLENGE_REQUIRED", "observed", now)
                outcome = "would_challenge"
                self._enqueue_review(sender_key, message, outcome, (), now)
                return outcome

            outcome = await self._issue_challenge(sender_key, message, actions, now)
            return outcome
        except Exception:
            LOG.error("message_processing_failed")
            self.store.audit(sender_key, "FAIL_SAFE", "no_action", now)
            return "fail_safe"
        finally:
            self.store.finish_message(sender_key, message.message_id, outcome)

    async def _issue_challenge(
        self,
        sender_key: str,
        message: IncomingMessage,
        actions: MessageActions,
        now: int,
    ) -> str:
        if not self._claim_outbound_slot(sender_key, now):
            return await self._rate_limit_fallback(sender_key, message, actions, now)

        challenge = self.challenge_factory()
        prompt = challenge_prompt(
            challenge, self.challenge_ttl_seconds, self.challenge_max_attempts
        )
        expires_at = now + self.challenge_ttl_seconds
        digest = self.protector.answer_digest(
            sender_key, challenge.challenge_id, challenge.answer
        )
        self.store.begin_challenge_issue(
            sender_key,
            challenge.challenge_id,
            digest,
            expires_at,
            prompt,
            message.review_reference,
            now,
        )
        archive_confirmed = False
        challenge_message_id: int | None = None
        try:
            challenge_message_id = await actions.send_text(
                prompt,
                formatting=challenge_prompt_formatting(prompt),
            )
            self.store.record_automated_message(
                sender_key, challenge_message_id, self.clock()
            )
            sent_at = self.clock()
            expires_at = sent_at + self.challenge_ttl_seconds
            if not self.store.refresh_challenge_expiry(
                sender_key, expires_at, sent_at
            ):
                await actions.delete_message(challenge_message_id)
                self.store.reset_incomplete_challenge(sender_key, self.clock())
                self.store.audit(sender_key, "CHALLENGE_EXPIRY", "state_changed", now)
                return "fail_safe"
            if not self.store.bind_challenge_message(
                sender_key, challenge_message_id, self.clock()
            ):
                await actions.delete_message(challenge_message_id)
                self.store.reset_incomplete_challenge(sender_key, self.clock())
                self.store.audit(sender_key, "CHALLENGE_BIND", "state_changed", now)
                return "fail_safe"
            if not await actions.archive_and_mute():
                await actions.delete_message(challenge_message_id)
                self.store.reset_incomplete_challenge(sender_key, self.clock())
                actions.cancel_timeout(sender_key)
                self.store.audit(sender_key, "PENDING_QUARANTINE", "action_failed", now)
                return "fail_safe"
            archive_confirmed = True
            if not self.store.activate_challenge(sender_key, self.clock()):
                restored = await self._restore_with_retry(actions)
                if restored:
                    await actions.delete_message(challenge_message_id)
                    self.store.reset_incomplete_challenge(sender_key, self.clock())
                self.store.audit(sender_key, "CHALLENGE_ACTIVATE", "state_changed", now)
                return "fail_safe"
        except Exception:
            restored = False
            if archive_confirmed:
                restored = await self._restore_with_retry(actions)
            if not archive_confirmed or restored:
                if challenge_message_id is not None:
                    await actions.delete_message(challenge_message_id)
                self.store.reset_incomplete_challenge(sender_key, self.clock())
            actions.cancel_timeout(sender_key)
            rollback = "restored" if restored else "action_failed"
            self.store.audit(sender_key, "CHALLENGE_DELIVERY", rollback, now)
            return "fail_safe"

        self.store.audit(sender_key, "CHALLENGE_SENT", "archived_muted", now)
        actions.schedule_timeout(
            sender_key,
            expires_at,
            grace_seconds=CHALLENGE_PROCESSING_GRACE_SECONDS,
        )
        return "challenged"

    async def _rate_limit_fallback(
        self,
        sender_key: str,
        message: IncomingMessage,
        actions: MessageActions,
        now: int,
    ) -> str:
        self.store.audit(sender_key, "OUTBOUND_RATE_LIMIT", "suppressed", now)
        try:
            archived = await actions.archive_and_mute()
        except Exception:
            archived = False
        if archived:
            self.store.quarantine(sender_key, now)
            self.store.audit(
                sender_key, "CHALLENGE_UNAVAILABLE", "archived_muted", now
            )
            classification = "challenge_unavailable"
            outcome = "quarantined_rate_limited"
        else:
            self.store.audit(sender_key, "CHALLENGE_UNAVAILABLE", "action_failed", now)
            classification = "challenge_unavailable_action_failed"
            outcome = "fail_safe"
        self._enqueue_review(sender_key, message, classification, (), now)
        return outcome

    def _enqueue_review(
        self,
        sender_key: str,
        message: IncomingMessage,
        classification: str,
        rule_codes: tuple[str, ...],
        now: int,
    ) -> None:
        if message.review_reference is None:
            self.store.audit(sender_key, "REVIEW_REFERENCE", "unavailable", now)
            return
        facts = message.facts
        features = {
            "domain_count": min(len(set(facts.domains)), 2),
            "forwarded": facts.is_forwarded,
            "has_any_button": facts.has_any_button,
            "has_link": facts.has_link,
            "has_link_button": facts.has_link_button,
            "has_quote": bool(facts.quote_text),
            "link_button_count": min(facts.link_button_count, 3),
            "quote_url_count": min(len(set(facts.quote_urls)), 2),
            "url_count": min(len(set(facts.urls)), 2),
            "via_bot": facts.via_bot,
        }
        self.store.enqueue_review(
            sender_key,
            message.review_reference,
            classification,
            json.dumps(rule_codes, separators=(",", ":")),
            json.dumps(features, sort_keys=True, separators=(",", ":")),
            now + self.review_retention_days * 86400,
            now,
        )

    async def _handle_challenge(
        self,
        sender_key: str,
        state: SenderState,
        message: IncomingMessage,
        actions: MessageActions,
        now: int,
    ) -> str:
        expires_at = state.challenge_expires_at
        if not expires_at or message.sent_at > expires_at:
            self.store.quarantine(sender_key, now)
            self.store.audit(sender_key, "challenge_expired", "already_archived", now)
            actions.cancel_timeout(sender_key)
            await self._finalize_test_failure(sender_key, state, actions, now)
            return "quarantined"

        if message.reply_to_message_id != state.challenge_message_id:
            await self._send_guidance_once(
                sender_key,
                state,
                actions,
                REPLY_REQUIRED_TEXT,
                now,
                formatting=notice_formatting(REPLY_REQUIRED_TEXT),
            )
            self.store.audit(sender_key, "CHALLENGE_WRONG_REPLY_TARGET", "ignored", now)
            return "challenge_pending"

        answer = canonical_answer(message.text)
        if answer is None:
            await self._send_guidance_once(
                sender_key,
                state,
                actions,
                DIGITS_REQUIRED_TEXT,
                now,
                formatting=notice_formatting(DIGITS_REQUIRED_TEXT),
            )
            self.store.audit(sender_key, "CHALLENGE_NON_NUMERIC", "ignored", now)
            return "challenge_pending"

        actual = self.protector.answer_digest(
            sender_key, state.challenge_id or "", answer
        )
        if state.answer_digest and self.protector.matches(state.answer_digest, actual):
            if not await self._restore_with_retry(actions):
                self.store.audit(sender_key, "CHALLENGE_RESTORE", "action_failed", now)
                self._enqueue_review(sender_key, message, "restore_failed", (), now)
                return "fail_safe"
            self.store.mark_provisional(sender_key, now)
            self.store.audit(sender_key, "CHALLENGE_CORRECT", "provisional", now)
            actions.cancel_timeout(sender_key)
            await self._send_notice(
                sender_key,
                actions,
                VERIFICATION_PASSED_TEXT,
                now,
                reply_to_message_id=message.message_id,
                formatting=notice_formatting(VERIFICATION_PASSED_TEXT),
            )
            if sender_key == self.test_sender_key:
                actions.schedule_test_state_reset(
                    sender_key, now, now + TEST_STATE_RESET_DELAY_SECONDS
                )
            return "provisional"

        attempts = self.store.increment_attempts(sender_key, now)
        self.store.audit(sender_key, "CHALLENGE_INCORRECT", "rejected", now)
        if attempts >= self.challenge_max_attempts:
            self.store.quarantine(sender_key, now)
            self.store.audit(sender_key, "attempts_exhausted", "already_archived", now)
            actions.cancel_timeout(sender_key)
            await self._finalize_test_failure(sender_key, state, actions, now)
            return "quarantined"
        remaining = self.challenge_max_attempts - attempts
        noun = "attempt" if remaining == 1 else "attempts"
        incorrect_text = (
            "Incorrect answer\n\nReply to the same verification message with "
            f"digits only. {remaining} {noun} remaining."
        )
        await self._send_notice(
            sender_key,
            actions,
            incorrect_text,
            now,
            reply_to_message_id=state.challenge_message_id,
            formatting=emphasized(
                incorrect_text, "Incorrect answer", f"{remaining} {noun} remaining"
            ),
        )
        return "challenge_incorrect"

    async def _send_guidance_once(
        self,
        sender_key: str,
        state: SenderState,
        actions: MessageActions,
        text: str,
        now: int,
        *,
        formatting: tuple[TextStyleSpan, ...] = (),
    ) -> None:
        if state.guidance_sent:
            return
        sent = await self._send_notice(
            sender_key,
            actions,
            text,
            now,
            reply_to_message_id=state.challenge_message_id,
            formatting=formatting,
        )
        if sent:
            self.store.mark_challenge_guidance_sent(sender_key)

    async def _restore_with_retry(self, actions: MessageActions) -> bool:
        for delay in RESTORE_RETRY_DELAYS_SECONDS:
            if delay:
                await asyncio.sleep(delay)
            try:
                if await actions.restore_from_pending():
                    return True
            except Exception:
                pass
        return False

    async def _send_notice(
        self,
        sender_key: str,
        actions: MessageActions,
        text: str,
        now: int,
        *,
        reply_to_message_id: int | None = None,
        formatting: tuple[TextStyleSpan, ...] = (),
    ) -> bool:
        if not self._claim_outbound_slot(sender_key, now):
            self.store.audit(sender_key, "OUTBOUND_RATE_LIMIT", "suppressed", now)
            return False
        try:
            message_id = await actions.send_text(
                text,
                reply_to_message_id=reply_to_message_id,
                formatting=formatting,
            )
            self.store.record_automated_message(sender_key, message_id, self.clock())
            return True
        except Exception:
            self.store.audit(sender_key, "OUTBOUND_NOTICE", "action_failed", now)
            return False

    def _claim_outbound_slot(self, sender_key: str, now: int) -> bool:
        return sender_key == self.test_sender_key or self.store.claim_outbound_slot(
            self.outbound_limit_per_hour, now
        )

    async def _finalize_test_failure(
        self,
        sender_key: str,
        challenge_state: SenderState,
        actions: MessageActions,
        now: int,
    ) -> None:
        if sender_key != self.test_sender_key:
            return
        await self._send_notice(
            sender_key,
            actions,
            VERIFICATION_FAILED_TEXT,
            now,
            formatting=notice_formatting(VERIFICATION_FAILED_TEXT),
        )
        challenge_started_at = (
            challenge_state.challenge_expires_at - self.challenge_ttl_seconds
            if challenge_state.challenge_expires_at is not None
            else challenge_state.updated_at
        )
        actions.schedule_test_message_deletion(
            sender_key,
            challenge_started_at,
            now + TEST_MESSAGE_DELETE_DELAY_SECONDS,
        )
        actions.schedule_test_state_reset(
            sender_key, now, now + TEST_STATE_RESET_DELAY_SECONDS
        )

    async def expire_challenge(
        self,
        sender_key: str,
        expires_at: int,
        *,
        now: int | None = None,
        actions: MessageActions | None = None,
    ) -> bool:
        async with self.sender_lock(sender_key):
            timestamp = self.clock() if now is None else now
            state = self.store.sender(sender_key)
            expired = self.store.expire_challenge(sender_key, expires_at, timestamp)
            if expired:
                self.store.audit(
                    sender_key, "CHALLENGE_TIMEOUT", "already_archived", timestamp
                )
                if actions is not None:
                    await self._finalize_test_failure(
                        sender_key, state, actions, timestamp
                    )
            return expired

    async def reset_test_sender(
        self, sender_key: str, expected_updated_at: int, *, now: int | None = None
    ) -> bool:
        if sender_key != self.test_sender_key:
            return False
        async with self.sender_lock(sender_key):
            timestamp = self.clock() if now is None else now
            reset = self.store.reset_test_sender(
                sender_key, expected_updated_at, timestamp
            )
            if reset:
                self.store.audit(sender_key, "TEST_STATE_RESET", "unknown", timestamp)
            return reset

    async def recover_incomplete_challenge(
        self,
        sender_key: str,
        actions: MessageActions,
        *,
        recovered_message_id: int | None = None,
    ) -> bool:
        async with self.sender_lock(sender_key):
            now = self.clock()
            state = self.store.sender(sender_key)
            if state.status not in {"challenge_issuing", "challenge_archiving"}:
                return False
            if not state.challenge_expires_at or state.challenge_expires_at <= now:
                stale_message_id = recovered_message_id or state.challenge_message_id
                if stale_message_id is not None:
                    await actions.delete_message(stale_message_id)
                self.store.reset_incomplete_challenge(sender_key, now)
                self.store.audit(sender_key, "CHALLENGE_RECOVERY", "expired_reset", now)
                return False
            if state.status == "challenge_issuing":
                message_id = recovered_message_id
                if message_id is None:
                    if not state.challenge_prompt:
                        self.store.reset_incomplete_challenge(sender_key, now)
                        return False
                    try:
                        message_id = await actions.send_text(
                            state.challenge_prompt,
                            formatting=challenge_prompt_formatting(
                                state.challenge_prompt
                            ),
                        )
                    except Exception:
                        self.store.reset_incomplete_challenge(sender_key, now)
                        self.store.audit(
                            sender_key, "CHALLENGE_RECOVERY", "send_failed", now
                        )
                        return False
                self.store.record_automated_message(sender_key, message_id, now)
                refreshed_expiry = now + self.challenge_ttl_seconds
                if not self.store.refresh_challenge_expiry(
                    sender_key, refreshed_expiry, now
                ):
                    await actions.delete_message(message_id)
                    self.store.reset_incomplete_challenge(sender_key, now)
                    self.store.audit(
                        sender_key, "CHALLENGE_RECOVERY", "expiry_failed", now
                    )
                    return False
                if not self.store.bind_challenge_message(sender_key, message_id, now):
                    await actions.delete_message(message_id)
                    self.store.reset_incomplete_challenge(sender_key, now)
                    self.store.audit(
                        sender_key, "CHALLENGE_RECOVERY", "bind_failed", now
                    )
                    return False
            else:
                message_id = state.challenge_message_id
            if not await actions.archive_and_mute():
                if message_id is not None:
                    await actions.delete_message(message_id)
                self.store.reset_incomplete_challenge(sender_key, now)
                self.store.audit(
                    sender_key, "CHALLENGE_RECOVERY", "archive_failed", now
                )
                return False
            if not self.store.activate_challenge(sender_key, now):
                restored = await self._restore_with_retry(actions)
                if restored:
                    if message_id is not None:
                        await actions.delete_message(message_id)
                    self.store.reset_incomplete_challenge(sender_key, now)
                self.store.audit(
                    sender_key, "CHALLENGE_RECOVERY", "activate_failed", now
                )
                return False
            refreshed = self.store.sender(sender_key)
            actions.schedule_timeout(
                sender_key, refreshed.challenge_expires_at or now, grace_seconds=30
            )
            self.store.audit(sender_key, "CHALLENGE_RECOVERY", "activated", now)
            return True

    async def abandon_incomplete_challenge(self, sender_key: str, reason: str) -> None:
        async with self.sender_lock(sender_key):
            now = self.clock()
            if self.store.reset_incomplete_challenge(sender_key, now):
                self.store.audit(sender_key, "CHALLENGE_RECOVERY", reason, now)

    async def _quarantine(
        self, sender_key: str, actions: MessageActions, now: int, reason: str
    ) -> str:
        if self.store.get_mode() == "observe":
            self.store.audit(sender_key, reason, "observed", now)
            return "would_quarantine"
        success = await actions.archive_and_mute()
        if success:
            self.store.quarantine(sender_key, now)
            self.store.audit(sender_key, reason, "archived_muted", now)
            actions.cancel_timeout(sender_key)
            return "quarantined"
        self.store.audit(sender_key, reason, "action_failed", now)
        return "fail_safe"
