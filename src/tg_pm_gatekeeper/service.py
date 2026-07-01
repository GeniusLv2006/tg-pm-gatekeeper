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
from typing import Protocol

from .crypto import IdentifierProtector
from .rules import MessageFacts, evaluate_hard_rules
from .store import SenderState, StateStore


LOG = logging.getLogger("gatekeeper.service")
DIGITS_RE = re.compile(r"^[0-9]+$")
CHALLENGE_PROCESSING_GRACE_SECONDS = 5
REPLY_REQUIRED_TEXT = (
    "Please use Telegram's Reply action on the verification message, then send "
    "only the answer. This did not use an attempt."
)
DIGITS_REQUIRED_TEXT = "Reply with digits only. This did not use an attempt."
VERIFICATION_PASSED_TEXT = (
    "Verification passed. This conversation has been restored."
)


class MessageActions(Protocol):
    async def send_text(
        self, text: str, *, reply_to_message_id: int | None = None
    ) -> int: ...
    async def archive_and_mute(self) -> bool: ...
    async def restore_from_pending(self) -> bool: ...
    def schedule_timeout(
        self, sender_key: str, expires_at: int, *, grace_seconds: int = 5
    ) -> None: ...
    def cancel_timeout(self, sender_key: str) -> None: ...


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


def challenge_prompt(challenge: Challenge, ttl_seconds: int) -> str:
    if ttl_seconds == 60:
        duration = "1 minute"
    else:
        unit = "second" if ttl_seconds == 1 else "seconds"
        duration = f"{ttl_seconds} {unit}"
    return (
        "Verification required\n\n"
        f"Please reply directly to this message within {duration} using Telegram's "
        "Reply action.\n"
        f"Send only the answer: {challenge.expression}\n"
        "A separate message will not be accepted."
    )


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
        if not self.store.claim_message(sender_key, message.message_id, now):
            return "duplicate"

        outcome = "fail_safe"
        try:
            state = self.store.sender(sender_key)
            if message.is_service or message.is_bot or message.is_contact:
                self.store.allow(sender_key, now)
                self.store.audit(sender_key, "TRUSTED_SENDER", "allowed", now)
                outcome = "allowed"
                return outcome
            if state.status == "allowed":
                outcome = "allowed"
                return outcome
            if state.status in {"unknown", "provisional"} and message.has_trusted_history:
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

            if decision.hard_spam:
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

            if self.store.get_mode() == "observe":
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
        if not self.store.claim_outbound_slot(self.outbound_limit_per_hour, now):
            return await self._rate_limit_fallback(sender_key, message, actions, now)

        challenge = self.challenge_factory()
        prompt = challenge_prompt(challenge, self.challenge_ttl_seconds)
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
        try:
            challenge_message_id = await actions.send_text(prompt)
            self.store.record_automated_message(
                sender_key, challenge_message_id, self.clock()
            )
            if not self.store.bind_challenge_message(
                sender_key, challenge_message_id, self.clock()
            ):
                self.store.reset_incomplete_challenge(sender_key, self.clock())
                self.store.audit(sender_key, "CHALLENGE_BIND", "state_changed", now)
                return "fail_safe"
            if not await actions.archive_and_mute():
                self.store.reset_incomplete_challenge(sender_key, self.clock())
                actions.cancel_timeout(sender_key)
                self.store.audit(sender_key, "PENDING_QUARANTINE", "action_failed", now)
                return "fail_safe"
            archive_confirmed = True
            if not self.store.activate_challenge(sender_key, self.clock()):
                self.store.audit(sender_key, "CHALLENGE_ACTIVATE", "state_changed", now)
                return "fail_safe"
        except Exception:
            restored = False
            if archive_confirmed:
                try:
                    restored = await actions.restore_from_pending()
                except Exception:
                    restored = False
            if not archive_confirmed or restored:
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
            return "quarantined"

        if message.reply_to_message_id != state.challenge_message_id:
            await self._send_guidance_once(
                sender_key, state, actions, REPLY_REQUIRED_TEXT, now
            )
            self.store.audit(sender_key, "CHALLENGE_WRONG_REPLY_TARGET", "ignored", now)
            return "challenge_pending"

        answer = canonical_answer(message.text)
        if answer is None:
            await self._send_notice(
                sender_key,
                actions,
                DIGITS_REQUIRED_TEXT,
                now,
                reply_to_message_id=state.challenge_message_id,
            )
            self.store.audit(sender_key, "CHALLENGE_NON_NUMERIC", "ignored", now)
            return "challenge_pending"

        actual = self.protector.answer_digest(
            sender_key, state.challenge_id or "", answer
        )
        if state.answer_digest and self.protector.matches(state.answer_digest, actual):
            if not await actions.restore_from_pending():
                self.store.audit(sender_key, "CHALLENGE_RESTORE", "action_failed", now)
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
            )
            return "provisional"

        attempts = self.store.increment_attempts(sender_key, now)
        self.store.audit(sender_key, "CHALLENGE_INCORRECT", "rejected", now)
        if attempts >= self.challenge_max_attempts:
            self.store.quarantine(sender_key, now)
            self.store.audit(sender_key, "attempts_exhausted", "already_archived", now)
            actions.cancel_timeout(sender_key)
            return "quarantined"
        remaining = self.challenge_max_attempts - attempts
        noun = "attempt" if remaining == 1 else "attempts"
        await self._send_notice(
            sender_key,
            actions,
            "Incorrect answer. Reply to the same verification message with digits "
            f"only. {remaining} {noun} remaining.",
            now,
            reply_to_message_id=state.challenge_message_id,
        )
        return "challenge_incorrect"

    async def _send_guidance_once(
        self,
        sender_key: str,
        state: SenderState,
        actions: MessageActions,
        text: str,
        now: int,
    ) -> None:
        if state.guidance_sent or not self.store.claim_challenge_guidance(sender_key):
            return
        await self._send_notice(
            sender_key,
            actions,
            text,
            now,
            reply_to_message_id=state.challenge_message_id,
        )

    async def _send_notice(
        self,
        sender_key: str,
        actions: MessageActions,
        text: str,
        now: int,
        *,
        reply_to_message_id: int | None = None,
    ) -> bool:
        if not self.store.claim_outbound_slot(self.outbound_limit_per_hour, now):
            self.store.audit(sender_key, "OUTBOUND_RATE_LIMIT", "suppressed", now)
            return False
        try:
            message_id = await actions.send_text(
                text, reply_to_message_id=reply_to_message_id
            )
            self.store.record_automated_message(sender_key, message_id, self.clock())
            return True
        except Exception:
            self.store.audit(sender_key, "OUTBOUND_NOTICE", "action_failed", now)
            return False

    async def expire_challenge(
        self, sender_key: str, expires_at: int, *, now: int | None = None
    ) -> bool:
        async with self.sender_lock(sender_key):
            timestamp = self.clock() if now is None else now
            expired = self.store.expire_challenge(sender_key, expires_at, timestamp)
            if expired:
                self.store.audit(
                    sender_key, "CHALLENGE_TIMEOUT", "already_archived", timestamp
                )
            return expired

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
                        message_id = await actions.send_text(state.challenge_prompt)
                    except Exception:
                        self.store.reset_incomplete_challenge(sender_key, now)
                        self.store.audit(
                            sender_key, "CHALLENGE_RECOVERY", "send_failed", now
                        )
                        return False
                self.store.record_automated_message(sender_key, message_id, now)
                if not self.store.bind_challenge_message(sender_key, message_id, now):
                    return False
            if not await actions.archive_and_mute():
                self.store.reset_incomplete_challenge(sender_key, now)
                self.store.audit(
                    sender_key, "CHALLENGE_RECOVERY", "archive_failed", now
                )
                return False
            if not self.store.activate_challenge(sender_key, now):
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
