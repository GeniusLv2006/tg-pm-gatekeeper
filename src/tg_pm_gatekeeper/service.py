from __future__ import annotations

import logging
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Protocol

from .crypto import IdentifierProtector
from .rules import MessageFacts, evaluate_hard_rules
from .store import StateStore


LOG = logging.getLogger("gatekeeper.service")
INTEGER_RE = re.compile(r"^[+-]?\d{1,6}$")


class MessageActions(Protocol):
    async def send_text(self, text: str) -> None: ...
    async def archive_and_mute(self) -> bool: ...
    async def restore_from_pending(self) -> bool: ...
    def schedule_timeout(self, sender_key: str, expires_at: int) -> None: ...
    def cancel_timeout(self, sender_key: str) -> None: ...


@dataclass(frozen=True, slots=True)
class IncomingMessage:
    sender_id: int
    message_id: int
    text: str
    facts: MessageFacts
    is_contact: bool = False
    is_bot: bool = False
    is_service: bool = False
    has_trusted_history: bool = False
    review_reference: bytes | None = None


@dataclass(frozen=True, slots=True)
class Challenge:
    challenge_id: str
    answer: str
    prompt: str


def new_challenge() -> Challenge:
    left = secrets.randbelow(17) + 2
    right = secrets.randbelow(17) + 2
    challenge_id = secrets.token_hex(16)
    return Challenge(
        challenge_id,
        str(left + right),
        f"To filter spam, please reply within 1 minute with only the answer: {left} + {right} = ?",
    )


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

    async def handle(self, message: IncomingMessage, actions: MessageActions) -> str:
        now = self.clock()
        sender_key = self.protector.sender_key(message.sender_id)
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
            if state.status == "unknown" and message.has_trusted_history:
                self.store.allow(sender_key, now)
                self.store.audit(sender_key, "TRUSTED_HISTORY", "allowed", now)
                outcome = "allowed"
                return outcome
            if state.status == "quarantined":
                outcome = "already_quarantined"
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
                outcome = await self._quarantine(sender_key, actions, now, "hard_rule")
                if outcome == "would_quarantine":
                    self._enqueue_review(
                        sender_key,
                        message,
                        outcome,
                        decision.rule_codes,
                        now,
                    )
                return outcome

            if state.status == "challenged":
                outcome = await self._handle_challenge(
                    sender_key, state, message.text, actions, now
                )
                return outcome

            if self.store.get_mode() == "observe":
                self.store.audit(sender_key, "CHALLENGE_REQUIRED", "observed", now)
                outcome = "would_challenge"
                self._enqueue_review(sender_key, message, outcome, (), now)
                return outcome

            challenge = self.challenge_factory()
            expires_at = now + self.challenge_ttl_seconds
            digest = self.protector.answer_digest(
                sender_key, challenge.challenge_id, challenge.answer
            )
            if not await self._send_if_allowed(
                sender_key, actions, challenge.prompt, now
            ):
                outcome = "outbound_rate_limited"
                return outcome
            self.store.set_challenge(
                sender_key, challenge.challenge_id, digest, expires_at, now
            )
            self.store.audit(sender_key, "CHALLENGE_SENT", "sent", now)
            actions.schedule_timeout(sender_key, expires_at)
            if not await actions.archive_and_mute():
                self.store.audit(sender_key, "PENDING_QUARANTINE", "action_failed", now)
                outcome = "fail_safe"
                return outcome
            self.store.audit(sender_key, "PENDING_QUARANTINE", "archived_muted", now)
            outcome = "challenged"
            return outcome
        except Exception:
            LOG.error("message_processing_failed")
            self.store.audit(sender_key, "FAIL_SAFE", "no_action", now)
            return "fail_safe"
        finally:
            self.store.finish_message(sender_key, message.message_id, outcome)

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
        self, sender_key, state, text, actions, now: int
    ) -> str:
        if not state.challenge_expires_at or state.challenge_expires_at <= now:
            return await self._quarantine(sender_key, actions, now, "challenge_expired")
        answer = text.strip()
        valid_shape = bool(INTEGER_RE.fullmatch(answer))
        if not valid_shape:
            self.store.audit(sender_key, "CHALLENGE_NON_NUMERIC", "ignored", now)
            return "challenge_pending"
        actual = self.protector.answer_digest(
            sender_key, state.challenge_id or "", answer
        )
        if (
            valid_shape
            and state.answer_digest
            and self.protector.matches(state.answer_digest, actual)
        ):
            if not await actions.restore_from_pending():
                self.store.audit(sender_key, "CHALLENGE_RESTORE", "action_failed", now)
                return "fail_safe"
            self.store.allow(sender_key, now)
            self.store.audit(sender_key, "CHALLENGE_CORRECT", "allowed", now)
            actions.cancel_timeout(sender_key)
            await self._send_if_allowed(
                sender_key,
                actions,
                "Verification passed. Future messages will be allowed.",
                now,
            )
            return "allowed"
        attempts = self.store.increment_attempts(sender_key, now)
        self.store.audit(sender_key, "CHALLENGE_INCORRECT", "rejected", now)
        if attempts >= self.challenge_max_attempts:
            return await self._quarantine(
                sender_key, actions, now, "attempts_exhausted"
            )
        await self._send_if_allowed(
            sender_key,
            actions,
            f"Incorrect answer. {self.challenge_max_attempts - attempts} attempt remaining.",
            now,
        )
        return "challenge_incorrect"

    async def _send_if_allowed(self, sender_key, actions, text: str, now: int) -> bool:
        if not self.store.claim_outbound_slot(self.outbound_limit_per_hour, now):
            self.store.audit(sender_key, "OUTBOUND_RATE_LIMIT", "suppressed", now)
            return False
        await actions.send_text(text)
        return True

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
