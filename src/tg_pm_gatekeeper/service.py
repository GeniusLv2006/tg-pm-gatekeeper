# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

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
from .evidence import EvidenceProtector, EvidenceStore
from .policy import DetectionResult, PolicyEngine
from .rules import MessageFacts, evaluate_hard_rules, url_evidence, url_shape
from .store import SenderState, StateStore


LOG = logging.getLogger("gatekeeper.service")
DIGITS_RE = re.compile(r"^[0-9]+$")
CHALLENGE_PROCESSING_GRACE_SECONDS = 30
RESTORE_RETRY_DELAYS_SECONDS = (0.0, 0.1, 0.5)
REPLY_REQUIRED_TEXT = (
    "↩️ Reply Required\n\nLong-press the verification message, choose Reply, and "
    "send only the answer. No attempt was used."
)
DIGITS_REQUIRED_TEXT = "🔢 Digits Only\n\nReply with digits only. No attempt was used."
VERIFICATION_PASSED_TEXT = (
    "✅ Verification Passed\n\nThis conversation has been restored."
)
VERIFICATION_FAILED_TEXT = (
    "⛔ Verification Failed\n\nThis conversation remains archived and muted.\n\n"
    "This conversation will be deleted in 10 seconds. New messages will be removed "
    "for 7 days."
)
VERIFICATION_TIMEOUT_TEXT = (
    "⛔ Verification Failed\n\nThe verification window expired.\n\n"
    "This conversation will be deleted in 10 seconds. Try again in 24 hours."
)
TEST_VERIFICATION_FAILED_TEXT = (
    "⛔ Verification Failed\n\nThis test conversation remains archived and muted.\n\n"
    "This conversation will be deleted in 10 seconds. The test sender will reset "
    "after 60 seconds."
)
TEST_VERIFICATION_TIMEOUT_TEXT = (
    "⛔ Verification Failed\n\nThe verification window expired.\n\n"
    "Messages recorded for this test challenge will be deleted in 10 seconds. "
    "The conversation will remain archived and muted, and the test sender will reset "
    "after 60 seconds."
)
FAILED_DIALOG_DELETE_DELAY_SECONDS = 10
TEST_MESSAGE_DELETE_DELAY_SECONDS = 10
TEST_STATE_RESET_DELAY_SECONDS = 60
MAX_EVIDENCE_BUTTON_TEXTS = 10


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
    async def delete_messages(self, message_ids: tuple[int, ...]) -> bool: ...
    async def delete_dialog(self) -> bool: ...
    def schedule_timeout(
        self, sender_key: str, expires_at: int, *, grace_seconds: int = 5
    ) -> None: ...
    def cancel_timeout(self, sender_key: str) -> None: ...
    def schedule_test_message_deletion(
        self, sender_key: str, since: int, delete_at: int
    ) -> None: ...
    def schedule_dialog_deletion(self, action_id: int, delete_at: int) -> None: ...
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
    duration = lines[2].removeprefix("Reply to this message within ").removesuffix(".")
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
        evidence_store: EvidenceStore | None = None,
        review_content_protector: EvidenceProtector | None = None,
        evidence_collection: bool = True,
        evidence_retention_days: int = 30,
        evidence_max_records_per_sender: int = 3,
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
        self.evidence_store = evidence_store
        self.review_content_protector = review_content_protector
        self.evidence_collection = evidence_collection
        self.evidence_retention_days = evidence_retention_days
        self.evidence_max_records_per_sender = evidence_max_records_per_sender
        self.policy = PolicyEngine()
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
            if state.status == "suppressed":
                if state.suppressed_until is not None and state.suppressed_until <= now:
                    self.store.release_expired_suppression(sender_key, now)
                    state = self.store.sender(sender_key)
                elif not is_test_sender:
                    if self.store.get_mode() == "monitor":
                        outcome = "would_delete_suppressed"
                        return outcome
                    outcome = self._schedule_suppressed_delete(
                        sender_key, state, message, actions, now
                    )
                    return outcome
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

            detection = decision.detection_result()
            policy = self.policy.decide(detection)
            evidence_id: int | None = None
            if state.status == "unknown" and not is_test_sender:
                evidence_id = self._collect_evidence(
                    message, detection, policy.planned_action, now
                )

            if decision.severity == "critical" and not is_test_sender:
                for rule in decision.rule_codes:
                    self.store.audit(sender_key, rule, "matched", now)
                if self.store.get_mode() == "monitor":
                    outcome = "would_delete"
                    self._enqueue_review(
                        sender_key, message, outcome, decision.rule_codes, now
                    )
                    if evidence_id is not None:
                        self._update_evidence_action(
                            evidence_id,
                            automatic_hint="spam_candidate",
                            actual_action=outcome,
                        )
                else:
                    self._capture_enforcement_review(
                        sender_key,
                        message,
                        reason="critical_rule",
                        rule_codes=decision.rule_codes,
                        now=now,
                    )
                    outcome = self._schedule_critical_delete(
                        sender_key, message, actions, now
                    )
                    if evidence_id is not None:
                        self._update_evidence_action(
                            evidence_id,
                            automatic_hint="spam_candidate",
                            actual_action=outcome,
                        )
                self._record_decision(
                    sender_key, detection, policy.planned_action, outcome, now
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

            if self.store.get_mode() == "monitor" and not is_test_sender:
                self.store.audit(sender_key, "CHALLENGE_REQUIRED", "observed", now)
                outcome = "would_challenge"
                self._enqueue_review(sender_key, message, outcome, (), now)
                if evidence_id is not None:
                    self._update_evidence_action(
                        evidence_id,
                        automatic_hint="uncertain",
                        actual_action=outcome,
                    )
                self._record_decision(
                    sender_key, detection, policy.planned_action, outcome, now
                )
                return outcome

            outcome = await self._issue_challenge(sender_key, message, actions, now)
            if evidence_id is not None:
                self._update_evidence_action(
                    evidence_id,
                    automatic_hint="uncertain",
                    actual_action=outcome,
                )
            self._record_decision(
                sender_key, detection, policy.planned_action, outcome, now
            )
            return outcome
        except Exception:
            LOG.error("message_processing_failed")
            self.store.audit(sender_key, "FAIL_SAFE", "no_action", now)
            return "fail_safe"
        finally:
            self.store.finish_message(sender_key, message.message_id, outcome)

    def _collect_evidence(
        self,
        message: IncomingMessage,
        detection: DetectionResult,
        planned_action: str,
        now: int,
    ) -> int | None:
        if self.evidence_store is None or not self.evidence_collection:
            return None
        facts = message.facts
        has_content = bool(
            message.text.strip()
            or facts.quote_text.strip()
            or facts.preview_text.strip()
        )
        if not has_content and not detection.signals:
            try:
                self.evidence_store.record_no_signal(now)
            except Exception:
                LOG.error("evidence_collection_failed")
                self.store.audit(
                    self.protector.sender_key(message.sender_id),
                    "EVIDENCE_COLLECTION",
                    "action_failed",
                    now,
                )
            return None
        payload = self._evidence_payload(
            message,
            detection=detection,
            planned_action=planned_action,
            actual_action="pending",
        )
        try:
            result = self.evidence_store.collect(
                sender_id=message.sender_id,
                message_id=message.message_id,
                payload=payload,
                automatic_hint="uncertain",
                retention_days=self.evidence_retention_days,
                max_per_sender=self.evidence_max_records_per_sender,
                sample_kind="content" if has_content else "structural",
                now=now,
            )
            return result.record_id
        except Exception:
            LOG.error("evidence_collection_failed")
            self.store.audit(
                self.protector.sender_key(message.sender_id),
                "EVIDENCE_COLLECTION",
                "action_failed",
                now,
            )
        return None

    def _evidence_payload(
        self,
        message: IncomingMessage,
        *,
        detection: DetectionResult | None = None,
        planned_action: str | None = None,
        actual_action: str | None = None,
        rule_codes: tuple[str, ...] = (),
    ) -> dict[str, object]:
        facts = message.facts
        signals = list(detection.signals if detection is not None else rule_codes)
        return {
            "schema_version": 4,
            "text": message.text,
            "quote_text": facts.quote_text,
            "preview_text": facts.preview_text,
            "button_texts": list(facts.button_texts[:MAX_EVIDENCE_BUTTON_TEXTS]),
            "urls": url_evidence(
                facts.urls,
                button_urls=facts.button_urls,
                preview_urls=facts.preview_urls,
            ),
            "quote_urls": url_evidence(facts.quote_urls),
            "domains": list(sorted(set(facts.domains))[:3]),
            "quote_domains": list(sorted(set(facts.quote_domains))[:3]),
            "url_shape": url_shape(facts.urls),
            "quote_url_shape": url_shape(facts.quote_urls),
            "features": {
                "button_text_count": min(len(set(facts.button_texts)), 10),
                "domain_count": min(len(set(facts.domains)), 2),
                "forwarded": facts.is_forwarded,
                "has_any_button": facts.has_any_button,
                "has_link": facts.has_link,
                "has_link_button": facts.has_link_button,
                "has_preview_text": bool(facts.preview_text),
                "has_quote": bool(facts.quote_text),
                "link_button_count": min(facts.link_button_count, 3),
                "quote_url_count": min(len(set(facts.quote_urls)), 2),
                "url_count": min(len(set(facts.urls)), 2),
                "via_bot": facts.via_bot,
            },
            "detector": detection.detector if detection is not None else "hard_rules",
            "signals": signals,
            "severity": detection.severity if detection is not None else None,
            "score": detection.score if detection is not None else None,
            "model_version": detection.model_version if detection is not None else None,
            "planned_action": planned_action,
            "actual_action": actual_action,
            "policy_version": "rules-v2",
        }

    def _capture_enforcement_review(
        self,
        sender_key: str,
        message: IncomingMessage,
        *,
        reason: str,
        rule_codes: tuple[str, ...] = (),
        now: int,
    ) -> None:
        if (
            self.review_content_protector is None
            or sender_key == self.test_sender_key
        ):
            return
        payload = self._evidence_payload(
            message,
            planned_action=None,
            actual_action="active_case",
            rule_codes=rule_codes,
        )
        payload["rule_codes"] = list(rule_codes)
        try:
            envelope = self.review_content_protector.seal_enforcement(payload)
            self.store.save_enforcement_review(
                sender_key,
                reference=message.review_reference,
                envelope=envelope,
                reason=reason,
                expires_at=now + self.review_retention_days * 86400,
                now=now,
            )
        except Exception:
            LOG.error("enforcement_review_capture_failed")
            try:
                self.store.audit(
                    sender_key, "ENFORCEMENT_REVIEW", "action_failed", now
                )
            except Exception:
                pass

    def _activate_enforcement_review(
        self,
        sender_key: str,
        reason: str,
        now: int,
        *,
        reference: bytes | None = None,
    ) -> None:
        try:
            self.store.activate_enforcement_review(
                sender_key,
                reason,
                now + self.review_retention_days * 86400,
                reference=reference,
                now=now,
            )
        except Exception:
            LOG.error("enforcement_review_activation_failed")
            try:
                self.store.audit(
                    sender_key, "ENFORCEMENT_REVIEW", "action_failed", now
                )
            except Exception:
                pass

    def _update_evidence_action(
        self, evidence_id: int, *, automatic_hint: str, actual_action: str
    ) -> None:
        if self.evidence_store is None:
            return
        try:
            self.evidence_store.update_record_action(
                evidence_id,
                automatic_hint=automatic_hint,
                actual_action=actual_action,
            )
        except Exception:
            LOG.error("evidence_update_failed")

    def _finalize_challenged_evidence(
        self, sender_id: int, *, automatic_hint: str, actual_action: str
    ) -> None:
        if self.evidence_store is None:
            return
        try:
            self.evidence_store.finalize_challenged_record(
                sender_id,
                automatic_hint=automatic_hint,
                actual_action=actual_action,
            )
        except Exception:
            LOG.error("evidence_update_failed")

    def _record_decision(
        self,
        sender_key: str,
        detection: DetectionResult,
        planned_action: str,
        actual_action: str,
        now: int,
    ) -> None:
        self.store.record_decision(
            sender_key,
            detector=detection.detector,
            signals=json.dumps(detection.signals, separators=(",", ":")),
            severity=detection.severity,
            score=detection.score,
            model_version=detection.model_version,
            planned_action=planned_action,
            actual_action=actual_action,
            policy_version="rules-v2",
            now=now,
        )

    def _schedule_critical_delete(
        self,
        sender_key: str,
        message: IncomingMessage,
        actions: MessageActions,
        now: int,
    ) -> str:
        if message.review_reference is None:
            self.store.delete_enforcement_review(sender_key)
            self.store.audit(
                sender_key, "CRITICAL_DELETE", "reference_unavailable", now
            )
            return "fail_safe"
        state = self.store.suppress(
            sender_key,
            "critical_rule",
            until=None,
            reference=message.review_reference,
            now=now,
        )
        self._activate_enforcement_review(
            sender_key,
            "critical_rule",
            now,
            reference=message.review_reference,
        )
        action_id = self.store.schedule_action(
            sender_key,
            reason="critical_rule",
            reference=message.review_reference,
            execute_at=now,
            expected_revision=state.revision,
            now=now,
        )
        actions.cancel_timeout(sender_key)
        actions.schedule_dialog_deletion(action_id, now)
        self.store.audit(sender_key, "CRITICAL_DELETE", "scheduled", now)
        return "suppressed"

    def _schedule_suppressed_delete(
        self,
        sender_key: str,
        state: SenderState,
        message: IncomingMessage,
        actions: MessageActions,
        now: int,
    ) -> str:
        reference = message.review_reference or state.challenge_action_reference
        if reference is None:
            self.store.audit(
                sender_key, "SUPPRESSION_DELETE", "reference_unavailable", now
            )
            return "fail_safe"
        action_id = self.store.schedule_action(
            sender_key,
            reason=state.suppression_reason or "suppressed_sender",
            reference=reference,
            execute_at=now,
            expected_revision=state.revision,
            now=now,
        )
        actions.schedule_dialog_deletion(action_id, now)
        return "suppressed"

    async def _issue_challenge(
        self,
        sender_key: str,
        message: IncomingMessage,
        actions: MessageActions,
        now: int,
    ) -> str:
        self._capture_enforcement_review(
            sender_key, message, reason="challenge_pending", now=now
        )
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
            if not self.store.refresh_challenge_expiry(sender_key, expires_at, sent_at):
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
            self._activate_enforcement_review(
                sender_key,
                "challenge_unavailable",
                now,
                reference=message.review_reference,
            )
            self.store.audit(sender_key, "CHALLENGE_UNAVAILABLE", "archived_muted", now)
            classification = "challenge_unavailable"
            outcome = "quarantined_rate_limited"
        else:
            self.store.delete_enforcement_review(sender_key)
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
            self.store.expire_challenge(sender_key, expires_at or 0, now)
            self.store.audit(sender_key, "challenge_expired", "already_archived", now)
            actions.cancel_timeout(sender_key)
            await self._finalize_timeout_failure(
                sender_key,
                state,
                actions,
                now,
                fallback_reference=message.review_reference,
            )
            return "suppressed"

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
            if self.evidence_store is not None and sender_key != self.test_sender_key:
                self._finalize_challenged_evidence(
                    message.sender_id,
                    automatic_hint="legitimate_candidate",
                    actual_action="provisional",
                )
            actions.cancel_timeout(sender_key)
            passed_message_id = await self._send_notice(
                sender_key,
                actions,
                VERIFICATION_PASSED_TEXT,
                now,
                reply_to_message_id=message.message_id,
                formatting=notice_formatting(VERIFICATION_PASSED_TEXT),
            )
            verification_message_ids = set(
                self.store.automated_message_ids_between(
                    sender_key,
                    state.challenge_message_id or message.message_id,
                    max(message.message_id, passed_message_id or message.message_id),
                )
            )
            verification_message_ids.add(message.message_id)
            if state.challenge_message_id is not None:
                verification_message_ids.add(state.challenge_message_id)
            if passed_message_id is not None:
                verification_message_ids.add(passed_message_id)
            cleanup_succeeded = await actions.delete_messages(
                tuple(sorted(verification_message_ids))
            )
            self.store.audit(
                sender_key,
                "CHALLENGE_CLEANUP",
                "messages_deleted" if cleanup_succeeded else "action_failed",
                now,
            )
            if sender_key == self.test_sender_key:
                actions.schedule_test_state_reset(
                    sender_key, now, now + TEST_STATE_RESET_DELAY_SECONDS
                )
            return "provisional"

        attempts = self.store.increment_attempts(sender_key, now)
        self.store.audit(sender_key, "CHALLENGE_INCORRECT", "rejected", now)
        if attempts >= self.challenge_max_attempts:
            actions.cancel_timeout(sender_key)
            failed_text = (
                TEST_VERIFICATION_FAILED_TEXT
                if sender_key == self.test_sender_key
                else VERIFICATION_FAILED_TEXT
            )
            warning_message_id = await self._send_notice(
                sender_key,
                actions,
                failed_text,
                now,
                formatting=emphasized(
                    failed_text,
                    "⛔ Verification Failed",
                    "10 seconds",
                ),
            )
            if warning_message_id is None:
                self.store.quarantine(sender_key, now)
                self._activate_enforcement_review(
                    sender_key,
                    "warning_failed",
                    now,
                    reference=message.review_reference,
                )
                self._enqueue_review(sender_key, message, "warning_failed", (), now)
                self.store.audit(
                    sender_key, "attempts_exhausted", "warning_failed", now
                )
                return "quarantined"
            reference = message.review_reference or state.challenge_action_reference
            if reference is None:
                self.store.quarantine(sender_key, now)
                self._activate_enforcement_review(
                    sender_key, "reference_unavailable", now
                )
                self.store.audit(
                    sender_key, "attempts_exhausted", "reference_unavailable", now
                )
                return "quarantined"
            if sender_key == self.test_sender_key:
                self.store.quarantine(sender_key, now)
                terminal = self.store.sender(sender_key)
                actions.schedule_test_state_reset(
                    sender_key,
                    terminal.updated_at,
                    now + TEST_STATE_RESET_DELAY_SECONDS,
                )
            else:
                terminal = self.store.suppress(
                    sender_key,
                    "attempts_exhausted",
                    until=now + 7 * 86400,
                    reference=reference,
                    now=now,
                )
                self._activate_enforcement_review(
                    sender_key,
                    "attempts_exhausted",
                    now,
                    reference=reference,
                )
                if self.evidence_store is not None:
                    self._finalize_challenged_evidence(
                        message.sender_id,
                        automatic_hint="spam_candidate",
                        actual_action="suppressed",
                    )
            action_id = self.store.schedule_action(
                sender_key,
                reason="attempts_exhausted",
                reference=reference,
                execute_at=now + FAILED_DIALOG_DELETE_DELAY_SECONDS,
                expected_revision=terminal.revision,
                mode_independent=sender_key == self.test_sender_key,
                now=now,
            )
            actions.schedule_dialog_deletion(
                action_id, now + FAILED_DIALOG_DELETE_DELAY_SECONDS
            )
            self.store.audit(
                sender_key,
                "attempts_exhausted",
                "dialog_deletion_scheduled",
                now,
            )
            return "suppressed" if sender_key != self.test_sender_key else "quarantined"
        remaining = self.challenge_max_attempts - attempts
        noun = "attempt" if remaining == 1 else "attempts"
        incorrect_text = (
            "❌ Incorrect Answer\n\nReply to the same verification message with "
            f"digits only. {remaining} {noun} remaining."
        )
        await self._send_notice(
            sender_key,
            actions,
            incorrect_text,
            now,
            reply_to_message_id=state.challenge_message_id,
            formatting=emphasized(
                incorrect_text,
                "❌ Incorrect Answer",
                f"{remaining} {noun} remaining",
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
    ) -> int | None:
        if not self._claim_outbound_slot(sender_key, now):
            self.store.audit(sender_key, "OUTBOUND_RATE_LIMIT", "suppressed", now)
            return None
        try:
            message_id = await actions.send_text(
                text,
                reply_to_message_id=reply_to_message_id,
                formatting=formatting,
            )
            self.store.record_automated_message(sender_key, message_id, self.clock())
            return message_id
        except Exception:
            self.store.audit(sender_key, "OUTBOUND_NOTICE", "action_failed", now)
            return None

    def _claim_outbound_slot(self, sender_key: str, now: int) -> bool:
        return sender_key == self.test_sender_key or self.store.claim_outbound_slot(
            self.outbound_limit_per_hour, now
        )

    async def _finalize_timeout_failure(
        self,
        sender_key: str,
        challenge_state: SenderState,
        actions: MessageActions,
        now: int,
        *,
        fallback_reference: bytes | None = None,
    ) -> None:
        timeout_text = (
            TEST_VERIFICATION_TIMEOUT_TEXT
            if sender_key == self.test_sender_key
            else VERIFICATION_TIMEOUT_TEXT
        )
        notice_id = await self._send_notice(
            sender_key,
            actions,
            timeout_text,
            now,
            formatting=notice_formatting(timeout_text),
        )
        if sender_key != self.test_sender_key:
            terminal = self.store.sender(sender_key)
            reference = terminal.challenge_action_reference or fallback_reference
            if notice_id is None or reference is None:
                if reference is not None:
                    self.store.enqueue_review(
                        sender_key,
                        reference,
                        "timeout_notice_failed",
                        "[]",
                        "{}",
                        now + self.review_retention_days * 86400,
                        now,
                    )
                self.store.quarantine(sender_key, now)
                self._activate_enforcement_review(
                    sender_key,
                    "timeout_notice_failed",
                    now,
                    reference=reference,
                )
                self.store.audit(
                    sender_key, "CHALLENGE_TIMEOUT_DELETE", "not_scheduled", now
                )
                return
            self._activate_enforcement_review(
                sender_key,
                "challenge_timeout",
                now,
                reference=reference,
            )
            action_id = self.store.schedule_action(
                sender_key,
                reason="challenge_timeout",
                reference=reference,
                execute_at=now + FAILED_DIALOG_DELETE_DELAY_SECONDS,
                expected_revision=terminal.revision,
                now=now,
            )
            actions.schedule_dialog_deletion(
                action_id, now + FAILED_DIALOG_DELETE_DELAY_SECONDS
            )
            return
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
                if sender_key != self.test_sender_key:
                    self._activate_enforcement_review(
                        sender_key,
                        "challenge_timeout",
                        timestamp,
                        reference=state.challenge_action_reference,
                    )
                self.store.audit(
                    sender_key, "CHALLENGE_TIMEOUT", "already_archived", timestamp
                )
                if actions is not None:
                    await self._finalize_timeout_failure(
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
        if self.store.get_mode() == "monitor":
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
