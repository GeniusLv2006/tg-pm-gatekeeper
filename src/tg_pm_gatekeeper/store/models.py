# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Row types returned by the state store."""

from __future__ import annotations

from dataclasses import dataclass

from ..states import ActionStatus, ReviewStatus, SenderStatus


@dataclass(frozen=True, slots=True)
class SenderState:
    status: SenderStatus
    challenge_id: str | None
    answer_digest: str | None
    challenge_expires_at: int | None
    challenge_message_id: int | None
    challenge_prompt: str | None
    challenge_profile: str | None
    challenge_action_reference: bytes | None
    restriction_reference: bytes | None
    guidance_sent: bool
    attempts: int
    suppression_reason: str | None
    suppressed_until: int | None
    revision: int
    updated_at: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", SenderStatus(self.status))


@dataclass(frozen=True, slots=True)
class ReviewItem:
    id: int
    sender_key: str
    reference: bytes | None
    classification: str
    signals: str
    features: str
    status: ReviewStatus
    message_count: int
    created_at: int
    updated_at: int
    expires_at: int
    reviewed_at: int | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", ReviewStatus(self.status))


@dataclass(frozen=True, slots=True)
class EnforcementReview:
    sender_key: str
    reference: bytes | None
    envelope: bytes
    reason: str
    created_at: int
    updated_at: int
    expires_at: int
    status: SenderStatus
    suppressed_until: int | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", SenderStatus(self.status))


@dataclass(frozen=True, slots=True)
class ActiveRestriction:
    sender_key: str
    reference: bytes | None
    status: SenderStatus
    reason: str
    suppressed_until: int | None
    updated_at: int
    envelope: bytes | None
    evidence_created_at: int | None
    evidence_expires_at: int | None
    archived_at: int | None
    has_open_actions: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", SenderStatus(self.status))


@dataclass(frozen=True, slots=True)
class DialogSnapshot:
    folder_id: int
    silent: bool
    mute_until: int | None


@dataclass(frozen=True, slots=True)
class PendingAction:
    id: int
    sender_key: str
    action: str
    reason: str
    reference: bytes
    execute_at: int
    expected_revision: int
    mode_independent: int
    status: ActionStatus
    created_at: int
    finished_at: int | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", ActionStatus(self.status))
