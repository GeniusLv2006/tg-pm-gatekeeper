# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Persistent status values; each enum mirrors a CHECK constraint in the store schema."""

from __future__ import annotations

from enum import StrEnum


class SenderStatus(StrEnum):
    UNKNOWN = "unknown"
    CHALLENGE_ISSUING = "challenge_issuing"
    CHALLENGE_ARCHIVING = "challenge_archiving"
    CHALLENGED = "challenged"
    PROVISIONAL = "provisional"
    ALLOWED = "allowed"
    QUARANTINED = "quarantined"
    SUPPRESSED = "suppressed"


class ReviewStatus(StrEnum):
    PENDING = "pending"
    LEGITIMATE = "legitimate"
    SPAM = "spam"
    DISMISSED = "dismissed"


class ActionStatus(StrEnum):
    PENDING = "pending"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


CHALLENGE_STARTING_STATUSES = frozenset(
    {SenderStatus.CHALLENGE_ISSUING, SenderStatus.CHALLENGE_ARCHIVING}
)
RESTRICTED_STATUSES = frozenset({SenderStatus.QUARANTINED, SenderStatus.SUPPRESSED})
# States in which Gatekeeper has archived and muted the dialog and must restore it on allow.
GATEKEEPER_ARCHIVED_STATUSES = frozenset({SenderStatus.CHALLENGED, *RESTRICTED_STATUSES})
REVIEW_DECISIONS = frozenset(set(ReviewStatus) - {ReviewStatus.PENDING})
FINISHED_ACTION_STATUSES = frozenset(set(ActionStatus) - {ActionStatus.PENDING})
