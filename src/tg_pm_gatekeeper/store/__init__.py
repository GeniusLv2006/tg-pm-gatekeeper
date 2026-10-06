# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""SQLite state store, split by aggregate behind one StateStore facade."""

from __future__ import annotations

from .actions import ActionMixin
from .challenges import ChallengeMixin
from .maintenance import MaintenanceMixin
from .models import (
    ActiveRestriction,
    DialogSnapshot,
    EnforcementReview,
    PendingAction,
    ReviewItem,
    SenderState,
)
from .reviews import ReviewMixin
from .schema import (
    CAMPAIGN_WINDOW_SECONDS,
    SCHEMA,
    SCHEMA_VERSION,
    SENDER_LINKED_TABLES,
    SENDER_STATE_SCHEMA,
    SENDER_STATUSES,
    StoreMigrationError,
)
from .senders import SenderStateMixin

__all__ = [
    "ActiveRestriction",
    "CAMPAIGN_WINDOW_SECONDS",
    "DialogSnapshot",
    "EnforcementReview",
    "PendingAction",
    "ReviewItem",
    "SCHEMA",
    "SCHEMA_VERSION",
    "SENDER_LINKED_TABLES",
    "SENDER_STATE_SCHEMA",
    "SENDER_STATUSES",
    "SenderState",
    "StateStore",
    "StoreMigrationError",
]


class StateStore(
    SenderStateMixin,
    ChallengeMixin,
    ActionMixin,
    ReviewMixin,
    MaintenanceMixin,
):
    """Owner of the state database; see the mixin modules for each aggregate."""
