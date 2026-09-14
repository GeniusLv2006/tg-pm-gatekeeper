# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Compatibility constructor for the former in-process Dashboard server."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .dashboard_backend import InProcessDashboardBackend
from .dashboard_http import (
    DASHBOARD_SESSION_ABSOLUTE_SECONDS,
    DASHBOARD_SESSION_COOKIE,
    DASHBOARD_SESSION_IDLE_SECONDS,
    DashboardHttpServer,
)
from .restriction_actions import RestrictionActions
from .service import GatekeeperService
from .store import StateStore


class ReviewAdminServer(DashboardHttpServer):
    def __init__(
        self,
        socket_path: Path,
        store: StateStore,
        service: GatekeeperService,
        telegram_client: Any,
        *,
        mute_days: int,
        cancel_timeout: Callable[[str], None] = lambda _sender_key: None,
        schedule_dialog_deletion: Callable[[int, int], None] = (
            lambda _action_id, _delete_at: None
        ),
        restriction_actions: RestrictionActions | None = None,
    ) -> None:
        actions = restriction_actions or RestrictionActions(
            store,
            service,
            telegram_client,
            cancel_timeout=cancel_timeout,
        )
        backend = InProcessDashboardBackend(
            store,
            service,
            telegram_client,
            mute_days=mute_days,
            cancel_timeout=cancel_timeout,
            schedule_dialog_deletion=schedule_dialog_deletion,
            restriction_actions=actions,
        )
        super().__init__(socket_path, backend)

__all__ = [
    "DASHBOARD_SESSION_ABSOLUTE_SECONDS",
    "DASHBOARD_SESSION_COOKIE",
    "DASHBOARD_SESSION_IDLE_SECONDS",
    "ReviewAdminServer",
]
