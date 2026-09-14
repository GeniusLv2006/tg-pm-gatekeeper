# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

from typing import Protocol


class DashboardBackend(Protocol):
    async def request(
        self, method: str, params: dict[str, object]
    ) -> dict[str, object]: ...


class DashboardBackendError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
