# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

from typing import Any, Protocol

# Broker payloads are decoded JSON; callers validate the fields they read.
JsonObject = dict[str, Any]


class DashboardBackend(Protocol):
    async def request(
        self, method: str, params: dict[str, object]
    ) -> JsonObject: ...


class DashboardBackendError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
