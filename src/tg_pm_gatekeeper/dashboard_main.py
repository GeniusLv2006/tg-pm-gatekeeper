# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from pathlib import Path

from .dashboard_http import DashboardHttpServer
from .dashboard_protocol import DashboardBackendError
from .dashboard_rpc import DashboardRpcClient

LOG = logging.getLogger("gatekeeper.dashboard_sidecar")
DEFAULT_RUNTIME_DIRECTORY = Path("/run/tg-pm-gatekeeper")
DEFAULT_IDLE_SECONDS = 10 * 60


class DashboardSidecar:
    def __init__(
        self,
        *,
        core_socket: Path,
        dashboard_socket: Path,
        idle_seconds: int = DEFAULT_IDLE_SECONDS,
    ) -> None:
        if idle_seconds <= 0:
            raise ValueError("idle_seconds must be positive")
        self.backend = DashboardRpcClient(core_socket)
        self.idle_seconds = idle_seconds
        self._last_authenticated_activity = time.monotonic()
        self._shutdown = asyncio.Event()
        self.shutdown_reason = "stopped"
        self.server = DashboardHttpServer(
            dashboard_socket,
            self.backend,
            on_authenticated_activity=self.note_authenticated_activity,
            on_logout=lambda: self.request_shutdown("logout"),
        )

    def note_authenticated_activity(self) -> None:
        self._last_authenticated_activity = time.monotonic()

    def request_shutdown(self, reason: str) -> None:
        if not self._shutdown.is_set():
            self.shutdown_reason = reason
            self._shutdown.set()

    async def run(self) -> str:
        # Refuse to publish a login token for a sidecar that cannot reach its core.
        await self.backend.request("overview", {})
        await self.server.start()
        LOG.info("dashboard_sidecar_started")
        try:
            while not self._shutdown.is_set():
                remaining = self.idle_seconds - (
                    time.monotonic() - self._last_authenticated_activity
                )
                if remaining <= 0:
                    self.request_shutdown("idle_timeout")
                    break
                try:
                    await asyncio.wait_for(self._shutdown.wait(), timeout=remaining)
                except TimeoutError:
                    if (
                        time.monotonic() - self._last_authenticated_activity
                        >= self.idle_seconds
                    ):
                        self.request_shutdown("idle_timeout")
        finally:
            await self.server.stop()
        LOG.info("dashboard_sidecar_stopped", extra={"reason": self.shutdown_reason})
        return self.shutdown_reason


async def _run() -> None:
    runtime_directory = Path(
        os.environ.get("TG_DASHBOARD_RUNTIME_DIR", str(DEFAULT_RUNTIME_DIRECTORY))
    )
    sidecar = DashboardSidecar(
        core_socket=runtime_directory / "core.sock",
        dashboard_socket=runtime_directory / "dashboard.sock",
    )
    loop = asyncio.get_running_loop()
    for handled_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            handled_signal,
            sidecar.request_shutdown,
            handled_signal.name.lower(),
        )
    try:
        await sidecar.run()
    except DashboardBackendError:
        LOG.error("dashboard_core_unavailable")
        raise SystemExit(1) from None


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("TG_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    asyncio.run(_run())


if __name__ == "__main__":
    main()
