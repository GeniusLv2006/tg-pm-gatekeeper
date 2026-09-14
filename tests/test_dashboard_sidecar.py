# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from tg_pm_gatekeeper.dashboard_http import DashboardHttpServer
from tg_pm_gatekeeper.dashboard_main import DashboardSidecar
from tg_pm_gatekeeper.dashboard_rpc import DashboardRpcServer


class FakeBackend:
    async def request(
        self, method: str, params: dict[str, object]
    ) -> dict[str, object]:
        if method == "overview":
            return {
                "mode": "protect",
                "pending_reviews": 0,
                "active_stats": {
                    "quarantined": 0,
                    "suppressed": 0,
                    "reviewable": 0,
                },
            }
        if method == "page_version":
            return {"version": "version"}
        raise AssertionError(method)


class SlowWriteBackend(FakeBackend):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.completed = asyncio.Event()

    async def request(
        self, method: str, params: dict[str, object]
    ) -> dict[str, object]:
        if method == "reviews.decide":
            self.started.set()
            await asyncio.sleep(0.02)
            self.completed.set()
            return {"outcome": "completed"}
        return await super().request(method, params)


class DashboardSidecarTests(unittest.IsolatedAsyncioTestCase):
    def make_sidecar(self, *, idle_seconds: float = 0.05) -> DashboardSidecar:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        sidecar = DashboardSidecar(
            core_socket=root / "core.sock",
            dashboard_socket=root / "dashboard.sock",
            idle_seconds=idle_seconds,
        )
        sidecar.backend = FakeBackend()
        sidecar.server.backend = sidecar.backend
        sidecar.server.start = AsyncMock()
        sidecar.server.stop = AsyncMock()
        return sidecar

    async def test_unauthenticated_traffic_does_not_extend_idle_lifetime(self) -> None:
        sidecar = self.make_sidecar()
        started = sidecar._last_authenticated_activity
        status, _, _ = await sidecar.server._dispatch(
            "GET", "/missing", b"", request_headers={"host": "127.0.0.1:8765"}
        )
        self.assertEqual(status, 404)
        self.assertEqual(sidecar._last_authenticated_activity, started)
        self.assertEqual(await sidecar.run(), "idle_timeout")

    async def test_authenticated_page_extends_idle_lifetime(self) -> None:
        sidecar = self.make_sidecar(idle_seconds=1)
        sidecar.server._activate_session()
        before = sidecar._last_authenticated_activity
        await asyncio.sleep(0)
        headers = {
            "host": "127.0.0.1:8765",
            "cookie": f"tg_pm_gatekeeper_session={sidecar.server._session_token}",
        }
        status, _, _ = await sidecar.server._dispatch(
            "GET", f"/{sidecar.server._capability_token}/", b"", request_headers=headers
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(sidecar._last_authenticated_activity, before)

    async def test_logout_requests_shutdown_after_response(self) -> None:
        sidecar = self.make_sidecar(idle_seconds=1)
        sidecar.server._activate_session()
        headers = {
            "host": "127.0.0.1:8765",
            "cookie": f"tg_pm_gatekeeper_session={sidecar.server._session_token}",
        }
        body = f"token={sidecar.server._csrf_token}".encode()
        status, _, _ = await sidecar.server._dispatch(
            "POST",
            f"/{sidecar.server._capability_token}/logout",
            body,
            request_headers=headers,
        )
        self.assertEqual(status, 303)
        await asyncio.sleep(0)
        self.assertEqual(await sidecar.run(), "logout")

    async def test_explicit_shutdown_cleans_up_server(self) -> None:
        sidecar = self.make_sidecar(idle_seconds=10)
        task = asyncio.create_task(sidecar.run())
        while sidecar.server.start.await_count == 0:
            await asyncio.sleep(0)
        sidecar.request_shutdown("sigterm")
        self.assertEqual(await task, "sigterm")
        sidecar.server.stop.assert_awaited_once()

    def test_each_starting_process_has_fresh_capabilities_and_cookie_secret(self) -> None:
        first = self.make_sidecar(idle_seconds=1)
        second = self.make_sidecar(idle_seconds=1)
        self.assertNotEqual(first.server._access_token, second.server._access_token)
        self.assertNotEqual(first.server._capability_token, second.server._capability_token)
        self.assertNotEqual(first.server._csrf_token, second.server._csrf_token)

    async def test_real_sidecar_idle_exit_removes_socket_and_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            core_socket = root / "core.sock"
            dashboard_socket = root / "dashboard.sock"
            broker = DashboardRpcServer(core_socket, FakeBackend())
            await broker.start()
            try:
                sidecar = DashboardSidecar(
                    core_socket=core_socket,
                    dashboard_socket=dashboard_socket,
                    idle_seconds=0.05,
                )
                self.assertEqual(await sidecar.run(), "idle_timeout")
                self.assertFalse(dashboard_socket.exists())
                self.assertFalse(
                    dashboard_socket.with_suffix(".access-token").exists()
                )
            finally:
                await broker.stop()

    async def test_http_shutdown_waits_for_accepted_write_and_returns_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "dashboard.sock"
            backend = SlowWriteBackend()
            server = DashboardHttpServer(socket_path, backend)
            await server.start()
            server._activate_session()
            reader, writer = await asyncio.open_unix_connection(socket_path)
            body = f"token={server._csrf_token}&action=dismiss".encode()
            writer.write(
                (
                    f"POST /{server._capability_token}/review/1 HTTP/1.1\r\n"
                    "Host: 127.0.0.1:8765\r\n"
                    f"Cookie: tg_pm_gatekeeper_session={server._session_token}\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode()
                + body
            )
            await writer.drain()
            await asyncio.wait_for(backend.started.wait(), timeout=1)
            await server.stop()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()
            self.assertTrue(backend.completed.is_set())
            self.assertIn(b"HTTP/1.1 303 See Other", response)


if __name__ == "__main__":
    unittest.main()
