# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from tg_pm_gatekeeper.dashboard_protocol import DashboardBackendError
from tg_pm_gatekeeper.dashboard_rpc import (
    MAX_REQUEST_BYTES,
    DashboardRpcClient,
    DashboardRpcServer,
)


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.failure: DashboardBackendError | Exception | None = None
        self.result: dict[str, object] = {"value": 1}

    async def request(
        self, method: str, params: dict[str, object]
    ) -> dict[str, object]:
        self.calls.append((method, params))
        if self.failure is not None:
            raise self.failure
        return self.result


class DashboardRpcTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.runtime = Path(self.temporary.name)
        self.runtime.chmod(0o700)
        self.path = self.runtime / "core.sock"
        self.backend = FakeBackend()
        self.server = DashboardRpcServer(self.path, self.backend)
        await self.server.start()

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        self.temporary.cleanup()

    async def test_round_trip_and_owner_only_socket(self) -> None:
        result = await DashboardRpcClient(self.path).request("overview", {})
        self.assertEqual(result, {"value": 1})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    async def test_backend_error_hides_message_and_internal_exception(self) -> None:
        self.backend.failure = DashboardBackendError("case_not_found")
        with self.assertRaisesRegex(DashboardBackendError, "case_not_found"):
            await DashboardRpcClient(self.path).request(
                "cases.detail", {"sender_key": "a" * 64}
            )
        self.backend.failure = RuntimeError("sensitive-canary")
        with self.assertLogs("gatekeeper.dashboard_rpc", level="ERROR") as logs:
            with self.assertRaisesRegex(DashboardBackendError, "request_failed"):
                await DashboardRpcClient(self.path).request(
                    "cases.detail", {"sender_key": "a" * 64}
                )
        self.assertNotIn("sensitive-canary", "\n".join(logs.output))

    async def test_malformed_and_wrong_version_are_rejected(self) -> None:
        for raw in (b"not-json\n", b'{"version":2}\n'):
            reader, writer = await asyncio.open_unix_connection(self.path)
            writer.write(raw)
            await writer.drain()
            response = json.loads(await reader.readline())
            writer.close()
            await writer.wait_closed()
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], "invalid_request")

    async def test_oversized_client_request_is_rejected_before_connect(self) -> None:
        with self.assertRaisesRegex(DashboardBackendError, "request_too_large"):
            await DashboardRpcClient(self.path).request(
                "reviews.decide", {"value": "x" * MAX_REQUEST_BYTES}
            )
        self.assertEqual(self.backend.calls, [])

    async def test_oversized_response_is_replaced_with_bounded_error(self) -> None:
        self.backend.result = {"value": "x" * (1024 * 1024)}
        with self.assertRaisesRegex(DashboardBackendError, "response_too_large"):
            await DashboardRpcClient(self.path).request("overview", {})

    async def test_unknown_method_is_rejected_before_backend(self) -> None:
        with self.assertRaisesRegex(DashboardBackendError, "unknown_method"):
            await DashboardRpcClient(self.path).request("internal.secret", {})
        self.assertEqual(self.backend.calls, [])

    async def test_accepted_write_completes_after_client_disconnects(self) -> None:
        completed = asyncio.Event()
        started = asyncio.Event()
        release = asyncio.Event()

        async def request(method: str, params: dict[str, object]) -> dict[str, object]:
            self.assertEqual(method, "reviews.decide")
            started.set()
            await release.wait()
            completed.set()
            return {"outcome": "completed"}

        self.backend.request = request
        _, writer = await asyncio.open_unix_connection(self.path)
        writer.write(
            json.dumps(
                {
                    "version": 1,
                    "id": "disconnected-client",
                    "method": "reviews.decide",
                    "params": {"review_id": 1, "action": "dismiss"},
                }
            ).encode()
            + b"\n"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(started.wait(), timeout=1)
        stop_task = asyncio.create_task(self.server.stop())
        await asyncio.sleep(0)
        self.assertFalse(stop_task.done())
        release.set()
        await stop_task
        await asyncio.wait_for(completed.wait(), timeout=1)

    async def test_partial_request_cannot_block_rpc_shutdown(self) -> None:
        with patch(
            "tg_pm_gatekeeper.dashboard_rpc.RPC_REQUEST_READ_TIMEOUT_SECONDS", 0.01
        ):
            _, writer = await asyncio.open_unix_connection(self.path)
            writer.write(b'{"version":1')
            await writer.drain()
            for _ in range(100):
                if self.server._connection_tasks:
                    break
                await asyncio.sleep(0)
            self.assertTrue(self.server._connection_tasks)
            await asyncio.wait_for(self.server.stop(), timeout=1)
            writer.close()
            await writer.wait_closed()

    async def test_incomplete_response_is_a_retryable_disconnect(self) -> None:
        client = DashboardRpcClient(self.path)

        class Reader:
            async def readuntil(self, _separator: bytes) -> bytes:
                raise asyncio.IncompleteReadError(b"", 1)

        class Writer:
            def write(self, _data: bytes) -> None:
                pass

            async def drain(self) -> None:
                pass

            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                pass

        with patch(
            "tg_pm_gatekeeper.dashboard_rpc.asyncio.open_unix_connection",
            AsyncMock(return_value=(Reader(), Writer())),
        ):
            with self.assertRaises(ConnectionError):
                await client._request_once("overview", {})

    async def test_read_retries_once_but_write_never_retries(self) -> None:
        client = DashboardRpcClient(self.path)
        client._request_once = AsyncMock(side_effect=ConnectionError("closed"))
        with self.assertRaisesRegex(DashboardBackendError, "core_unavailable"):
            await client.request("overview", {})
        self.assertEqual(client._request_once.await_count, 2)

        client._request_once.reset_mock()
        with self.assertRaisesRegex(DashboardBackendError, "core_unavailable"):
            await client.request("reviews.decide", {})
        self.assertEqual(client._request_once.await_count, 1)

    async def test_timeout_is_reported_without_details(self) -> None:
        client = DashboardRpcClient(self.path)
        client._request_once = AsyncMock(side_effect=asyncio.TimeoutError)
        with patch("tg_pm_gatekeeper.dashboard_rpc.RPC_TIMEOUT_SECONDS", 0.01):
            with self.assertRaisesRegex(DashboardBackendError, "core_unavailable"):
                await client.request("reviews.decide", {})

    async def test_broker_rejects_runtime_directory_with_group_access(self) -> None:
        await self.server.stop()
        self.runtime.chmod(0o750)
        with self.assertRaisesRegex(RuntimeError, "not owner-only"):
            await self.server.start()


if __name__ == "__main__":
    unittest.main()
