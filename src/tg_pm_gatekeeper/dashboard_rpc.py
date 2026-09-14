# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import stat
from pathlib import Path

from .dashboard_protocol import DashboardBackend, DashboardBackendError

LOG = logging.getLogger("gatekeeper.dashboard_rpc")
PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
RPC_TIMEOUT_SECONDS = 10
READ_ONLY_METHODS = {
    "overview",
    "page_version",
    "reviews.list",
    "reviews.detail",
    "cases.list",
    "cases.detail",
}
WRITE_METHODS = {
    "reviews.decide",
    "cases.decide",
    "cases.release_legacy",
}
ALLOWED_METHODS = READ_ONLY_METHODS | WRITE_METHODS


class DashboardRpcServer:
    def __init__(self, path: Path, backend: DashboardBackend) -> None:
        self.path = path
        self.backend = backend
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = self.path.parent.stat()
        if info.st_mode & 0o077:
            raise RuntimeError("dashboard runtime directory permissions are too broad")
        try:
            socket_info = self.path.lstat()
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(socket_info.st_mode):
                raise RuntimeError("dashboard RPC path is not a socket")
            self.path.unlink()
        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=self.path,
            limit=MAX_REQUEST_BYTES + 1,
        )
        os.chmod(self.path, 0o600)
        LOG.info("dashboard_rpc_started")

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self.path.unlink(missing_ok=True)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        response: dict[str, object]
        request_id = ""
        try:
            raw = await reader.readuntil(b"\n")
            if len(raw) > MAX_REQUEST_BYTES:
                raise ValueError("request too large")
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            request_id = request.get("id", "")
            method = request.get("method")
            params = request.get("params")
            if (
                request.get("version") != PROTOCOL_VERSION
                or not isinstance(request_id, str)
                or len(request_id) > 64
                or not isinstance(method, str)
                or len(method) > 64
                or not isinstance(params, dict)
            ):
                raise ValueError("invalid request")
            if method not in ALLOWED_METHODS:
                raise DashboardBackendError("unknown_method")
            result = await self.backend.request(method, params)
            response = {
                "version": PROTOCOL_VERSION,
                "id": request_id,
                "ok": True,
                "result": result,
            }
        except DashboardBackendError as exc:
            response = self._error(request_id, exc.code)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            response = self._error(request_id, "invalid_request")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            response = self._error(request_id, "invalid_request")
        except Exception:
            LOG.error("dashboard_rpc_request_failed")
            response = self._error(request_id, "request_failed")
        encoded = json.dumps(
            response, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii") + b"\n"
        if len(encoded) > MAX_RESPONSE_BYTES:
            encoded = json.dumps(
                self._error(request_id, "response_too_large"),
                separators=(",", ":"),
            ).encode("ascii") + b"\n"
        try:
            writer.write(encoded)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    @staticmethod
    def _error(request_id: str, code: str) -> dict[str, object]:
        return {
            "version": PROTOCOL_VERSION,
            "id": request_id,
            "ok": False,
            "error": {"code": code},
        }


class DashboardRpcClient:
    def __init__(self, path: Path) -> None:
        self.path = path

    async def request(
        self, method: str, params: dict[str, object]
    ) -> dict[str, object]:
        attempts = 2 if method in READ_ONLY_METHODS else 1
        for attempt in range(attempts):
            try:
                return await asyncio.wait_for(
                    self._request_once(method, params), timeout=RPC_TIMEOUT_SECONDS
                )
            except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
                if attempt + 1 == attempts:
                    raise DashboardBackendError("core_unavailable") from exc
        raise DashboardBackendError("core_unavailable")

    async def _request_once(
        self, method: str, params: dict[str, object]
    ) -> dict[str, object]:
        request_id = secrets.token_hex(16)
        encoded = json.dumps(
            {
                "version": PROTOCOL_VERSION,
                "id": request_id,
                "method": method,
                "params": params,
            },
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii") + b"\n"
        if len(encoded) > MAX_REQUEST_BYTES:
            raise DashboardBackendError("request_too_large")
        reader, writer = await asyncio.open_unix_connection(
            self.path, limit=MAX_RESPONSE_BYTES + 1
        )
        try:
            writer.write(encoded)
            await writer.drain()
            raw = await reader.readuntil(b"\n")
            if len(raw) > MAX_RESPONSE_BYTES:
                raise DashboardBackendError("response_too_large")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise DashboardBackendError("invalid_response") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DashboardBackendError("invalid_response") from exc
        if (
            not isinstance(response, dict)
            or response.get("version") != PROTOCOL_VERSION
            or response.get("id") != request_id
        ):
            raise DashboardBackendError("invalid_response")
        if response.get("ok") is not True:
            error = response.get("error")
            code = error.get("code") if isinstance(error, dict) else None
            raise DashboardBackendError(code if isinstance(code, str) else "request_failed")
        result = response.get("result")
        if not isinstance(result, dict):
            raise DashboardBackendError("invalid_response")
        return result
