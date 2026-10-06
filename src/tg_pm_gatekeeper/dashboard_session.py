# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Dashboard credentials: one-time login token, capability path, browser session, CSRF."""

from __future__ import annotations

import os
import secrets
import time
from http.cookies import CookieError, SimpleCookie
from pathlib import Path

DASHBOARD_SESSION_IDLE_SECONDS = 30 * 60
DASHBOARD_SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60
DASHBOARD_SESSION_COOKIE = "tg_pm_gatekeeper_session"


class DashboardCredentials:
    """Process-memory credentials; only the current one-time login token touches disk."""

    def __init__(self, access_token_path: Path) -> None:
        self.access_token_path = access_token_path
        self.csrf_token = secrets.token_urlsafe(32)
        self.access_token = secrets.token_urlsafe(32)
        self.capability_token = secrets.token_urlsafe(32)
        self.session_token: str | None = None
        self.session_started_at: float | None = None
        self.session_last_seen_at: float | None = None

    def accepts_login(self, token: str) -> bool:
        return secrets.compare_digest(token, self.access_token)

    def accepts_csrf(self, token: str) -> bool:
        return secrets.compare_digest(token, self.csrf_token)

    def start_session(self) -> None:
        """Consume the login token: rotate it and the capability, then open a session."""
        self.access_token = secrets.token_urlsafe(32)
        self.capability_token = secrets.token_urlsafe(32)
        self.activate_session()

    def activate_session(self) -> None:
        now = time.monotonic()
        self.session_token = secrets.token_urlsafe(32)
        self.session_started_at = now
        self.session_last_seen_at = now

    def invalidate_session(self) -> None:
        self.session_token = None
        self.session_started_at = None
        self.session_last_seen_at = None
        self.access_token = secrets.token_urlsafe(32)
        self.capability_token = secrets.token_urlsafe(32)
        self.write_access_token()

    def record_activity(self) -> None:
        self.session_last_seen_at = time.monotonic()

    def has_valid_session(self, request_headers: dict[str, str]) -> bool:
        token = self.session_cookie_value(request_headers.get("cookie", ""))
        if (
            token is None
            or self.session_token is None
            or self.session_started_at is None
            or self.session_last_seen_at is None
            or not secrets.compare_digest(token, self.session_token)
        ):
            return False
        now = time.monotonic()
        if (
            now - self.session_last_seen_at >= DASHBOARD_SESSION_IDLE_SECONDS
            or now - self.session_started_at >= DASHBOARD_SESSION_ABSOLUTE_SECONDS
        ):
            return False
        return True

    def logical_path(self, path: str) -> str | None:
        """Strip the capability prefix, or return None when it is missing or wrong."""
        parts = path.split("/", 2)
        candidate = parts[1] if len(parts) > 1 else ""
        if not secrets.compare_digest(candidate, self.capability_token):
            return None
        return "/" + parts[2] if len(parts) == 3 else "/"

    @staticmethod
    def session_cookie_value(raw_cookie: str) -> str | None:
        cookies = SimpleCookie()
        try:
            cookies.load(raw_cookie)
        except CookieError:
            return None
        morsel = cookies.get(DASHBOARD_SESSION_COOKIE)
        return morsel.value if morsel is not None else None

    def session_cookie_header(self) -> str:
        return (
            f"{DASHBOARD_SESSION_COOKIE}={self.session_token}; "
            f"Path=/{self.capability_token}/; Max-Age={DASHBOARD_SESSION_ABSOLUTE_SECONDS}; "
            "HttpOnly; SameSite=Strict"
        )

    def expired_session_cookie_header(self) -> str:
        return (
            f"{DASHBOARD_SESSION_COOKIE}=; Path=/{self.capability_token}/; "
            "Max-Age=0; HttpOnly; SameSite=Strict"
        )

    def capability_headers(self, headers: dict[str, str]) -> dict[str, str]:
        location = headers.get("Location")
        if location is None or not location.startswith("/"):
            return headers
        return {**headers, "Location": f"/{self.capability_token}{location}"}

    def capability_html(self, response: bytes, headers: dict[str, str]) -> bytes:
        """Prefix every root-relative link, form, and script with the capability path."""
        content_type = headers.get("Content-Type", "text/html")
        if not content_type.startswith("text/html"):
            return response
        prefix = f"/{self.capability_token}/".encode("ascii")
        for attribute in (b"href", b"action", b"src"):
            response = response.replace(attribute + b"='/", attribute + b"='" + prefix)
            response = response.replace(attribute + b'="/', attribute + b'="' + prefix)
        return response

    def write_access_token(self) -> None:
        temporary = self.access_token_path.with_suffix(".access-token.tmp")
        temporary.unlink(missing_ok=True)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as output:
                output.write(self.access_token)
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(self.access_token_path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
