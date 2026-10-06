# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Escaped HTML building blocks shared by every dashboard page."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime, timezone

PAGE_SIZE = 50
DASHBOARD_POLL_SECONDS = 15


@dataclass(frozen=True, slots=True)
class LiveIdentity:
    user_id: int
    name: str | None
    username: str | None


def json_block(value: object) -> str:
    return html.escape(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def text_block(label: str, value: str, *, quote: bool = False) -> str:
    if not value:
        return ""
    css = "message quote" if quote else "message"
    return (
        f"<h3 class='field-label'>{html.escape(label)}</h3>"
        f"<pre class='{css}'>{html.escape(value)}</pre>"
    )


def badge(label: str, tone: str = "neutral") -> str:
    return f"<span class='badge badge-{tone}'>{html.escape(label)}</span>"


def page_header(
    title: str,
    *,
    count: str | None = None,
    lede: str = "",
    meta: str = "",
    aside: str = "",
    back: tuple[str, str] | None = None,
) -> str:
    back_link = (
        f"<a class='back-link' href='{back[0]}'>← {html.escape(back[1])}</a>"
        if back is not None
        else ""
    )
    count_html = (
        f" <span class='title-count'>{html.escape(count)}</span>" if count else ""
    )
    lede_html = f"<p class='lede'>{lede}</p>" if lede else ""
    return (
        "<div class='page-header'><div class='page-heading'>"
        f"{back_link}<h1>{html.escape(title)}{count_html}</h1>{meta}{lede_html}</div>"
        + (f"<div class='page-header-aside'>{aside}</div>" if aside else "")
        + "</div>"
    )


def key_values(rows: list[tuple[str, str]]) -> str:
    return (
        "<dl class='kv'>"
        + "".join(f"<div><dt>{label}</dt><dd>{value}</dd></div>" for label, value in rows)
        + "</dl>"
    )


def joined(value: object) -> str:
    if not isinstance(value, list) or not value:
        return "—"
    return ", ".join(str(item) for item in value)


def identity_from_value(value: object) -> LiveIdentity | None:
    if not isinstance(value, dict):
        return None
    user_id = value.get("user_id")
    name = value.get("name")
    username = value.get("username")
    if not isinstance(user_id, int):
        return None
    return LiveIdentity(
        user_id,
        name if isinstance(name, str) else None,
        username if isinstance(username, str) else None,
    )


def identity_cell(identity: LiveIdentity | None, *, href: str | None = None) -> str:
    if identity is None:
        label = "Identity Unavailable"
        identity_id = ""
    else:
        if identity.name is None:
            label = "Name Unavailable"
        else:
            label = identity.name + (
                f" (@{identity.username})" if identity.username else ""
            )
        identity_id = f"<span class='identity-id'>ID {identity.user_id}</span>"
    name = html.escape(label)
    if href is not None:
        name = (
            f"<a class='identity-link row-link' href='{html.escape(href, quote=True)}'>"
            f"{name}</a>"
        )
    return f"<span class='identity-name'>{name}</span>{identity_id}"


def identity_meta(user_id: int | None, *, review_id: int | None = None) -> str:
    parts: list[str] = []
    if user_id is not None:
        parts.append(f"<span class='identity-id'>ID {user_id}</span>")
    if review_id is not None:
        parts.append(f"<span class='identity-id'>Review #{review_id}</span>")
    if user_id is not None:
        parts.append(
            f"<a class='telegram-link' href='tg://user?id={user_id}'>"
            "Open This Conversation in Telegram ↗</a>"
        )
    return f"<p class='page-meta'>{''.join(parts)}</p>" if parts else ""


def pagination(base: str, page: int, total: int) -> str:
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if total_pages == 1:
        return ""
    separator = "&" if "?" in base else "?"
    previous = (
        f"<a href='{base}{separator}page={page - 1}'>← Previous</a>"
        if page > 1 else ""
    )
    following = (
        f"<a href='{base}{separator}page={page + 1}'>Next →</a>"
        if page < total_pages
        else ""
    )
    return (
        "<nav class='pagination' aria-label='Pagination'>"
        + previous
        + f"<span>Page {page} of {total_pages}</span>"
        + following
        + "</nav>"
    )


NAVIGATION = (
    ("overview", "/", "Overview"),
    ("reviews", "/review", "Pending Reviews"),
    ("cases", "/cases", "Needs Attention"),
    ("archive", "/cases/archive", "Archived"),
)


def masthead(
    active: str | None = None, *, csrf_token: str | None = None
) -> str:
    brand = (
        "<span class='brand-mark' aria-hidden='true'>TG</span>"
        "<span class='brand-name'>PM Gatekeeper</span>"
    )
    if csrf_token is None:
        return f"<header class='masthead'><div class='masthead-inner'><span class='brand'>{brand}</span></div></header>"
    current = " aria-current='page'"
    links = "".join(
        f"<a href='{href}'{current if key == active else ''}>{label}</a>"
        for key, href, label in NAVIGATION
    )
    checked_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    return (
        "<header class='masthead'><div class='masthead-inner'>"
        f"<a class='brand' href='/'>{brand}</a>"
        "<nav class='primary-nav' aria-label='Dashboard sections' data-section-indicator>"
        f"{links}</nav>"
        "<div class='connection' data-connection data-state='connected'>"
        "<span class='live'><i aria-hidden='true'></i><span data-connection-label>Connected</span></span>"
        f"<small data-checked-at>Checked {checked_at}</small>"
        "<button class='refresh-control' type='button' data-dashboard-refresh "
        "aria-label='Check Now' title='Check Now'>↻</button></div>"
        "<button class='theme-toggle' type='button' data-theme-toggle "
        "aria-label='Change theme'>System</button>"
        "<form class='logout-form' method='post' action='/logout'>"
        f"<input type='hidden' name='token' value='{csrf_token}'>"
        "<button type='submit'>Sign Out</button></form>"
        "</div></header>"
    )


def change_notice() -> str:
    return (
        "<section class='live-change-notice' data-change-notice hidden>"
        "<strong>This record changed while you were viewing it.</strong> "
        "Actions are paused to prevent a stale decision. Check now to load the current state."
        "</section>"
    )


def action_form(
    csrf_token: str,
    review_id: int | str,
    action: str,
    label: str,
    *,
    tone: str | None = None,
    base: str = "review",
) -> str:
    button_class = f"btn btn-{tone}" if tone else "btn"
    return (
        f"<form method='post' action='/{base}/{review_id}'>"
        f"<input type='hidden' name='token' value='{csrf_token}'>"
        f"<input type='hidden' name='action' value='{action}'>"
        f"<button class='{button_class}' type='submit'>{html.escape(label)}</button></form>"
    )


def confirmation_page(
    *,
    csrf_token: str,
    nav: str,
    title: str,
    body: str,
    action: str,
    button: str,
    tone: str,
    cancel_href: str,
    page_title: str,
    hidden: dict[str, str] | None = None,
    warning: str | None = None,
    disabled: bool = False,
) -> bytes:
    hidden_inputs = "".join(
        f"<input type='hidden' name='{name}' value='{html.escape(value, quote=True)}'>"
        for name, value in (hidden or {}).items()
    )
    warning_badge = badge(warning, "block") if warning else ""
    content = (
        masthead(nav, csrf_token=csrf_token)
        + "<main class='page confirm-page'><section class='confirm-card"
        + (" confirm-danger" if tone == "block" else "")
        + f"'>{warning_badge}<h1>{html.escape(title)}</h1><p>{html.escape(body)}</p>"
        + "<div class='confirm-actions'>"
        + f"<form method='post' action='{action}'>"
        + f"<input type='hidden' name='token' value='{csrf_token}'>{hidden_inputs}"
        + f"<button class='btn btn-{tone}' type='submit'{' disabled' if disabled else ''}>"
        + f"{html.escape(button)}</button></form>"
        + f"<a class='btn' href='{cancel_href}'>Cancel</a></div></section></main>"
    )
    return render_page(content, raw=True, page_title=page_title)


def render_page(
    content: str,
    *,
    raw: bool = False,
    page_title: str | None = None,
    live_refresh: str | None = None,
    page_version: str | None = None,
) -> bytes:
    if raw:
        # Keep the masthead mounted while navigating between dashboard pages.
        header, separator, page_content = content.partition("</header>")
        body = (
            header + separator
            + "<div data-dashboard-content>" + page_content + "</div>"
            if separator else content
        )
    else:
        guidance = {
            "Invalid Access Token": (
                "This login link is invalid or has already been used. Run "
                "the tunnel helper again to generate a new one-time link."
            ),
            "Not Found": (
                "The requested page is unavailable. Check the address or return to the "
                "dashboard."
            ),
            "Dashboard Access Missing": (
                "This address does not contain a valid dashboard session. Run the tunnel "
                "helper again and open its new one-time link in this browser."
            ),
            "Dashboard Signed Out": (
                "This browser session has been revoked. Run the tunnel helper again when "
                "you need to reopen the dashboard."
            ),
            "Confirmation Required": (
                "Suppress and Delete deletes the Telegram conversation, so it must be "
                "confirmed on its own page. Nothing was changed."
            ),
            "Request Failed": (
                "The request could not be completed. No dashboard action was confirmed."
            ),
        }.get(content, "Check the request and return to the dashboard.")
        return_action = (
            ""
            if content
            in {
                "Invalid Access Token",
                "Dashboard Access Missing",
                "Dashboard Signed Out",
            }
            else "<a class='btn' href='/'>Return to Dashboard</a>"
        )
        body = (
            masthead()
            + "<main class='error-layout'><section class='error-card'>"
            + "<div class='error-content'>"
            + "<p class='error-kind'>Dashboard Error</p>"
            + f"<h1>{html.escape(content)}</h1>"
            + f"<p>{html.escape(guidance)}</p>"
            + "<p class='error-command'><code>scripts/dashboard-tunnel.sh SSH_TARGET</code></p>"
            + return_action
            + "</div></section></main>"
        )
    document_title = page_title or (
        "Gatekeeper Dashboard" if raw else f"Gatekeeper · {content}"
    )
    live_attributes = (
        f' data-live-refresh="{html.escape(live_refresh)}"'
        f' data-page-version="{html.escape(page_version)}"'
        f' data-poll-seconds="{DASHBOARD_POLL_SECONDS}"'
        if raw and live_refresh and page_version
        else ""
    )
    dashboard_script = (
        '<script src="/dashboard-theme.js"></script>'
        '<script src="/dashboard.js" defer></script>'
        if raw
        else ""
    )
    stylesheet = "/dashboard.css" if raw else "/dashboard-error.css"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(document_title)}</title>
<link rel="stylesheet" href="{stylesheet}">
{dashboard_script}</head><body{' data-dashboard-page' if raw else ''}{live_attributes}>{body}</body></html>""".encode("utf-8")
