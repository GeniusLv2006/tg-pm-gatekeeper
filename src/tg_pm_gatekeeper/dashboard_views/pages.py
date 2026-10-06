# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Full dashboard pages rendered from broker results."""

from __future__ import annotations

import html
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import urlencode

from ..dashboard_protocol import JsonObject
from ..states import SenderStatus
from .components import (
    action_form,
    badge,
    change_notice,
    identity_cell,
    identity_from_value,
    identity_meta,
    key_values,
    masthead,
    page_header,
    pagination,
    render_page,
)
from .evidence import (
    policy_decision_panel,
    policy_thresholds,
    recomputed_policy_panel,
    review_sections,
    signal_breakdown,
    signal_summary,
)
from .labels import (
    case_tone,
    human_label,
    list_reason_label,
    reason_label,
    relative_age,
    remaining,
    restriction_summary,
    review_tone,
)


def paged_target(base: str, page: int) -> str:
    """The list address, including its page number, that a page version is computed for."""
    return base if page == 1 else f"{base}{'&' if '?' in base else '?'}page={page}"


def cases_list_base(*, archived: bool, reason: str | None, older_days: int | None) -> str:
    base = "/cases/archive" if archived else "/cases"
    filter_values: dict[str, object] = {}
    if reason:
        filter_values["reason"] = reason
    if older_days:
        filter_values["older_days"] = older_days
    return base + (f"?{urlencode(filter_values)}" if filter_values else "")


def overview_page(
    result: JsonObject, *, csrf_token: str, page_version: str | None
) -> bytes:
    pending_reviews = int(result["pending_reviews"])
    active_stats = result["active_stats"]
    active_restrictions = active_stats["quarantined"] + active_stats["suppressed"]
    storage_stats = result.get("storage_stats")
    if not isinstance(storage_stats, dict):
        storage_stats = {
            "attention_cases": active_restrictions,
            "archived_restrictions": 0,
            "database_page_count": 0,
            "database_page_size": 0,
            "database_logical_bytes": 0,
            "database_freelist_count": 0,
            "database_freelist_percent": 0,
            "temporary_released": 0,
            "auto_forgotten": 0,
            "auto_forget_skipped": 0,
        }
    mode = str(result["mode"])

    def queue_card(href: str, title: str, note: str, count: int, tone: str) -> str:
        state = f"tone-{tone}" if count else "is-empty"
        return (
            f"<a class='queue-card {state}' href='{href}'>"
            f"<span class='queue-count'>{count}</span>"
            f"<strong>{title}</strong><span class='queue-note'>{note}</span></a>"
        )

    content = (
        masthead("overview", csrf_token=csrf_token)
        + "<main class='page'><div class='live-region' data-live-region='operations'>"
        + page_header(
            "Operations Dashboard",
            lede="Review restrictions, recover false positives, and resolve pending decisions.",
            aside=badge(
                f"{mode.title()} Mode", "monitor" if mode == "monitor" else "allow"
            ),
        )
        + "<nav class='queue-grid' aria-label='Review areas'>"
        + queue_card(
            "/review", "Pending Reviews",
            "Resolve simulations and exception reviews.", pending_reviews, "monitor",
        )
        + queue_card(
            "/cases", "Active Cases · Needs Attention",
            "Review unresolved restrictions and failures.",
            int(storage_stats["attention_cases"]), "hold",
        )
        + queue_card(
            "/cases/archive", "Archived Restrictions",
            "Review or forget confirmed permanent restrictions.",
            int(storage_stats["archived_restrictions"]), "neutral",
        )
        + "</nav><dl class='stat-strip stat-strip-wide'>"
        f"<div><dt>Active Restrictions</dt><dd class='data-value'>{active_restrictions}</dd></div>"
        f"<div><dt>Reviewable Cases</dt><dd class='data-value'>{active_stats['reviewable']}</dd></div>"
        "</dl>"
        + policy_thresholds()
        + "<details class='context-note'><summary>Storage and Maintenance</summary>"
        f"<p>Needs attention: {storage_stats['attention_cases']} · "
        f"Archived: {storage_stats['archived_restrictions']} · "
        f"Database: {storage_stats['database_logical_bytes']} bytes "
        f"({storage_stats['database_page_count']} pages × "
        f"{storage_stats['database_page_size']} bytes) · "
        f"Free pages: {storage_stats['database_freelist_count']} "
        f"({storage_stats['database_freelist_percent']}%).</p>"
        f"<p>Last maintenance: released {storage_stats['temporary_released']} temporary restrictions, "
        f"forgot {storage_stats['auto_forgotten']} archived restrictions, "
        f"skipped {storage_stats['auto_forget_skipped']} with unfinished work.</p>"
        "</details></div></main>"
    )
    return render_page(
        content,
        raw=True,
        page_title="Operations Dashboard",
        live_refresh="replace",
        page_version=page_version,
    )


def review_queue_page(
    result: JsonObject, *, page: int, csrf_token: str, page_version: str | None
) -> bytes:
    total = int(result["total"])
    items = [SimpleNamespace(**value) for value in result["items"]]

    def row(item: SimpleNamespace) -> str:
        tone = review_tone(item.classification)
        identity = identity_cell(
            identity_from_value(item.identity), href=f"/review/{item.id}"
        )
        return (
            f"<tr class='tone-{tone}'>"
            f"<td data-label='Sender'>{identity}</td>"
            f"<td data-label='Review'>{badge(human_label(item.classification), tone)}"
            f"<span class='cell-note'>Review #{item.id}</span></td>"
            f"<td data-label='Signals'>{html.escape(signal_summary(json.loads(item.signals)))}</td>"
            f"<td data-label='Messages' class='numeric'>{item.message_count}</td>"
            f"<td data-label='Age' class='age'>{html.escape(relative_age(item.updated_at))}</td>"
            "</tr>"
        )

    rows = "".join(row(item) for item in items) or (
        "<tr class='empty-row'><td colspan='5'>No pending reviews.</td></tr>"
    )
    return render_page(
        masthead("reviews", csrf_token=csrf_token)
        + "<main class='page'><div class='live-region' data-live-region='pending-reviews'>"
        + page_header(
            "Pending Reviews",
            count=str(total),
            lede="Open a sender to fetch message content and make a decision.",
        )
        + "<details class='context-note'><summary>Review and Refresh Behavior</summary>"
        "<p>Identity is cached briefly in memory; message content is fetched only on the detail page. "
        "Deleted Telegram conversations leave their local review available for resolution. "
        "The list refreshes in place only when review state changes.</p></details>"
        "<div class='table-shell'><table class='data-table reviews-table'><thead><tr><th>Sender</th><th>Review</th>"
        "<th>Signals</th><th>Messages</th>"
        f"<th>Age</th></tr></thead><tbody>{rows}</tbody></table></div>"
        + pagination("/review", page, total)
        + "</div></main>",
        raw=True,
        page_title="Pending Reviews",
        live_refresh="replace",
        page_version=page_version,
    )


def review_detail_page(
result: JsonObject, *, csrf_token: str, page_version: str | None
) -> bytes:
    item = SimpleNamespace(**result)
    identity_value = identity_from_value(result.get("identity"))
    identity = "Identity Unavailable"
    user_id: int | None = None
    if identity_value is not None:
        user_id = identity_value.user_id
        identity = identity_value.name or "Name Unavailable"
        if identity_value.username:
            identity += f" (@{identity_value.username})"
    recorded_signals = json.loads(item.signals)
    signals = signal_breakdown(recorded_signals)
    policy_panel = recomputed_policy_panel(recorded_signals)
    review_reason = human_label(item.classification)
    tone = review_tone(item.classification)
    features = json.dumps(json.loads(item.features), indent=2, sort_keys=True)
    observed_at = datetime.fromtimestamp(item.updated_at, timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )
    text = result.get("message")
    facts_rows: list[tuple[str, str]] = []
    if text is not None and user_id is not None:
        facts_rows.append(("Telegram ID", f"<span class='mono'>{user_id}</span>"))
    facts_rows += [
        ("Messages Observed", str(item.message_count)),
        ("Last Observed", observed_at),
    ]
    facts = key_values(facts_rows)
    if text is None:
        message_panel = (
            "<section class='panel'><div class='panel-head'>"
            "<h2 class='panel-title'>Telegram Message Unavailable</h2></div>"
            "<div class='empty-state'><strong>The referenced message no longer exists.</strong>"
            "<p>The conversation may have been deleted in Telegram. This pending row is local "
            "review state and is not removed automatically.</p></div></section>"
        )
        decision = (
            "<section class='rail-card decision-card'>"
            "<h2 class='rail-title'>Dismiss Pending Reviews</h2>"
            "<p class='rail-help'>Remove this sender's pending review and cancel pending "
            "Gatekeeper deletion jobs. Telegram and trust state are unchanged.</p>"
            "<div class='action-stack'>"
            + action_form(csrf_token, item.id, "dismiss", "Dismiss & Cancel Jobs")
            + "</div></section>"
        )
        technical = ""
    else:
        message_panel = (
            "<section class='panel'><div class='panel-head'>"
            "<h2 class='panel-title'>Message</h2>"
            "<p class='panel-note'>Fetched from Telegram · Not Stored Locally</p></div>"
            f"<pre class='message'>{html.escape(str(text))}</pre></section>"
        )
        decision = (
            "<section class='rail-card decision-card'>"
            "<h2 class='rail-title'>Sender Decision</h2>"
            "<p class='rail-help'>This decision applies to all pending entries for this "
            "sender.</p><div class='action-stack'>"
            + action_form(csrf_token, item.id, "legitimate", "Allow Sender", tone="allow")
            + f"<a class='btn btn-block' href='/review/{item.id}/spam'>Suppress and Delete…</a>"
            + action_form(csrf_token, item.id, "dismiss", "Dismiss & Cancel Jobs")
            + "</div></section>"
        )
        technical = (
            "<section class='panel panel-quiet'><h2 class='panel-title'>Technical Details</h2>"
            f"<details><summary>Structural Features</summary><pre>{html.escape(features)}</pre>"
            "</details></section>"
        )
    content = (
        masthead("reviews", csrf_token=csrf_token)
        + "<main class='page detail-page'>"
        + page_header(
            identity,
            meta=identity_meta(
                user_id if text is not None else None, review_id=item.id
            ),
            back=("/review", "Pending Reviews"),
            aside=badge(review_reason, tone),
        )
        + "<div class='detail-grid'><div class='evidence-column'>"
        + message_panel
        + "<section class='panel'><h2 class='panel-title'>Evidence Signals</h2>"
        + f"<div class='signal-breakdown'>{signals}</div></section>"
        + technical
        + "</div><aside class='decision-rail' aria-label='Decision'>"
        + change_notice()
        + decision
        + policy_panel
        + "<section class='rail-card'><h2 class='rail-title'>Review Details</h2>"
        + facts
        + "</section></aside></div></main>"
    )
    return render_page(
        content,
        raw=True,
        page_title=f"Review #{item.id}",
        live_refresh="notice",
        page_version=page_version,
    )


def cases_page(
result: JsonObject,
*,
page: int,
archived: bool,
reason: str | None,
older_days: int | None,
csrf_token: str,
page_version: str | None,
) -> bytes:
    total = int(result["total"])
    items = [SimpleNamespace(**value) for value in result["items"]]
    stats = result["stats"]
    def sender_cell(item: SimpleNamespace) -> str:
        if archived:
            return (
                f"<a class='identity-link row-link' href='/cases/{item.sender_key}'>"
                "Archived Sender</a>"
            )
        return identity_cell(
            identity_from_value(item.identity),
            href=f"/cases/{item.sender_key}",
        )

    def row(item: SimpleNamespace) -> str:
        tone = case_tone(item.status, archived=archived)
        evidence = (
            "<span class='availability'>Ready</span>"
            if item.has_evidence
            else "<span class='availability availability-unavailable'>Unavailable</span>"
        )
        age = relative_age(item.archived_at if archived else item.updated_at)
        return (
            f"<tr class='tone-{tone}'>"
            f"<td data-label='Sender'>{sender_cell(item)}</td>"
            f"<td data-label='State'>{badge(human_label(item.status), tone)}"
            f"<span class='cell-note'>{html.escape(restriction_summary(item))}</span></td>"
            f"<td data-label='Trigger'>{html.escape(list_reason_label(item.reason))}</td>"
            f"<td data-label='Evidence'>{evidence}</td>"
            f"<td data-label='Age' class='age'>{html.escape(age)}</td>"
            "</tr>"
        )

    rows = "".join(row(item) for item in items) or (
        "<tr class='empty-row'><td colspan='5'>"
        f"No {'archived' if archived else 'active'} restrictions.</td></tr>"
    )
    scope = "archived" if archived else "active"
    reason_counts = sorted(
        (key.removeprefix("reason:"), value)
        for key, value in stats.items()
        if key.startswith("reason:")
    )
    reasons = " · ".join(
        f"{html.escape(reason_label(reason))} {count}"
        for reason, count in reason_counts
    ) or f"No {scope} reasons"
    snapshot_note = (
        f"{stats['unreviewable']} restriction"
        f"{'s' if stats['unreviewable'] != 1 else ''} "
        f"{'have' if stats['unreviewable'] != 1 else 'has'} no reviewable evidence; "
        "the restriction remains visible and manageable."
        if stats["unreviewable"]
        else f"Every {scope} restriction currently has reviewable evidence."
    )
    identity_note = (
        f" {stats['unidentified']} restriction"
        f"{'s' if stats['unidentified'] != 1 else ''} without a control identity require"
        f"{'s' if stats['unidentified'] == 1 else ''} manual ID recovery."
        if stats["unidentified"]
        else f" Every {scope} restriction has a retained encrypted control identity."
    )
    # Recovery spans both lists, so an archived restriction without identity stays reachable.
    unidentified_total = int(result.get("unidentified_total", stats["unidentified"]))
    recovery = ""
    if unidentified_total:
        recovery = (
            "<details class='advanced-recovery'><summary>Advanced Recovery"
            f" <span class='summary-note'>{unidentified_total} unidentified</span></summary>"
            "<div class='advanced-recovery-content'>"
            "<h2>Allow an Unidentified Restricted Sender by Telegram User ID</h2>"
            "<p>Use this only for a restriction without an encrypted control identity, such as "
            "one created before control identities were retained or when Gatekeeper could "
            "not keep a Telegram reference. This removes the Gatekeeper restriction and cancels "
            "pending deletion jobs, but cannot restore saved Telegram folder or notification "
            "state without a peer reference. The entered ID is used only to derive the "
            "existing sender key and is not stored.</p>"
            "<form class='manual-release' method='post' action='/cases/release'>"
            f"<input type='hidden' name='token' value='{csrf_token}'>"
            "<label for='release-user-id'>Telegram User ID</label>"
            "<input id='release-user-id' name='user_id' type='text' inputmode='numeric' "
            "pattern='[0-9]+' autocomplete='off' required>"
            "<button class='btn btn-block' type='submit'>Allow Without Restore</button>"
            "</form></div></details>"
        )
    filtered_base = cases_list_base(
        archived=archived, reason=reason, older_days=older_days
    )
    archive_tools = ""
    if archived:

        def filter_link(label: str, values: Mapping[str, object], current: bool) -> str:
            query = f"?{urlencode(values)}" if values else ""
            marker = " aria-current='true'" if current else ""
            return f"<a href='/cases/archive{query}'{marker}>{html.escape(label)}</a>"

        age_filter = {"older_days": older_days} if older_days else {}
        reason_filter = {"reason": reason} if reason else {}
        reason_links = filter_link("All", age_filter, reason is None) + "".join(
            filter_link(
                reason_label(item_reason),
                {"reason": item_reason, **age_filter},
                reason == item_reason,
            )
            for item_reason, _ in reason_counts
        )
        age_links = filter_link("Any age", reason_filter, older_days is None) + "".join(
            filter_link(f"{days} days", {**reason_filter, "older_days": days}, older_days == days)
            for days in (30, 90, 180, 365)
        )
        forget_links = "".join(
            f"<a href='/cases/archive/forget?days={days}'>{days} days</a>"
            for days in (30, 90, 180, 365)
        )
        # One label column keeps both filters and the cleanup action aligned.
        archive_tools = (
            "<section class='archive-tools' aria-label='Archive filters and cleanup'>"
            "<span class='filter-label'>Reason</span>"
            f"<nav class='segmented' aria-label='Filter by reason'>{reason_links}</nav>"
            "<span class='filter-label'>Minimum archive age</span>"
            f"<nav class='segmented' aria-label='Minimum archive age'>{age_links}</nav>"
            "<hr class='tools-divider'>"
            "<span class='filter-label'>Preview release and forget</span>"
            "<nav class='segmented segmented-danger' aria-label='Preview release and forget'>"
            f"{forget_links}</nav></section>"
        )
    if archived:
        lede = (
            "Permanent restrictions you chose to keep. They remain enforced by local "
            "policy; review them or forget them here."
        )
    else:
        lede = (
            "Review every current restriction. Evidence availability is tracked "
            "separately; Telegram block is never used."
        )
    # Statistics cover exactly the restrictions this list shows.
    if archived:
        stat_items = [
            ("Reviewable Evidence", stats["reviewable"]),
            ("Evidence Unavailable", stats["unreviewable"]),
        ]
    else:
        stat_items = [
            ("Quarantined", stats["quarantined"]),
            ("Suppressed", stats["suppressed"]),
            ("Reviewable Evidence", stats["reviewable"]),
        ]
    stat_strip = (
        "<dl class='stat-strip'>"
        + "".join(
            f"<div><dt>{label}</dt><dd class='data-value'>{value}</dd></div>"
            for label, value in stat_items
        )
        + "</dl>"
    )
    live_region = "archived-restrictions" if archived else "active-cases"
    content = (
        masthead("archive" if archived else "cases", csrf_token=csrf_token)
        + "<main class='page'>"
        + f"<div class='live-region' data-live-region='{live_region}'>"
        + page_header(
            "Archived Restrictions" if archived else "Needs Attention",
            count=str(total),
            lede=lede,
            aside=stat_strip,
        )
        + "<details class='context-note'><summary>Restriction Context</summary>"
        + f"<p><strong>State reasons:</strong> {reasons}. {snapshot_note}{identity_note}</p></details>"
        + archive_tools
        + "<div class='table-shell'><table class='data-table cases-table'><thead><tr><th>Sender</th><th>State</th><th>Trigger</th><th>Evidence</th><th>Age</th></tr></thead>"
        + f"<tbody>{rows}</tbody></table></div>"
        + pagination(filtered_base, page, total)
        + "</div>"
        + "<section class='advanced-recovery-wrap' data-live-region='legacy-recovery'>"
        + recovery
        + "</section></main>"
    )
    return render_page(
        content,
        raw=True,
        page_title="Archived Restrictions" if archived else "Active Cases",
        live_refresh="replace",
        page_version=page_version,
    )


def case_detail_page(
result: JsonObject, *, csrf_token: str, page_version: str | None
) -> bytes:
    item = SimpleNamespace(**result)
    payload = result.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    evidence_available = result.get("evidence_available") is True
    unavailable_note = {
        "authentication_failed": (
            "Encrypted evidence failed authentication and was not shown."
        ),
        "missing": "No message evidence is retained.",
    }.get(
        str(result.get("evidence_unavailable_reason")),
        "Encrypted evidence cannot be opened by this runtime.",
    )
    identity_value = identity_from_value(result.get("identity"))
    identity = "Identity Unavailable"
    user_id: int | None = None
    if identity_value is not None:
        user_id = identity_value.user_id
        identity = identity_value.name or "Name Unavailable"
        if identity_value.username:
            identity += f" (@{identity_value.username})"
    signals_html = signal_breakdown(payload.get("signals", []))
    policy_panel = policy_decision_panel(payload)
    features = json.dumps(payload.get("features", {}), indent=2, sort_keys=True)
    observed_at = item.evidence_created_at or item.updated_at
    observed = datetime.fromtimestamp(observed_at, timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )
    evidence_expiry = (
        datetime.fromtimestamp(item.evidence_expires_at, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        if item.evidence_expires_at is not None
        else "Expired or unavailable"
    )
    if evidence_available:
        message_html, link_facts, technical = review_sections(payload)
        evidence_heading = "Decrypted Local Evidence"
        evidence_note = "Encrypted at rest; decrypted only for this owner-only view."
        evidence_panels = (
            "<section class='panel'><h2 class='panel-title'>Links and Buttons</h2>"
            f"{link_facts}</section>"
        )
    else:
        message_html = (
            "<div class='empty-state'><strong>Evidence expired or unavailable.</strong> "
            "The encrypted control identity is retained only so this restriction remains "
            "visible and reversible.</div>"
        )
        technical = ""
        evidence_heading = "Restriction Control"
        evidence_note = (
            unavailable_note + " Only the encrypted control identity remains available."
        )
        evidence_panels = ""
    allow_action = (
        action_form(
            csrf_token, item.sender_key, "allow", "Allow Sender", base="cases", tone="allow"
        )
        if user_id is not None
        else "<button class='btn' type='button' disabled>Allow Unavailable</button>"
    )
    if result.get("has_dialog_snapshot") is True:
        allow_guidance = (
            "Allow restores the saved folder and notification state before changing policy."
        )
    else:
        allow_guidance = (
            "No saved dialog state is available. Allow moves the conversation to the main "
            "folder and enables notifications before changing policy."
        )
    archived = item.archived_at is not None
    if archived:
        secondary_action = action_form(
            csrf_token, item.sender_key, "unarchive", "Move to Needs Attention", base="cases"
        )
        if not item.has_open_actions:
            secondary_action += (
                f"<a class='btn btn-block-outline' href='/cases/{item.sender_key}/forget'>"
                "Release and Forget…</a>"
            )
    elif item.status == SenderStatus.SUPPRESSED and item.suppressed_until is None:
        secondary_action = (
            f"<a class='btn' href='/cases/{item.sender_key}/archive'>"
            "Keep and Archive…</a>"
        )
    else:
        secondary_action = ""
    back = (
        ("/cases/archive", "Archived Restrictions")
        if archived
        else ("/cases", "Needs Attention")
    )
    status_label = human_label(item.status)
    tone = case_tone(item.status, archived=archived)
    meta = identity_meta(user_id)
    technical_panel = (
        "<section class='panel panel-quiet'><h2 class='panel-title'>Technical Details</h2>"
        f"{technical}"
        f"<details><summary>Structural Features</summary><pre>{html.escape(features)}</pre></details>"
        "</section>"
    )
    facts = key_values(
        [
            ("Restriction Cause", html.escape(human_label(item.reason))),
            ("Triggered", observed),
            ("Restriction", html.escape(remaining(item))),
            ("Evidence Expires", evidence_expiry),
        ]
    )
    content = (
        masthead("archive" if archived else "cases", csrf_token=csrf_token)
        + "<main class='page detail-page'>"
        + page_header(
            identity,
            meta=meta,
            back=back,
            aside=badge(
                "Archived · " + status_label if archived else status_label, tone
            ),
        )
        + f"""
        <div class="detail-grid">
          <div class="evidence-column">
            <section class="panel">
              <div class="panel-head"><h2 class="panel-title">{evidence_heading}</h2>
                <p class="panel-note">{evidence_note}</p></div>
              {message_html}
            </section>
            {evidence_panels}
            <section class="panel"><h2 class="panel-title">Evidence Signals</h2>
              <div class="signal-breakdown">{signals_html}</div></section>
            {technical_panel}
          </div>
          <aside class="decision-rail" aria-label="Decision">
            {change_notice()}
            <section class="rail-card decision-card"><h2 class="rail-title">Operator Action</h2>
              <p class="rail-help">{html.escape(allow_guidance)}</p>
              <div class="action-stack">{allow_action}{secondary_action}</div></section>
            {policy_panel}
            <section class="rail-card"><h2 class="rail-title">Restriction Details</h2>{facts}</section>
          </aside>
        </div></main>"""
    )
    return render_page(
        content,
        raw=True,
        page_title=f"Active Case · {status_label}",
        live_refresh="notice",
        page_version=page_version,
    )
