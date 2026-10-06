# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Human-readable labels, tones, and relative times for dashboard values."""

from __future__ import annotations

import time
from typing import Any

from ..states import SenderStatus


def human_label(value: str) -> str:
    labels = {
        "would_challenge": "Simulated Challenge · Monitor",
        "would_delete": "Planned Deletion · Monitor",
        "would_quarantine": "Simulated Quarantine · Monitor",
        "challenge_unavailable": "Challenge Unavailable · Protect",
        "challenge_unavailable_action_failed": "Challenge and Archive Failed · Protect",
        "restore_failed": "Restoration Failed · Protect",
        "warning_failed": "Failure Warning Not Delivered · Protect",
        "timeout_notice_failed": "Timeout Warning Not Delivered · Protect",
        "critical_rule": "Legacy Critical Rule Match",
        "permanent_suppression": "Permanent Suppression",
        "standard_challenge": "Standard Challenge",
        "strict_challenge": "Strict Challenge",
        "owner_denied_domain": "Owner Denied Domain",
        "corroborated_repeated_campaign": "Corroborated Repeated Campaign",
        "risk_score_requires_strict_challenge": "Risk Score Requires Strict Challenge",
        "risk_score_below_strict_threshold": "Risk Score Below Strict Threshold",
        "manual_operator_decision": "Manual Operator Decision",
        "manual_permanent_suppression": "Manual Permanent Suppression",
        "manual_spam": "Manual Spam Review",
        "attempts_exhausted": "Attempts Exhausted",
        "challenge_timeout": "Challenge Timeout",
        "challenge_pending": "Challenge Pending",
        "reference_unavailable": "Telegram Reference Unavailable",
        "reason_unavailable": "Reason Unavailable",
        "spam_candidate": "Spam Candidate",
        "legitimate_candidate": "Legitimate Candidate",
        "not recorded": "Not Recorded",
    }
    if value in labels:
        return labels[value]
    if value == "uncertain":
        return "Uncertain"
    if value.endswith("_action_failed"):
        action = value.removesuffix("_action_failed").replace("_", " ").title()
        return f"{action} Action Failed · Protect"
    prefix = ""
    body = value
    if value.startswith("HR-") and "_" in value:
        # HR rule codes predate adaptive scoring and survive only in old rows.
        prefix, body = value.split("_", 1)
        prefix = f"Legacy {prefix} · "
    label = body.replace("_", " ").strip().title()
    label = label.replace("Url", "URL").replace("Vpn", "VPN")
    label = label.replace("Webview", "WebView")
    return prefix + label


def reason_label(reason: str) -> str:
    return human_label(reason)


def list_reason_label(reason: str) -> str:
    labels = {
        "challenge_timeout": "Challenge timed out",
        "timeout_notice_failed": "Timeout warning failed",
        "warning_failed": "Failure warning failed",
        "manual_permanent_suppression": "Manual suppression",
        "attempts_exhausted": "Attempts exhausted",
    }
    return labels.get(reason, human_label(reason))


def case_tone(status: str, *, archived: bool = False) -> str:
    if archived:
        return "neutral"
    return {"quarantined": "hold", "suppressed": "block"}.get(status, "neutral")


def review_tone(classification: str) -> str:
    return "monitor" if classification.startswith("would_") else "hold"


def relative_age(created_at: int) -> str:
    seconds = max(0, int(time.time()) - created_at)
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def remaining(item: Any) -> str:
    if item.status == SenderStatus.QUARANTINED:
        return "Manual review required"
    if item.suppressed_until is None:
        return "No automatic release"
    seconds = item.suppressed_until - int(time.time())
    if seconds <= 0:
        return "Release pending"
    if seconds < 3600:
        return f"{max(1, seconds // 60)}m remaining"
    if seconds < 86400:
        return f"{max(1, seconds // 3600)}h remaining"
    return f"{max(1, seconds // 86400)}d remaining"


def restriction_summary(item: Any) -> str:
    if item.status == SenderStatus.QUARANTINED:
        return "Review needed"
    if item.suppressed_until is None:
        return "No automatic release"
    if item.suppressed_until <= int(time.time()):
        return "Awaiting next message"
    return remaining(item)
