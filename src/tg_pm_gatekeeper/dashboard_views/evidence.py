# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

"""Evidence-signal and policy-decision panels."""

from __future__ import annotations

import html

from ..policy import EvidenceSignal, PolicyEngine
from .components import joined, json_block, key_values, text_block
from .labels import human_label


def signal_summary(value: object) -> str:
    if not isinstance(value, list) or not value:
        return "—"
    labels: list[str] = []
    for item in value:
        code = item.get("code") if isinstance(item, dict) else item
        if code:
            labels.append(human_label(str(code)))
    if not labels:
        return "—"
    remaining = len(labels) - 1
    return labels[0] + (f" · +{remaining} more" if remaining else "")


def signal_breakdown(value: object) -> str:
    if not isinstance(value, list) or not value:
        return "<span class='empty-value'>—</span>"
    items: list[str] = []
    for item in value:
        code = item.get("code") if isinstance(item, dict) else item
        if not code:
            continue
        title = html.escape(human_label(str(code)))
        source = item.get("source") if isinstance(item, dict) else None
        weight = item.get("weight") if isinstance(item, dict) else None
        explanation = item.get("explanation") if isinstance(item, dict) else None
        source_badge = (
            "<span class='signal-source'>"
            f"{html.escape(human_label(str(source)))}"
            "</span>"
            if source
            else ""
        )
        score_badge = (
            f"<span class='signal-score'>+{weight:g}</span>"
            if isinstance(weight, (int, float))
            else ""
        )
        explanation_copy = (
            f"<p class='signal-explanation'>{html.escape(str(explanation))}</p>"
            if explanation
            else ""
        )
        items.append(
            "<li class='signal-item'>"
            "<div class='signal-copy'>"
            f"<div class='signal-heading'><strong>{title}</strong>{score_badge}</div>"
            f"{source_badge}{explanation_copy}"
            "</div></li>"
        )
    if not items:
        return "<span class='empty-value'>—</span>"
    return (
        "<ol class='signal-list' aria-label='Evidence signals'>"
        + "".join(items)
        + "</ol>"
    )


def policy_decision_panel(
    payload: dict[str, object], *, note: str | None = None
) -> str:
    raw_score = payload.get("risk_score")
    if isinstance(raw_score, bool):
        risk_score = None
    else:
        try:
            risk_score = int(raw_score)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            risk_score = None
    if risk_score is None:
        return ""

    raw_signals = payload.get("signals", [])
    policy_signals = tuple(
        EvidenceSignal(
            str(item["code"]),
            str(item.get("source", "behavior")),  # type: ignore[arg-type]
            int(item.get("weight", 0)),
            str(item.get("explanation", "")),
        )
        for item in raw_signals
        if isinstance(item, dict) and item.get("code")
    ) if isinstance(raw_signals, list) else ()
    gate_basis = PolicyEngine.destructive_gate_basis(policy_signals)
    score_gate_met = risk_score >= PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD
    destructive_gate_met = gate_basis is not None
    planned_action = str(payload.get("planned_action", "not_recorded"))
    action_label = human_label(planned_action)
    action_class = {
        "standard_challenge": "standard",
        "strict_challenge": "strict",
        "permanent_suppression": "permanent",
    }.get(planned_action, "unknown")
    plotted_score = min(max(risk_score, 0), 100)
    policy_version = html.escape(str(payload.get("policy_version", "adaptive-v1")))

    if gate_basis == "owner_denied_domain":
        gate_label = "Met · Non-quoted owner-denied domain"
    elif gate_basis == "corroborated_repeated_campaign":
        gate_label = "Met · Corroborated cross-sender campaign"
    else:
        gate_label = (
            "Not met · No non-quoted denylist match or corroborated "
            "cross-sender campaign"
        )

    if planned_action == "permanent_suppression":
        outcome_copy = (
            "Both permanent-suppression conditions were met, so no challenge was sent."
        )
    elif score_gate_met and not destructive_gate_met:
        outcome_copy = (
            "The score reached 70, but permanent suppression also requires destructive "
            f"evidence. The recorded decision was {action_label.lower()}."
        )
    elif planned_action == "strict_challenge":
        outcome_copy = (
            "The score reached the strict threshold but not both permanent-suppression "
            "conditions."
        )
    else:
        outcome_copy = "The score remained below the strict-challenge threshold."

    score_state = "met" if score_gate_met else "unmet"
    gate_state = "met" if destructive_gate_met else "unmet"
    score_symbol = "✓" if score_gate_met else "×"
    gate_symbol = "✓" if destructive_gate_met else "×"
    return f"""
        <section class="rail-card policy-map" aria-label="Policy decision explanation">
          <div class="policy-outcome {action_class}">
            <small>Final Policy Decision</small><strong>{html.escape(action_label)}</strong>
            <p>{html.escape(outcome_copy)}</p>
          </div>
          <div class="policy-score-head">
            <div><span class="policy-kicker">Risk Score</span>
              <strong>{risk_score}</strong><small>Additive points · not a probability</small></div>
            <span class="policy-version">{policy_version}</span>
          </div>
          <div class="risk-track" role="img" aria-label="Risk score {risk_score}; strict challenge starts at {PolicyEngine.STRICT_CHALLENGE_THRESHOLD} and permanent score condition starts at {PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD}">
            <meter class="risk-meter" min="0" max="100" value="{plotted_score}">{plotted_score}%</meter>
            <span class="risk-mark strict-mark"><i>{PolicyEngine.STRICT_CHALLENGE_THRESHOLD}</i><b>Strict</b></span>
            <span class="risk-mark permanent-mark"><i>{PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD}</i><b>Permanent Score</b></span>
          </div>
          <p class="gate-formula">Permanent suppression requires <strong>both</strong> conditions:</p>
          <div class="gate-check {score_state}">
            <span class="gate-symbol" aria-hidden="true">{score_symbol}</span>
            <div><small>1 · Score Condition</small>
              <strong>{risk_score} ≥ {PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD}</strong>
              <p>Risk score reaches the permanent-suppression score threshold.</p></div>
          </div>
          <div class="gate-check {gate_state}">
            <span class="gate-symbol" aria-hidden="true">{gate_symbol}</span>
            <div><small>2 · Destructive Evidence</small>
              <strong>{html.escape(gate_label)}</strong>
              <p>Requires a non-quoted denied domain, or a corroborated repeated campaign.</p></div>
          </div>
          {f'<p class="policy-note">{html.escape(note)}</p>' if note else ''}
        </section>"""


def recomputed_policy_panel(recorded_signals: object) -> str:
    """Rebuild the policy view for a review, which records signals but not a score."""
    if not isinstance(recorded_signals, list) or not recorded_signals:
        return ""
    signals: list[EvidenceSignal] = []
    for item in recorded_signals:
        if not isinstance(item, dict):
            return ""
        code, source, weight = item.get("code"), item.get("source"), item.get("weight")
        # Legacy HR-rule rows carry bare codes without weights; they cannot be scored.
        if (
            not isinstance(code, str)
            or not isinstance(source, str)
            or isinstance(weight, bool)
            or not isinstance(weight, int)
        ):
            return ""
        signals.append(EvidenceSignal(code, source, weight, ""))  # type: ignore[arg-type]
    decision = PolicyEngine().decide(tuple(signals))
    return policy_decision_panel(
        {
            "risk_score": decision.risk_score,
            "signals": recorded_signals,
            "planned_action": decision.planned_action,
            "policy_version": decision.policy_version,
        },
        note=(
            "Recomputed from the recorded signal weights with the current policy. "
            "Reviews do not store their original score."
        ),
    )


def policy_thresholds() -> str:
    strict = PolicyEngine.STRICT_CHALLENGE_THRESHOLD
    permanent = PolicyEngine.PERMANENT_SUPPRESSION_THRESHOLD
    version = html.escape(PolicyEngine().decide(()).policy_version)
    return (
        "<section class='policy-thresholds' aria-label='Scoring policy thresholds'>"
        f"<h2>Scoring Policy <span class='policy-version'>{version}</span></h2>"
        "<ol class='threshold-scale'>"
        f"<li class='tone-allow'><b>0–{strict - 1}</b><span>Standard Challenge</span></li>"
        f"<li class='tone-hold'><b>{strict}+</b><span>Strict Challenge</span></li>"
        f"<li class='tone-block'><b>{permanent}+</b><span>Permanent Suppression, only with "
        "a non-quoted owner-denied domain or a corroborated repeated campaign</span></li>"
        "</ol></section>"
    )


def review_sections(payload: dict[str, object]) -> tuple[str, str, str]:
    text = str(payload.get("text", ""))
    quote_text = str(payload.get("quote_text", ""))
    preview_text = str(payload.get("preview_text", ""))
    structural_only = not (
        text.strip() or quote_text.strip() or preview_text.strip()
    )
    button_texts = joined(payload.get("button_texts", []))
    domains = joined(payload.get("domains", []))
    quote_domains = joined(payload.get("quote_domains", []))
    details = json_block(payload)
    urls = json_block(payload.get("urls", []))
    quote_urls = json_block(payload.get("quote_urls", []))
    url_shape = json_block(payload.get("url_shape", {}))
    quote_url_shape = json_block(payload.get("quote_url_shape", {}))
    sections = (
        text_block("Message Text or Caption", text)
        + text_block("Quoted Context", quote_text, quote=True)
        + text_block("Telegram Webpage Preview", preview_text, quote=True)
    )
    if structural_only:
        sections += (
            "<div class='notice'><strong>Limited Textual Evidence</strong> "
            "No message text, quoted text, or webpage-preview text was retained. "
            "Review any available URLs, button text, evidence signals, and structural "
            "metadata before deciding whether to allow the sender or leave the "
            "restriction unchanged.</div>"
        )

    def value(text: str) -> str:
        if text == "—":
            return "<span class='empty-value'>—</span>"
        return f"<span class='mono'>{html.escape(text)}</span>"

    link_facts = key_values(
        [
            ("Button Text", value(button_texts)),
            ("Normalized Domains", value(domains)),
            ("Quoted-Context Domains", value(quote_domains)),
        ]
    )
    technical = (
        f"<details><summary>Full URLs</summary><pre>{urls}</pre></details>"
        + f"<details><summary>Quoted-Context URLs</summary><pre>{quote_urls}</pre></details>"
        + f"<details><summary>Link Shape</summary><pre>{url_shape}</pre></details>"
        + f"<details><summary>Quoted-Context Link Shape</summary><pre>{quote_url_shape}</pre></details>"
        + f"<details><summary>Full Decrypted Case Payload</summary><pre>{details}</pre></details>"
    )
    return sections, link_facts, technical
