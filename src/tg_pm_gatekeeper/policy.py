# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SignalSource = Literal[
    "authored", "button", "preview", "quoted", "behavior", "owner_policy"
]
ChallengeProfile = Literal["standard", "strict"]
ScreeningAction = Literal[
    "standard_challenge", "strict_challenge", "permanent_suppression"
]


@dataclass(frozen=True, slots=True)
class EvidenceSignal:
    code: str
    source: SignalSource
    weight: int
    explanation: str


@dataclass(frozen=True, slots=True)
class ScreeningDecision:
    signals: tuple[EvidenceSignal, ...]
    risk_score: int
    challenge_profile: ChallengeProfile | None
    planned_action: ScreeningAction
    decision_basis: str
    policy_version: str = "adaptive-v1"


class PolicyEngine:
    STRICT_CHALLENGE_THRESHOLD = 30
    PERMANENT_SUPPRESSION_THRESHOLD = 70

    def decide(self, signals: tuple[EvidenceSignal, ...]) -> ScreeningDecision:
        risk_score = sum(signal.weight for signal in signals)
        codes = {signal.code for signal in signals}
        denied_authored_source = bool(
            codes.intersection(
                {
                    "AUTHORED_DENIED_DOMAIN",
                    "BUTTON_DENIED_DOMAIN",
                    "PREVIEW_DENIED_DOMAIN",
                }
            )
        )
        repeated_campaign_gate = {
            "REPEATED_CAMPAIGN",
            "FORWARDED_PAYLOAD",
        }.issubset(codes) and bool(
            codes.intersection({"MULTIPLE_LINKS", "QUOTED_MULTIPLE_LINKS"})
        ) and bool(
            codes.intersection(
                {"PROMOTIONAL_LANGUAGE", "QUOTED_PROMOTIONAL_LANGUAGE"}
            )
        )
        destructive_gate = denied_authored_source or repeated_campaign_gate

        if risk_score >= self.PERMANENT_SUPPRESSION_THRESHOLD and destructive_gate:
            basis = (
                "owner_denied_domain"
                if denied_authored_source
                else "corroborated_repeated_campaign"
            )
            return ScreeningDecision(
                signals, risk_score, None, "permanent_suppression", basis
            )
        if risk_score >= self.STRICT_CHALLENGE_THRESHOLD:
            return ScreeningDecision(
                signals,
                risk_score,
                "strict",
                "strict_challenge",
                "risk_score_requires_strict_challenge",
            )
        return ScreeningDecision(
            signals,
            risk_score,
            "standard",
            "standard_challenge",
            "risk_score_below_strict_threshold",
        )
