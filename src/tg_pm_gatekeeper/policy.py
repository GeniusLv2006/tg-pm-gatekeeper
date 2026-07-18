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
    policy_version: str = "adaptive-v2"


class PolicyEngine:
    STRICT_CHALLENGE_THRESHOLD = 30
    PERMANENT_SUPPRESSION_THRESHOLD = 70

    @staticmethod
    def destructive_gate_basis(
        signals: tuple[EvidenceSignal, ...],
    ) -> str | None:
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
        repeated_campaign_core = {
            "REPEATED_CAMPAIGN",
        }.issubset(codes) and bool(
            codes.intersection({"MULTIPLE_LINKS", "QUOTED_MULTIPLE_LINKS"})
        )
        forwarded_promotion = "FORWARDED_PAYLOAD" in codes and bool(
            codes.intersection(
                {"PROMOTIONAL_LANGUAGE", "QUOTED_PROMOTIONAL_LANGUAGE"}
            )
        )
        preview_promotion = any(
            signal.code == "PREVIEW_PROMOTIONAL_LANGUAGE"
            and signal.source == "preview"
            for signal in signals
        ) and any(
            signal.code == "MULTIPLE_LINKS" and signal.source == "preview"
            for signal in signals
        )
        repeated_campaign_gate = repeated_campaign_core and (
            forwarded_promotion or preview_promotion
        )
        if denied_authored_source:
            return "owner_denied_domain"
        if repeated_campaign_gate:
            return "corroborated_repeated_campaign"
        return None

    def decide(self, signals: tuple[EvidenceSignal, ...]) -> ScreeningDecision:
        risk_score = sum(signal.weight for signal in signals)
        destructive_basis = self.destructive_gate_basis(signals)

        if (
            risk_score >= self.PERMANENT_SUPPRESSION_THRESHOLD
            and destructive_basis is not None
        ):
            return ScreeningDecision(
                signals,
                risk_score,
                None,
                "permanent_suppression",
                destructive_basis,
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
