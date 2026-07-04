# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Severity = Literal["none", "signal", "high", "critical"]
PlannedAction = Literal["allow", "challenge", "delete", "exception_review"]


@dataclass(frozen=True, slots=True)
class DetectionResult:
    detector: str
    signals: tuple[str, ...]
    severity: Severity
    score: float | None = None
    model_version: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    planned_action: PlannedAction
    reason: str
    policy_version: str = "rules-v2"


class PolicyEngine:
    def decide(self, detection: DetectionResult) -> PolicyDecision:
        if detection.severity == "critical":
            return PolicyDecision("delete", "critical_rule")
        return PolicyDecision("challenge", "unknown_sender")
