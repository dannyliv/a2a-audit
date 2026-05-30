"""Composite posture scoring: findings -> 0-100 score + letter grade.

This is the differentiator: a transparent, opinionated,
diffable grade per card. Score starts at 100 and subtracts a penalty per
non-passing finding = severity_weight x check_weight. Weights are configurable
so teams can tune the opinion without forking.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from a2a_audit.finding import Finding, Severity

_DEFAULT_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.0,
    Severity.MEDIUM: 8.0,
    Severity.HIGH: 18.0,
    Severity.CRITICAL: 30.0,
}

# Per-check multipliers (mirror CheckMeta.weight; kept here so scoring is
# self-contained and overridable without importing every check).
_DEFAULT_CHECK_WEIGHT: dict[str, float] = {
    "auth": 1.4,
    "signature": 1.2,
    "transport": 1.3,
    "skills": 1.5,
    "exposure": 1.0,
    "webhook": 1.1,
}


@dataclass(slots=True)
class ScoreWeights:
    severity: dict[Severity, float] = field(
        default_factory=lambda: dict(_DEFAULT_SEVERITY_WEIGHT)
    )
    check: dict[str, float] = field(default_factory=lambda: dict(_DEFAULT_CHECK_WEIGHT))


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings: list[Finding], weights: ScoreWeights | None = None) -> tuple[int, str]:
    w = weights or ScoreWeights()
    penalty = 0.0
    for f in findings:
        if f.passed:
            continue
        sev_w = w.severity.get(f.severity, 0.0)
        chk_w = w.check.get(f.check_id, 1.0)
        penalty += sev_w * chk_w
    score = max(0, min(100, round(100 - penalty)))
    return score, grade_for(score)
