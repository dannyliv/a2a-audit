"""Audit orchestration: discover -> fetch -> normalize -> check -> score."""

from __future__ import annotations

from typing import Any

from a2a_audit.checks import run_all_checks
from a2a_audit.classifier import SkillClassifier
from a2a_audit.context import CheckContext
from a2a_audit.fetch import FetchError, fetch_card
from a2a_audit.finding import AuditResult
from a2a_audit.schema import normalize
from a2a_audit.score import ScoreWeights, score_findings


def audit_raw(
    raw: dict[str, Any],
    *,
    target: str,
    fetched_https: bool | None = None,
    fetched_path: str | None = None,
    classifier: SkillClassifier | None = None,
    verify_signatures: bool = True,
    weights: ScoreWeights | None = None,
) -> AuditResult:
    """Audit an already-loaded card dict."""
    card = normalize(raw)
    ctx = CheckContext(
        fetched_https=fetched_https,
        verify_signatures=verify_signatures,
        classifier=classifier,
    )
    findings = run_all_checks(card, ctx)
    score, grade = score_findings(findings, weights)
    return AuditResult(
        target=target,
        findings=findings,
        score=score,
        grade=grade,
        spec_version=card.spec_version,
        parse_ok=True,
        classifier_mode=ctx.classifier_mode,
        fetched_path=fetched_path,
    )


def audit_target(
    target: str,
    *,
    classifier: SkillClassifier | None = None,
    verify_signatures: bool = True,
    weights: ScoreWeights | None = None,
    timeout: float = 10.0,
) -> AuditResult:
    """Fetch a card from a URL/domain and audit it."""
    try:
        fetched = fetch_card(target, timeout=timeout)
    except FetchError as exc:
        return AuditResult(
            target=target,
            parse_ok=False,
            classifier_mode=classifier.mode if classifier else "disabled",
            errors=[f"fetch failed: {exc}"],
        )
    return audit_raw(
        fetched.raw,
        target=target,
        fetched_https=fetched.transport_https,
        fetched_path=fetched.path,
        classifier=classifier,
        verify_signatures=verify_signatures,
        weights=weights,
    )
