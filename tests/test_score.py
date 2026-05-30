from __future__ import annotations

from a2a_audit.finding import Asi, Finding, Severity
from a2a_audit.score import grade_for, score_findings


def _f(check_id: str, sev: Severity, passed: bool = False) -> Finding:
    return Finding(
        check_id=check_id,
        title="t",
        severity=sev,
        asi_primary=Asi.ASI03,
        message="m",
        passed=passed,
    )


def test_grade_boundaries():
    assert grade_for(100) == "A"
    assert grade_for(90) == "A"
    assert grade_for(89) == "B"
    assert grade_for(70) == "C"
    assert grade_for(59) == "F"


def test_passed_findings_do_not_penalize():
    score, grade = score_findings([_f("auth", Severity.INFO, passed=True)])
    assert score == 100
    assert grade == "A"


def test_high_finding_lowers_score():
    score, _ = score_findings([_f("transport", Severity.HIGH)])
    # 18 * 1.3 = 23.4 penalty -> ~77
    assert score < 80


def test_score_floor_at_zero():
    findings = [_f("auth", Severity.CRITICAL) for _ in range(20)]
    score, grade = score_findings(findings)
    assert score == 0
    assert grade == "F"
