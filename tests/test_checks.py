from __future__ import annotations

from a2a_audit.audit import audit_raw
from a2a_audit.classifier import SkillClassifier
from a2a_audit.finding import Severity
from tests.conftest import load_fixture


def _audit(name: str, **kw):
    # Default: skip signature network verification and disable classifier for
    # determinism; individual tests override.
    kw.setdefault("verify_signatures", False)
    return audit_raw(load_fixture(name), target=name, **kw)


def _ids(result):
    return {(f.check_id, f.title) for f in result.findings if not f.passed}


def test_clean_card_scores_well():
    r = _audit("clean.json", classifier=SkillClassifier(mode="disabled"))
    assert r.grade in ("A", "B")
    assert r.max_severity() < Severity.HIGH


def test_unsigned_flagged():
    r = _audit("unsigned.json", classifier=SkillClassifier(mode="disabled"))
    titles = {f.title for f in r.findings}
    assert "Card is unsigned" in titles


def test_plaintext_http_is_high():
    r = _audit("plaintext-http.json", classifier=SkillClassifier(mode="disabled"))
    sev = {f.title: f.severity for f in r.findings}
    assert sev.get("Plaintext (HTTP) endpoint") == Severity.HIGH
    # also: no auth declared
    assert any("No authentication declared" == f.title for f in r.findings)


def test_injected_skill_heuristic_flags():
    # Heuristic mode must catch the obvious injection payload.
    r = _audit("injected-skill.json", classifier=SkillClassifier(mode="heuristic"))
    skill_findings = [f for f in r.findings if f.check_id == "skills" and not f.passed]
    assert skill_findings, "expected the injected skill to be flagged"


def test_over_exposed_extended_card():
    r = _audit("over-exposed.json", classifier=SkillClassifier(mode="disabled"))
    titles = {f.title for f in r.findings}
    assert "Extended card advertised without authentication" in titles
    # push notifications + no auth -> webhook SSRF posture finding
    assert any(f.check_id == "webhook" and f.severity == Severity.MEDIUM for f in r.findings)


def test_v1_card_parses_and_audits():
    r = _audit("v1-card.json", classifier=SkillClassifier(mode="disabled"))
    assert r.spec_version == "v1.0"
    assert r.parse_ok
