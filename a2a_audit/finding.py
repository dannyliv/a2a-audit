"""Core shared types: severities, OWASP ASI categories, and findings.

These types are deliberately dependency-free so every other module (checks,
score, report, the client-side demo generator) can import them without pulling
in httpx / pydantic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import cast


class Severity(str, Enum):
    """Finding severity, ordered. ``rank`` drives scoring and ``--fail-on``."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:  # enables `finding.severity >= fail_on`
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Asi(str, Enum):
    """OWASP Top 10 for Agentic Applications (ASI), 2026 edition.

    Published 2025-12-09 by the OWASP GenAI Security Project. See RESEARCH.md §5.
    """

    ASI01 = "ASI01"
    ASI02 = "ASI02"
    ASI03 = "ASI03"
    ASI04 = "ASI04"
    ASI05 = "ASI05"
    ASI06 = "ASI06"
    ASI07 = "ASI07"
    ASI08 = "ASI08"
    ASI09 = "ASI09"
    ASI10 = "ASI10"

    @property
    def title(self) -> str:  # type: ignore[override]  # intentional: shadows str.title (never used)
        return _ASI_TITLES[self]

    @property
    def label(self) -> str:
        return f"{self.value}: {self.title}"


_ASI_TITLES: dict[Asi, str] = {
    Asi.ASI01: "Agent Goal Hijack",
    Asi.ASI02: "Tool Misuse & Exploitation",
    Asi.ASI03: "Agent Identity & Privilege Abuse",
    Asi.ASI04: "Agentic Supply Chain Compromise",
    Asi.ASI05: "Unexpected Code Execution",
    Asi.ASI06: "Memory & Context Poisoning",
    Asi.ASI07: "Insecure Inter-Agent Communication",
    Asi.ASI08: "Cascading Agent Failures",
    Asi.ASI09: "Human-Agent Trust Exploitation",
    Asi.ASI10: "Rogue Agents",
}


@dataclass(slots=True)
class Finding:
    """A single audit observation.

    ``passed`` findings (severity INFO with ``passed=True``) record a control
    that is present and correct; they raise the score rather than lower it.
    """

    check_id: str
    title: str
    severity: Severity
    asi_primary: Asi
    message: str
    remediation: str = ""
    asi_secondary: Asi | None = None
    evidence: str | None = None
    passed: bool = False
    caveat: str | None = None

    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "passed": self.passed,
            "asi": {"primary": self.asi_primary.label},
            "message": self.message,
        }
        if self.asi_secondary is not None:
            asi = cast("dict[str, str]", d["asi"])
            asi["secondary"] = self.asi_secondary.label
        if self.remediation:
            d["remediation"] = self.remediation
        if self.evidence is not None:
            d["evidence"] = self.evidence
        if self.caveat is not None:
            d["caveat"] = self.caveat
        return d


@dataclass(slots=True)
class CheckMeta:
    """Static description of a check, used for docs and the ASI mapping table."""

    check_id: str
    name: str
    asi_primary: Asi
    asi_secondary: Asi | None = None
    description: str = ""
    weight: float = 1.0


@dataclass(slots=True)
class AuditResult:
    """Everything produced by auditing one card."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    grade: str = "?"
    spec_version: str = "unknown"
    parse_ok: bool = True
    classifier_mode: str = "disabled"
    errors: list[str] = field(default_factory=list)
    fetched_path: str | None = None

    def max_severity(self) -> Severity:
        sevs = [f.severity for f in self.findings if not f.passed]
        return max(sevs, key=lambda s: s.rank) if sevs else Severity.INFO

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "fetched_path": self.fetched_path,
            "spec_version": self.spec_version,
            "parse_ok": self.parse_ok,
            "classifier_mode": self.classifier_mode,
            "score": self.score,
            "grade": self.grade,
            "max_severity": self.max_severity().value,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }
