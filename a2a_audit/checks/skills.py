"""Skill-description intent check (ASI01: Agent Goal Hijack).

Runs each skill's text through the two-stage classifier (heuristic gate -> LLM
intent). A confirmed malicious skill description is an indirect prompt-injection
payload that hijacks a consuming agent's goal. When the classifier runs
heuristic-only (degraded), matches are reported as LOW + unverified rather than
HIGH, to avoid false positives on legitimate skills.
"""

from __future__ import annotations

from a2a_audit.classifier import skill_text
from a2a_audit.context import CheckContext
from a2a_audit.finding import Asi, CheckMeta, Finding, Severity
from a2a_audit.schema import NormalizedCard

META = CheckMeta(
    check_id="skills",
    name="Skill-description intent",
    asi_primary=Asi.ASI01,
    asi_secondary=Asi.ASI06,
    description="LLM-backed detection of prompt-injection / hijack payloads in skill text.",
    weight=1.5,
)


def run(card: NormalizedCard, ctx: CheckContext) -> list[Finding]:
    classifier = ctx.classifier
    if classifier is None or classifier.mode == "disabled":
        return [
            Finding(
                check_id=META.check_id,
                title="Skill intent classification disabled",
                severity=Severity.INFO,
                asi_primary=Asi.ASI01,
                message="No classifier configured; skill descriptions were not screened for injection.",
            )
        ]

    findings: list[Finding] = []
    flagged = 0
    degraded = classifier.mode == "heuristic"

    for skill in card.skills:
        text = skill_text(skill.name, skill.description, skill.examples)
        if not text.strip():
            continue
        verdict = classifier.classify(text)
        if not verdict.malicious:
            continue
        flagged += 1
        label = skill.id or skill.name or "(unnamed skill)"
        if degraded:
            findings.append(
                Finding(
                    check_id=META.check_id,
                    title=f"Suspicious skill description (unverified): {label}",
                    severity=Severity.LOW,
                    asi_primary=Asi.ASI01,
                    message=(
                        "Heuristic patterns matched possible injection intent. The LLM "
                        "classifier was unavailable, so this is UNVERIFIED."
                    ),
                    evidence=verdict.reason,
                    remediation="Review the skill description manually; run the CLI with the LLM classifier enabled.",
                    caveat="Degraded mode: heuristic-only, expect false positives.",
                )
            )
        else:
            sev = Severity.HIGH if verdict.confidence >= 0.6 else Severity.MEDIUM
            findings.append(
                Finding(
                    check_id=META.check_id,
                    title=f"Likely prompt-injection in skill: {label}",
                    severity=sev,
                    asi_primary=Asi.ASI01,
                    asi_secondary=Asi.ASI06,
                    message="The skill description appears to contain an instruction-hijack / injection payload.",
                    evidence=f"{verdict.reason} (confidence {verdict.confidence:.2f})",
                    remediation="Treat this agent as hostile until the skill text is reviewed and cleaned.",
                )
            )

    if flagged == 0 and card.skills:
        findings.append(
            Finding(
                check_id=META.check_id,
                title="No injection patterns in skill descriptions",
                severity=Severity.INFO,
                asi_primary=Asi.ASI01,
                message=f"Screened {len(card.skills)} skill(s); none flagged ({classifier.mode} mode).",
                passed=True,
            )
        )
    return findings
