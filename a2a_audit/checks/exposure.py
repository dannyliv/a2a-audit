"""Capability / extended-card over-exposure check (ASI03 / ASI02).

The authenticated extended card is additional, gated attack surface. A card that
advertises an extended card but requires no auth is exposing more than it
protects. Also surfaces a capability inventory and skill hygiene issues.
"""

from __future__ import annotations

from a2a_audit.context import CheckContext
from a2a_audit.finding import Asi, CheckMeta, Finding, Severity
from a2a_audit.schema import NormalizedCard

META = CheckMeta(
    check_id="exposure",
    name="Capability & extended-card exposure",
    asi_primary=Asi.ASI03,
    asi_secondary=Asi.ASI02,
    description="Extended-card exposure, capability inventory, skill hygiene.",
    weight=1.0,
)


def run(card: NormalizedCard, ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    has_auth = bool(card.security_schemes or card.security_requirements)

    if card.supports_extended_card:
        if not has_auth:
            findings.append(
                Finding(
                    check_id=META.check_id,
                    title="Extended card advertised without authentication",
                    severity=Severity.MEDIUM,
                    asi_primary=Asi.ASI03,
                    message=(
                        "The card advertises an authenticated extended card "
                        "(supportsAuthenticatedExtendedCard / capabilities.extendedAgentCard) "
                        "but declares no auth, so the 'authenticated' surface is unprotected."
                    ),
                    remediation="Require a securityScheme before serving the extended card.",
                )
            )
        else:
            findings.append(
                Finding(
                    check_id=META.check_id,
                    title="Extended card present (audit it separately)",
                    severity=Severity.INFO,
                    asi_primary=Asi.ASI03,
                    message=(
                        "The agent serves an authenticated extended card with additional "
                        "skills/fields. Audit that endpoint separately with credentials."
                    ),
                )
            )

    # Skill hygiene: missing ids/tags reduce auditability and can mask intent.
    missing_id = [s for s in card.skills if not s.id]
    untagged = [s for s in card.skills if not s.tags]
    if missing_id:
        findings.append(
            Finding(
                check_id=META.check_id,
                title=f"{len(missing_id)} skill(s) missing an id",
                severity=Severity.LOW,
                asi_primary=Asi.ASI03,
                message="Skills without a stable id are hard to reference, diff, and govern.",
                remediation="Give every skill a unique, stable id.",
            )
        )
    if untagged:
        findings.append(
            Finding(
                check_id=META.check_id,
                title=f"{len(untagged)} skill(s) without tags",
                severity=Severity.LOW,
                asi_primary=Asi.ASI03,
                message="Untagged skills obscure capability scope.",
                remediation="Tag each skill to make its capability scope explicit.",
            )
        )

    if not card.supports_extended_card and not missing_id and not untagged and card.skills:
        findings.append(
            Finding(
                check_id=META.check_id,
                title="No over-exposure indicators",
                severity=Severity.INFO,
                asi_primary=Asi.ASI03,
                message="No extended-card exposure gap; skills carry ids and tags.",
                passed=True,
            )
        )
    return findings
