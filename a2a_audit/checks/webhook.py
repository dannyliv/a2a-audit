"""Push-notification webhook hygiene / SSRF check (ASI07 / ASI05).

When an agent advertises pushNotifications, clients register a webhook URL the
agent will call. If that registration is unauthenticated and the agent does not
validate the target, it becomes an SSRF pivot (callable against internal/cloud
metadata endpoints). From the card alone we assess posture, not the live
endpoint, so findings are framed as risk indicators.

Caveat (RESEARCH §5.3): OWASP ASI07 text emphasizes message spoofing / Agent-in-
the-Middle more than SSRF, so webhook-SSRF coverage under ASI07 is partial.
"""

from __future__ import annotations

from a2a_audit.context import CheckContext
from a2a_audit.finding import Asi, CheckMeta, Finding, Severity
from a2a_audit.schema import NormalizedCard

META = CheckMeta(
    check_id="webhook",
    name="Push-notification webhook hygiene",
    asi_primary=Asi.ASI07,
    asi_secondary=Asi.ASI05,
    description="SSRF / abuse exposure from pushNotifications webhook configuration.",
    weight=1.1,
)

_SSRF_CAVEAT = (
    "OWASP ASI07 emphasizes inter-agent message spoofing/AitM; SSRF is covered "
    "only partially under ASI07 (ASI05 secondary)."
)


def run(card: NormalizedCard, ctx: CheckContext) -> list[Finding]:
    caps = card.capabilities
    push = bool(caps.pushNotifications)
    if not push:
        return [
            Finding(
                check_id=META.check_id,
                title="Push notifications not enabled",
                severity=Severity.INFO,
                asi_primary=Asi.ASI07,
                message="No pushNotifications capability; no client-webhook SSRF surface advertised.",
                passed=True,
            )
        ]

    has_auth = bool(card.security_schemes or card.security_requirements)
    if not has_auth:
        return [
            Finding(
                check_id=META.check_id,
                title="Push notifications enabled with no declared auth",
                severity=Severity.MEDIUM,
                asi_primary=Asi.ASI07,
                asi_secondary=Asi.ASI05,
                message=(
                    "The agent accepts push-notification webhooks but declares no auth. "
                    "An unauthenticated webhook-config endpoint that does not validate the "
                    "target URL is an SSRF pivot toward internal / cloud-metadata addresses."
                ),
                remediation=(
                    "Require auth to register webhooks, validate webhook URLs against an "
                    "allowlist, and block private/link-local/metadata IP ranges."
                ),
                caveat=_SSRF_CAVEAT,
            )
        ]
    return [
        Finding(
            check_id=META.check_id,
            title="Push notifications enabled (verify webhook URL validation)",
            severity=Severity.LOW,
            asi_primary=Asi.ASI07,
            message=(
                "Push notifications are enabled with auth declared. Confirm the agent "
                "still validates client-supplied webhook URLs against an SSRF allowlist."
            ),
            remediation="Validate and allowlist webhook targets; block private IP ranges.",
            caveat=_SSRF_CAVEAT,
        )
    ]
