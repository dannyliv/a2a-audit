"""Auth posture check (ASI03: Agent Identity & Privilege Abuse).

"No auth declared" is NOT automatically critical (many cards are intentional
public demos), so undeclared auth is MEDIUM and context-flagged, not HIGH.
Weak mechanisms (API key in query string, HTTP Basic, deprecated OAuth flows)
are called out specifically.
"""

from __future__ import annotations

from a2a_audit.context import CheckContext
from a2a_audit.finding import Asi, CheckMeta, Finding, Severity
from a2a_audit.schema import NormalizedCard

META = CheckMeta(
    check_id="auth",
    name="Authentication posture",
    asi_primary=Asi.ASI03,
    asi_secondary=Asi.ASI07,
    description="securitySchemes strength, whether auth is required, weak mechanisms.",
    weight=1.4,
)

_STRONG = {"oauth2", "openIdConnect", "mutualTLS"}


def run(card: NormalizedCard, ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    schemes = card.security_schemes
    requirements = card.security_requirements

    if not schemes and not requirements:
        findings.append(
            Finding(
                check_id=META.check_id,
                title="No authentication declared",
                severity=Severity.MEDIUM,
                asi_primary=Asi.ASI03,
                message=(
                    "The card declares no securitySchemes and no security "
                    "requirements. Callers can reach the agent without credentials."
                ),
                remediation=(
                    "If the agent is not an intentional public demo, declare a "
                    "securityScheme and a matching security requirement."
                ),
                caveat="Public demo agents may leave auth undeclared intentionally.",
            )
        )
        return findings

    if schemes and not requirements:
        findings.append(
            Finding(
                check_id=META.check_id,
                title="Security schemes defined but not required",
                severity=Severity.LOW,
                asi_primary=Asi.ASI03,
                message=(
                    "securitySchemes are declared but the card has no top-level "
                    "`security` requirement, so auth may not be enforced on calls."
                ),
                remediation="Add a `security` requirement referencing the declared scheme(s).",
            )
        )

    has_strong = False
    for scheme_name, scheme in schemes.items():
        kind = scheme.kind()
        if kind in _STRONG:
            has_strong = True
        if kind == "apiKey" and (scheme.key_location() == "query"):
            findings.append(
                Finding(
                    check_id=META.check_id,
                    title=f"API key passed in query string ({scheme_name})",
                    severity=Severity.MEDIUM,
                    asi_primary=Asi.ASI03,
                    message="API keys in the URL query string leak via logs, proxies, and Referer.",
                    remediation="Move the API key to a header (in: header).",
                    evidence=f"scheme '{scheme_name}': apiKey in=query",
                )
            )
        if kind == "http" and (scheme.scheme or "").lower() == "basic":
            findings.append(
                Finding(
                    check_id=META.check_id,
                    title=f"HTTP Basic auth ({scheme_name})",
                    severity=Severity.MEDIUM,
                    asi_primary=Asi.ASI03,
                    message="HTTP Basic transmits reusable base64 credentials on every request.",
                    remediation="Prefer Bearer tokens, OAuth2, OpenID Connect, or mTLS.",
                    evidence=f"scheme '{scheme_name}': http basic",
                )
            )
        if kind == "oauth2" and scheme.flows:
            deprecated = [f for f in scheme.flows if f in ("implicit", "password")]
            if deprecated:
                findings.append(
                    Finding(
                        check_id=META.check_id,
                        title=f"Deprecated OAuth2 flow ({scheme_name}: {', '.join(deprecated)})",
                        severity=Severity.LOW,
                        asi_primary=Asi.ASI03,
                        message="The implicit and password OAuth2 grants are deprecated and weaker.",
                        remediation="Use authorizationCode (with PKCE) or clientCredentials.",
                        evidence=f"scheme '{scheme_name}': flows {deprecated}",
                    )
                )

    if has_strong and requirements:
        findings.append(
            Finding(
                check_id=META.check_id,
                title="Strong authentication required",
                severity=Severity.INFO,
                asi_primary=Asi.ASI03,
                message="The card requires a strong auth scheme (OAuth2/OIDC/mTLS).",
                passed=True,
            )
        )
    return findings
