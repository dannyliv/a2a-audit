"""Transport + provider hygiene check (ASI04 / ASI07).

Plaintext endpoints expose credentials and tasks in transit and let a network
attacker impersonate the agent. HTTPS is required for production A2A endpoints.
"""

from __future__ import annotations

from urllib.parse import urlparse

from a2a_audit.context import CheckContext
from a2a_audit.finding import Asi, CheckMeta, Finding, Severity
from a2a_audit.schema import NormalizedCard

META = CheckMeta(
    check_id="transport",
    name="Transport & provider hygiene",
    asi_primary=Asi.ASI04,
    asi_secondary=Asi.ASI07,
    description="HTTPS on endpoints and the card itself; provider presence and URL hygiene.",
    weight=1.3,
)


def _is_http(url: str | None) -> bool:
    return bool(url) and urlparse(url).scheme == "http"


def run(card: NormalizedCard, ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []

    if not card.interfaces and not card.primary_url:
        findings.append(
            Finding(
                check_id=META.check_id,
                title="No service endpoint declared",
                severity=Severity.MEDIUM,
                asi_primary=Asi.ASI04,
                message="The card declares no url / interface, so no endpoint can be reached or assessed.",
                remediation="Declare the agent's endpoint url (v0.3) or supportedInterfaces (v1.0).",
            )
        )

    plaintext = []
    for iface in card.interfaces:
        if _is_http(iface.url):
            plaintext.append(iface.url)
    if _is_http(card.primary_url) and card.primary_url not in plaintext:
        plaintext.append(card.primary_url)

    for url in plaintext:
        findings.append(
            Finding(
                check_id=META.check_id,
                title="Plaintext (HTTP) endpoint",
                severity=Severity.HIGH,
                asi_primary=Asi.ASI04,
                asi_secondary=Asi.ASI07,
                message="An agent endpoint is served over plaintext HTTP; traffic and credentials are exposed.",
                remediation="Serve all endpoints over HTTPS with a valid certificate.",
                evidence=url,
            )
        )

    if ctx.fetched_https is False:
        findings.append(
            Finding(
                check_id=META.check_id,
                title="Agent Card served over HTTP",
                severity=Severity.HIGH,
                asi_primary=Asi.ASI04,
                message="The Agent Card itself was retrieved over plaintext HTTP and can be tampered in transit.",
                remediation="Serve /.well-known/agent-card.json over HTTPS.",
            )
        )

    # Provider hygiene.
    if card.provider is None or not (card.provider.organization or card.provider.url):
        findings.append(
            Finding(
                check_id=META.check_id,
                title="No provider information",
                severity=Severity.LOW,
                asi_primary=Asi.ASI04,
                message="The card declares no provider, reducing accountability/attribution.",
                remediation="Add a provider with organization and url.",
            )
        )
    elif _is_http(card.provider.url):
        findings.append(
            Finding(
                check_id=META.check_id,
                title="Provider URL is plaintext HTTP",
                severity=Severity.LOW,
                asi_primary=Asi.ASI04,
                message="The provider URL uses HTTP.",
                remediation="Use an HTTPS provider URL.",
                evidence=card.provider.url,
            )
        )

    if not plaintext and ctx.fetched_https is not False and card.primary_url:
        findings.append(
            Finding(
                check_id=META.check_id,
                title="All endpoints use HTTPS",
                severity=Severity.INFO,
                asi_primary=Asi.ASI04,
                message="Declared endpoints use HTTPS.",
                passed=True,
            )
        )
    return findings
