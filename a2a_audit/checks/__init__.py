"""Security checks. Each module exposes ``META`` and ``run(card, ctx)``."""

from __future__ import annotations

from a2a_audit.checks import auth, exposure, signature, skills, transport, webhook
from a2a_audit.context import CheckContext
from a2a_audit.finding import CheckMeta, Finding, Severity
from a2a_audit.schema import NormalizedCard

# Order is the report order.
_CHECK_MODULES = [auth, signature, transport, skills, exposure, webhook]

ALL_META: list[CheckMeta] = [m.META for m in _CHECK_MODULES]


def run_all_checks(card: NormalizedCard, ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for module in _CHECK_MODULES:
        try:
            findings.extend(module.run(card, ctx))
        except Exception as exc:  # noqa: BLE001 - a broken check must not kill the audit
            findings.append(
                Finding(
                    check_id=module.META.check_id,
                    title=f"{module.META.name} check errored",
                    severity=Severity.INFO,
                    asi_primary=module.META.asi_primary,
                    message=f"check raised an exception: {exc}",
                )
            )
    return findings
