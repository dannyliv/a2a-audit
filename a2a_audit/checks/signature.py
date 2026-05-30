"""Signature presence + verification check (ASI04: Agentic Supply Chain).

Verifies, not just detects. Per spec §8.4 the signed payload is the card with
the ``signatures`` field removed, canonicalized with RFC 8785 JCS, signed as a
detached JWS. We rebuild that payload and verify with jwcrypto, fetching the
JWKS from the protected header's ``jku`` only through the SSRF-guarded fetcher.
``jku`` is untrusted, so verification proves integrity-against-that-key, not
trust-in-the-issuer; we say so in the finding.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from a2a_audit.context import CheckContext
from a2a_audit.finding import Asi, CheckMeta, Finding, Severity
from a2a_audit.schema import NormalizedCard

META = CheckMeta(
    check_id="signature",
    name="Card signature",
    asi_primary=Asi.ASI04,
    asi_secondary=Asi.ASI07,
    description="JWS signature presence and cryptographic verification over the JCS payload.",
    weight=1.2,
)


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _canonical_payload(raw: dict[str, Any]) -> bytes:
    import rfc8785

    unsigned = {k: v for k, v in raw.items() if k != "signatures"}
    return rfc8785.dumps(unsigned)


def _verify_one(sig: dict[str, Any], payload: bytes, ctx: CheckContext) -> tuple[bool, str]:
    """Return (verified, detail)."""
    from jwcrypto import jwk, jws

    protected_b64 = sig.get("protected")
    signature_b64 = sig.get("signature")
    if not protected_b64 or not signature_b64:
        return False, "signature object missing protected/signature fields"
    try:
        header = json.loads(_b64url_decode(protected_b64))
    except Exception as exc:  # noqa: BLE001
        return False, f"protected header undecodable: {exc}"

    jku = header.get("jku")
    kid = header.get("kid")
    if not jku:
        return False, "no jku in protected header; cannot retrieve verification key"

    # Fetch JWKS through the SSRF-guarded fetcher.
    try:
        import httpx

        from a2a_audit.fetch import assert_safe_url

        assert_safe_url(jku, allow_http=False)
        resp = httpx.get(jku, timeout=10.0, follow_redirects=False)
        resp.raise_for_status()
        jwks_data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return False, f"jku JWKS fetch failed ({jku}): {exc}"

    try:
        keyset = jwk.JWKSet.from_json(json.dumps(jwks_data))
        key = keyset.get_key(kid) if kid else None
        if key is None:
            keys = list(getattr(keyset, "_keys", []) or [])
            if len(keys) == 1:
                key = keys[0]
        if key is None:
            return False, f"no JWKS key matched kid={kid}"
        token = jws.JWS()
        token.deserialize(json.dumps({"protected": protected_b64, "signature": signature_b64}))
        token.verify(key, detached_payload=payload)
        return True, f"verified against jku={jku} kid={kid}"
    except Exception as exc:  # noqa: BLE001
        return False, f"signature verification failed: {exc}"


def run(card: NormalizedCard, ctx: CheckContext) -> list[Finding]:
    sigs = card.raw.get("signatures") or []
    if not sigs:
        return [
            Finding(
                check_id=META.check_id,
                title="Card is unsigned",
                severity=Severity.MEDIUM,
                asi_primary=Asi.ASI04,
                message=(
                    "No `signatures` present. The card's authenticity and integrity "
                    "cannot be cryptographically verified; it can be silently tampered."
                ),
                remediation="Sign the card with a detached JWS (RFC 7515 + RFC 8785 JCS) per spec §8.4.",
            )
        ]

    if not ctx.verify_signatures:
        return [
            Finding(
                check_id=META.check_id,
                title="Card is signed (verification skipped)",
                severity=Severity.INFO,
                asi_primary=Asi.ASI04,
                message=f"{len(sigs)} signature(s) present; verification disabled by flag.",
                passed=True,
            )
        ]

    payload = _canonical_payload(card.raw)
    results = [_verify_one(s, payload, ctx) for s in sigs if isinstance(s, dict)]
    verified = [d for ok, d in results if ok]
    failed = [d for ok, d in results if not ok]

    if verified:
        return [
            Finding(
                check_id=META.check_id,
                title="Card signature verified",
                severity=Severity.INFO,
                asi_primary=Asi.ASI04,
                message="At least one signature verified over the JCS-canonicalized card.",
                evidence=verified[0],
                passed=True,
                caveat=(
                    "Verification proves integrity against the jku-provided key, not "
                    "trust in the issuer. Pin the JWKS host to a known issuer for full assurance."
                ),
            )
        ]

    # Signed but nothing verified.
    unverifiable = all("cannot retrieve" in d or "JWKS fetch failed" in d or "no jku" in d for d in failed)
    if unverifiable:
        return [
            Finding(
                check_id=META.check_id,
                title="Signature present but unverifiable",
                severity=Severity.LOW,
                asi_primary=Asi.ASI04,
                message="Signature(s) present but no usable key (jku/JWKS) was available to verify them.",
                evidence="; ".join(failed)[:400],
                remediation="Publish a reachable JWKS via the protected-header `jku` so clients can verify.",
            )
        ]
    return [
        Finding(
            check_id=META.check_id,
            title="Signature verification FAILED",
            severity=Severity.HIGH,
            asi_primary=Asi.ASI04,
            message="A signature was present and a key was available, but verification failed.",
            evidence="; ".join(failed)[:400],
            remediation="The card may be tampered or signed incorrectly. Re-sign over the JCS payload.",
        )
    ]
