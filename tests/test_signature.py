"""Real signature verification, fully offline (JWKS fetch + SSRF guard mocked)."""

from __future__ import annotations

import json

import pytest
import rfc8785
from jwcrypto import jwk, jws

from a2a_audit.audit import audit_raw
from a2a_audit.classifier import SkillClassifier
from a2a_audit.finding import Severity


class _FakeResp:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def _signed_card(jku: str = "https://issuer.example.com/jwks.json") -> tuple[dict, dict]:
    key = jwk.JWK.generate(kty="EC", crv="P-256", kid="k1")
    card = {
        "protocolVersion": "0.3.0",
        "name": "Signed Agent",
        "description": "Properly signed.",
        "url": "https://signed.example.com/a2a",
        "version": "1.0.0",
        "capabilities": {},
        "securitySchemes": {"bearer": {"type": "http", "scheme": "Bearer"}},
        "security": [{"bearer": []}],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "s", "name": "S", "description": "does s", "tags": ["t"]}],
    }
    payload = rfc8785.dumps(card)
    token = jws.JWS(payload)
    protected = json.dumps({"alg": "ES256", "kid": "k1", "jku": jku})
    token.add_signature(key, alg="ES256", protected=protected)
    serialized = json.loads(token.serialize())
    card["signatures"] = [
        {"protected": serialized["protected"], "signature": serialized["signature"]}
    ]
    jwks = {"keys": [json.loads(key.export_public())]}
    return card, jwks


@pytest.fixture(autouse=True)
def _mock_network(monkeypatch):
    # Bypass DNS-based SSRF guard for the test issuer host.
    monkeypatch.setattr("a2a_audit.fetch.assert_safe_url", lambda *a, **k: None)


def test_valid_signature_verifies(monkeypatch):
    card, jwks = _signed_card()
    monkeypatch.setattr("httpx.get", lambda *a, **k: _FakeResp(jwks))
    r = audit_raw(card, target="signed", classifier=SkillClassifier(mode="disabled"))
    sig = [f for f in r.findings if f.check_id == "signature"]
    assert sig and sig[0].passed is True
    assert sig[0].title == "Card signature verified"


def test_tampered_card_fails_verification(monkeypatch):
    card, jwks = _signed_card()
    monkeypatch.setattr("httpx.get", lambda *a, **k: _FakeResp(jwks))
    card["description"] = "TAMPERED after signing"
    r = audit_raw(card, target="tampered", classifier=SkillClassifier(mode="disabled"))
    sig = [f for f in r.findings if f.check_id == "signature"]
    assert sig and sig[0].severity == Severity.HIGH
    assert "FAILED" in sig[0].title


def test_unreachable_jwks_is_low(monkeypatch):
    card, _ = _signed_card()

    def _boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr("httpx.get", _boom)
    r = audit_raw(card, target="unverifiable", classifier=SkillClassifier(mode="disabled"))
    sig = [f for f in r.findings if f.check_id == "signature"]
    assert sig and sig[0].severity == Severity.LOW
