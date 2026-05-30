from __future__ import annotations

from a2a_audit.schema import detect_spec_version, normalize
from tests.conftest import load_fixture


def test_normalize_v03():
    card = normalize(load_fixture("clean.json"))
    assert card.spec_version == "v0.3"
    assert card.primary_url == "https://clean.example.com/a2a"
    assert len(card.interfaces) == 1
    assert card.interfaces[0].transport_name() == "JSONRPC"
    assert "oidc" in card.security_schemes
    assert card.security_schemes["oidc"].kind() == "openIdConnect"


def test_normalize_v1():
    card = normalize(load_fixture("v1-card.json"))
    assert card.spec_version == "v1.0"
    assert card.primary_url == "https://v1.example.com/a2a"
    assert card.interfaces[0].transport_name() == "JSONRPC"
    # extended-card flag lives in capabilities in v1.0
    assert card.supports_extended_card is True
    # securityRequirements normalize into security_requirements
    assert card.security_requirements


def test_apikey_in_alias():
    raw = {
        "name": "k",
        "url": "https://e.com",
        "securitySchemes": {"k": {"type": "apiKey", "in": "query", "name": "api_key"}},
        "skills": [],
    }
    card = normalize(raw)
    sch = card.security_schemes["k"]
    assert sch.kind() == "apiKey"
    assert sch.key_location() == "query"


def test_detect_versions():
    assert detect_spec_version({"supportedInterfaces": []}) == "v1.0"
    assert detect_spec_version({"protocolVersion": "0.2.5", "url": "x"}) == "v0.2"
    assert detect_spec_version({"protocolVersion": "1.0.0"}) == "v1.0"
    assert detect_spec_version({"url": "x"}) == "v0.3"
    assert detect_spec_version({}) == "unknown"


def test_lenient_parse_garbage():
    # Auditor must not crash on malformed input.
    card = normalize({"name": 123, "skills": "not-a-list", "securitySchemes": []})
    assert card is not None
