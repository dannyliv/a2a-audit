"""Pydantic models for the A2A Agent Card and a version-agnostic normalizer.

Two serialization models exist (RESEARCH.md §1): the v0.2/v0.3 JSON shape
(flat ``url`` + ``preferredTransport`` + ``additionalInterfaces``, ``type``
discriminator on security schemes, ``supportsAuthenticatedExtendedCard`` at
root) and the v1.0 proto shape (``supportedInterfaces`` array, extended-card
flag inside ``capabilities``). We parse leniently (an auditor must ingest
malformed cards, not reject them) and normalize both into ``NormalizedCard``,
which every check consumes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class _Lenient(BaseModel):
    # Auditors ingest hostile/messy input: never raise on unknown or extra keys.
    model_config = ConfigDict(extra="allow", populate_by_name=True, str_strip_whitespace=False)


class SecurityScheme(_Lenient):
    type: str | None = None
    description: str | None = None
    # apiKey
    in_: str | None = Field(default=None, alias="in")
    location: str | None = None  # v1.0 proto name for `in`
    name: str | None = None
    # http
    scheme: str | None = None
    bearerFormat: str | None = None
    # oauth2
    flows: dict[str, Any] | None = None
    oauth2MetadataUrl: str | None = None
    # openIdConnect
    openIdConnectUrl: str | None = None

    def kind(self) -> str:
        """Best-effort scheme kind across both serializations."""
        if self.type:
            return self.type
        if self.flows is not None:
            return "oauth2"
        if self.openIdConnectUrl:
            return "openIdConnect"
        if self.scheme:
            return "http"
        if self.name and (self.in_ or self.location):
            return "apiKey"
        return "unknown"

    def key_location(self) -> str | None:
        return self.in_ or self.location


class AgentProvider(_Lenient):
    organization: str | None = None
    url: str | None = None


class AgentExtension(_Lenient):
    uri: str | None = None
    description: str | None = None
    required: bool | None = None
    params: dict[str, Any] | None = None


class AgentCapabilities(_Lenient):
    streaming: bool | None = None
    pushNotifications: bool | None = None
    stateTransitionHistory: bool | None = None
    extensions: list[AgentExtension] | None = None
    extendedAgentCard: bool | None = None  # v1.0 location of the extended-card flag


class AgentSkill(_Lenient):
    id: str | None = None
    name: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    examples: list[str] | None = None
    inputModes: list[str] | None = None
    outputModes: list[str] | None = None


class AgentInterface(_Lenient):
    url: str | None = None
    transport: str | None = None  # v0.3
    protocolBinding: str | None = None  # v1.0 rename
    protocolVersion: str | None = None
    tenant: str | None = None

    def transport_name(self) -> str | None:
        return self.transport or self.protocolBinding


class AgentCardSignature(_Lenient):
    protected: str | None = None
    signature: str | None = None
    header: dict[str, Any] | None = None


class AgentCard(_Lenient):
    """Union of both serializations; every field optional for lenient parsing."""

    protocolVersion: str | None = None
    name: str | None = None
    description: str | None = None
    url: str | None = None
    preferredTransport: str | None = None
    additionalInterfaces: list[AgentInterface] | None = None
    supportedInterfaces: list[AgentInterface] | None = None  # v1.0
    iconUrl: str | None = None
    provider: AgentProvider | None = None
    version: str | None = None
    documentationUrl: str | None = None
    capabilities: AgentCapabilities | None = None
    securitySchemes: dict[str, SecurityScheme] | None = None
    security: list[dict[str, list[str]]] | None = None
    securityRequirements: list[dict[str, Any]] | None = None  # v1.0
    defaultInputModes: list[str] | None = None
    defaultOutputModes: list[str] | None = None
    skills: list[AgentSkill] | None = None
    supportsAuthenticatedExtendedCard: bool | None = None
    signatures: list[AgentCardSignature] | None = None


@dataclass(slots=True)
class NormalizedCard:
    """Version-agnostic view the checks operate on."""

    name: str | None
    description: str | None
    version: str | None
    protocol_version: str | None
    spec_version: str  # "v0.2", "v0.3", "v1.0", or "unknown"
    interfaces: list[AgentInterface]
    primary_url: str | None
    provider: AgentProvider | None
    capabilities: AgentCapabilities
    security_schemes: dict[str, SecurityScheme]
    security_requirements: list[dict[str, Any]]
    skills: list[AgentSkill]
    signatures: list[AgentCardSignature]
    supports_extended_card: bool
    raw: dict[str, Any] = field(default_factory=dict)
    model: AgentCard | None = None


def detect_spec_version(raw: dict[str, Any]) -> str:
    """Heuristic version detection from a raw card dict."""
    if "supportedInterfaces" in raw:
        return "v1.0"
    pv = str(raw.get("protocolVersion", "") or "")
    if pv.startswith("1."):
        return "v1.0"
    if pv.startswith("0.3"):
        return "v0.3"
    if pv.startswith("0.2"):
        return "v0.2"
    # No protocolVersion + a flat url => most likely a v0.3-style/legacy card.
    if "url" in raw:
        return "v0.3"
    return "unknown"


def parse_card(raw: dict[str, Any]) -> tuple[AgentCard, list[str]]:
    """Lenient parse. Returns (model, soft_errors). Never raises on field issues."""
    errors: list[str] = []
    try:
        model = AgentCard.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 - lenient by design
        errors.append(f"pydantic parse degraded: {exc}")
        model = AgentCard.model_construct(**{k: v for k, v in raw.items()})
    return model, errors


_M = TypeVar("_M", bound=_Lenient)


def _coerce(model_cls: type[_M], value: Any) -> _M | None:
    """Defensively turn a raw value into a submodel; never raise on bad input."""
    if isinstance(value, model_cls):
        return value
    if isinstance(value, dict):
        try:
            return model_cls.model_validate(value)
        except Exception:  # noqa: BLE001 - lenient by design
            try:
                return model_cls.model_construct(**value)
            except Exception:  # noqa: BLE001
                return None
    return None


def _coerce_list(model_cls: type[_M], value: Any) -> list[_M]:
    if not isinstance(value, list):
        return []
    out: list[_M] = []
    for item in value:
        coerced = _coerce(model_cls, item)
        if coerced is not None:
            out.append(coerced)
    return out


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def normalize(raw: dict[str, Any]) -> NormalizedCard:
    """Parse + normalize a raw card dict into a version-agnostic NormalizedCard.

    Built defensively from ``raw`` (not from nested pydantic coercion) so that a
    malformed field in one place cannot break parsing of the rest of the card.
    """
    model, _ = parse_card(raw)
    spec = detect_spec_version(raw)

    interfaces: list[AgentInterface] = []
    supported = raw.get("supportedInterfaces")
    if isinstance(supported, list) and supported:
        interfaces.extend(_coerce_list(AgentInterface, supported))
    else:
        url = _str_or_none(raw.get("url"))
        if url:
            interfaces.append(
                AgentInterface(url=url, transport=_str_or_none(raw.get("preferredTransport")))
            )
        interfaces.extend(_coerce_list(AgentInterface, raw.get("additionalInterfaces")))

    primary_url = _str_or_none(raw.get("url"))
    if primary_url is None and interfaces:
        primary_url = interfaces[0].url

    caps = _coerce(AgentCapabilities, raw.get("capabilities")) or AgentCapabilities()
    extended = bool(raw.get("supportsAuthenticatedExtendedCard") or caps.extendedAgentCard)

    schemes_raw = raw.get("securitySchemes")
    security_schemes: dict[str, SecurityScheme] = {}
    if isinstance(schemes_raw, dict):
        for key, val in schemes_raw.items():
            coerced = _coerce(SecurityScheme, val)
            if coerced is not None:
                security_schemes[str(key)] = coerced

    sec_reqs: list[dict[str, Any]] = []
    for src in (raw.get("security"), raw.get("securityRequirements")):
        if isinstance(src, list):
            sec_reqs.extend(item for item in src if isinstance(item, dict))

    signatures = _coerce_list(AgentCardSignature, raw.get("signatures"))

    return NormalizedCard(
        name=_str_or_none(raw.get("name")),
        description=_str_or_none(raw.get("description")),
        version=_str_or_none(raw.get("version")),
        protocol_version=_str_or_none(raw.get("protocolVersion")),
        spec_version=spec,
        interfaces=interfaces,
        primary_url=primary_url,
        provider=_coerce(AgentProvider, raw.get("provider")),
        capabilities=caps,
        security_schemes=security_schemes,
        security_requirements=sec_reqs,
        skills=_coerce_list(AgentSkill, raw.get("skills")),
        signatures=signatures,
        supports_extended_card=extended,
        raw=raw,
        model=model,
    )
