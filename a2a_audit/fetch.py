"""Well-known Agent Card discovery and SSRF-hardened fetching.

We fetch attacker-influenced URLs (the user passes a domain; the registry
hands us ``wellKnownURI`` values), so this module is itself a security
boundary. Defenses (RESEARCH §6.4, threat model in SECURITY.md):
  - scheme allowlist (http/https only)
  - DNS-resolve the host and reject private / loopback / link-local /
    reserved / cloud-metadata addresses
  - re-validate every redirect hop (no blind redirect following)
  - hard timeout and response-size cap
"""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

WELL_KNOWN_PRIMARY = "/.well-known/agent-card.json"
WELL_KNOWN_LEGACY = "/.well-known/agent.json"

DEFAULT_TIMEOUT = 10.0
MAX_BYTES = 5 * 1024 * 1024  # 5 MiB cap on a card response
MAX_REDIRECTS = 3
ALLOWED_SCHEMES = {"http", "https"}


class FetchError(Exception):
    """Raised when a card cannot be safely fetched."""


@dataclass(slots=True)
class FetchResult:
    url: str
    path: str
    raw: dict
    transport_https: bool


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local  # covers 169.254.169.254 cloud metadata
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def assert_safe_url(url: str, *, allow_http: bool = True) -> None:
    """Raise FetchError if ``url`` is unsafe to fetch (SSRF guard)."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise FetchError(f"blocked scheme: {parsed.scheme or '(none)'}")
    if not allow_http and parsed.scheme != "https":
        raise FetchError("non-HTTPS URL blocked")
    host = parsed.hostname
    if not host:
        raise FetchError("missing host")
    # Reject literal-IP private targets and resolve hostnames to check every A/AAAA.
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise FetchError(f"DNS resolution failed for {host}: {exc}") from exc
    for info in infos:
        ip = str(info[4][0])
        if _is_blocked_ip(ip):
            raise FetchError(f"blocked private/reserved address for {host}: {ip}")


def _get(client: httpx.Client, url: str) -> bytes:
    """GET with manual, re-validated redirect handling and a size cap.

    Returns the decoded response body bytes. ``iter_bytes`` already applies any
    Content-Encoding, so we return those bytes directly rather than rebuilding a
    Response (which would try to decode a second time).
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        assert_safe_url(current)
        with client.stream("GET", current) as resp:
            if resp.is_redirect:
                loc = resp.headers.get("location")
                if not loc:
                    raise FetchError("redirect without location header")
                current = urljoin(current, loc)
                continue
            resp.raise_for_status()
            body = bytearray()
            for chunk in resp.iter_bytes():
                body.extend(chunk)
                if len(body) > MAX_BYTES:
                    raise FetchError(f"response exceeds {MAX_BYTES} byte cap")
            return bytes(body)
    raise FetchError(f"too many redirects (>{MAX_REDIRECTS})")


def _base_origin(target: str) -> str:
    """Turn a user-supplied target into an https origin to probe."""
    if "://" not in target:
        target = "https://" + target
    p = urlparse(target)
    scheme = p.scheme if p.scheme in ALLOWED_SCHEMES else "https"
    return f"{scheme}://{p.netloc}"


def fetch_card(
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> FetchResult:
    """Fetch a card from a target.

    If ``target`` already points at a ``.json`` card, fetch it directly.
    Otherwise probe the primary then legacy well-known paths on the origin.
    """
    owns_client = client is None
    client = client or httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": "a2a-audit/0.1 (+https://github.com/dannyliv/a2a-audit)"},
    )
    try:
        candidates: list[str]
        parsed = urlparse(target if "://" in target else "https://" + target)
        if parsed.path.endswith(".json"):
            candidates = [target if "://" in target else "https://" + target]
        else:
            origin = _base_origin(target)
            candidates = [origin + WELL_KNOWN_PRIMARY, origin + WELL_KNOWN_LEGACY]

        last_err: Exception | None = None
        for url in candidates:
            try:
                body = _get(client, url)
                raw = json.loads(body)
                if not isinstance(raw, dict):
                    raise FetchError("card is not a JSON object")
                return FetchResult(
                    url=url,
                    path=urlparse(url).path,
                    raw=raw,
                    transport_https=urlparse(url).scheme == "https",
                )
            except (httpx.HTTPError, FetchError, json.JSONDecodeError) as exc:
                last_err = exc
                continue
        raise FetchError(f"no card found at {target}: {last_err}")
    finally:
        if owns_client:
            client.close()
