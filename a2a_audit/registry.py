"""a2aregistry.org client.

Embedded card fields are a STALE snapshot (RESEARCH §4.6) so they are used only
as a discovery index; callers re-fetch each canonical /.well-known card before
auditing. Pagination is offset-based (limit<=100), requests are serial with
exponential backoff (no `?page` param; deep pagination 403s).
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx

REGISTRY_BASE = "https://a2aregistry.org/api"
PAGE_LIMIT = 100
_BACKOFF_START = 2.0
_BACKOFF_CAP = 60.0
_MAX_RETRIES = 5


@dataclass(slots=True)
class RegistryAgent:
    id: str | None
    name: str | None
    well_known_uri: str | None
    url: str | None
    embedded: dict[str, Any]

    def discovery_target(self) -> str | None:
        """Best target for a canonical re-fetch."""
        return self.well_known_uri or self.url


class RegistryClient:
    def __init__(self, base: str = REGISTRY_BASE, *, timeout: float = 15.0) -> None:
        self.base = base.rstrip("/")
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "a2a-audit/0.1 (+https://github.com/dannyliv/a2a-audit)"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> RegistryClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        delay = _BACKOFF_START
        last_exc: Exception | None = None
        for _ in range(_MAX_RETRIES):
            try:
                resp = self._client.get(f"{self.base}{path}", params=params)
                if resp.status_code in (403, 429):
                    last_exc = httpx.HTTPStatusError(
                        f"rate-limited {resp.status_code}", request=resp.request, response=resp
                    )
                    time.sleep(min(delay, _BACKOFF_CAP))  # noqa: ASYNC251 - sync client
                    delay *= 2
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                last_exc = exc
                time.sleep(min(delay, _BACKOFF_CAP))
                delay *= 2
        raise RuntimeError(f"registry GET {path} failed after {_MAX_RETRIES} retries: {last_exc}")

    def stats(self) -> dict[str, Any]:
        data = self._get("/stats")
        return data if isinstance(data, dict) else {}

    def _page(self, limit: int, offset: int) -> list[dict[str, Any]]:
        data = self._get("/agents", params={"limit": limit, "offset": offset})
        if isinstance(data, dict):
            agents = data.get("agents", [])
        elif isinstance(data, list):
            agents = data
        else:
            agents = []
        return [a for a in agents if isinstance(a, dict)]

    def iter_agents(self, total: int | None = None) -> Iterator[RegistryAgent]:
        """Yield up to ``total`` agents using offset pagination + serial pacing."""
        seen = 0
        offset = 0
        while True:
            page = self._page(PAGE_LIMIT, offset)
            if not page:
                break
            for a in page:
                yield RegistryAgent(
                    id=a.get("id"),
                    name=a.get("name"),
                    well_known_uri=a.get("wellKnownURI") or a.get("well_known_uri"),
                    url=a.get("url"),
                    embedded=a,
                )
                seen += 1
                if total is not None and seen >= total:
                    return
            offset += PAGE_LIMIT
            time.sleep(1.0)  # polite pacing between pages
            if len(page) < PAGE_LIMIT:
                break
