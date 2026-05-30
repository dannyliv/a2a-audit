"""Live end-to-end tests against real A2A infrastructure.

Marked ``network`` so CI/offline runs skip them: ``pytest -m 'not network'``.
"""

from __future__ import annotations

import pytest

from a2a_audit.audit import audit_raw
from a2a_audit.classifier import SkillClassifier
from a2a_audit.registry import RegistryClient

pytestmark = pytest.mark.network


def test_registry_stats_reachable():
    with RegistryClient() as client:
        stats = client.stats()
    assert isinstance(stats, dict)
    assert int(stats.get("total_agents", 0)) > 0


def test_registry_iter_and_audit():
    audited = 0
    with RegistryClient() as client:
        for agent in client.iter_agents(total=5):
            result = audit_raw(
                agent.embedded,
                target=f"registry:{agent.name}",
                classifier=SkillClassifier(mode="disabled"),
                verify_signatures=False,
            )
            assert 0 <= result.score <= 100
            assert result.grade in ("A", "B", "C", "D", "F")
            audited += 1
    assert audited > 0
