"""Shared per-audit context passed to every check."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from a2a_audit.classifier import SkillClassifier


@dataclass(slots=True)
class CheckContext:
    """State a check may need beyond the card itself."""

    fetched_https: bool | None = None  # was the card served over HTTPS? None = offline/paste
    allow_http: bool = True
    verify_signatures: bool = True
    classifier: SkillClassifier | None = None

    @property
    def classifier_mode(self) -> str:
        return self.classifier.mode if self.classifier is not None else "disabled"
