"""Skill-description intent classifier (ASI01).

Two stages (RESEARCH §6):
  1. A high-recall heuristic YAML gate (rules/injection_patterns.yaml) flags
     candidate skills. Regex alone over-flags, so a match is a candidate, not a
     verdict.
  2. A pluggable backend (see backends.py) gives the final malicious/benign
     verdict: a local DeBERTa injection classifier (default when installed), a
     local GGUF model (Qwen2.5), any OpenAI-compatible server (Ollama, vLLM),
     or Claude. With no backend installed, the classifier runs the gate alone in
     degraded mode (results marked unverified, capped at LOW by the skills check).

The card is untrusted input to any LLM backend, so the prompt wraps skill text in
a delimited DATA block and forbids treating it as instructions (see backends.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from a2a_audit.backends import Backend, BackendConfig, build_backend

_RULES_PATH = Path(__file__).parent / "rules" / "injection_patterns.yaml"

# Back-compat aliases for the `mode` selector.
_MODE_ALIASES = {"llm": "claude"}


@dataclass(slots=True)
class Verdict:
    malicious: bool
    confidence: float
    reason: str
    mode: str
    matched_patterns: list[str]
    backend_agreed: bool | None = None  # did the model confirm a gate hit? None = no backend


@dataclass(slots=True)
class _Pattern:
    id: str
    regex: re.Pattern[str]
    note: str


class SkillClassifier:
    """Heuristic gate + pluggable verdict backend.

    ``mode`` selects the backend: ``auto`` (best available, local-first),
    ``heuristic`` / ``disabled``, or an explicit ``deberta`` / ``gguf`` /
    ``openai`` / ``claude`` (``llm`` is an alias for ``claude``).
    """

    def __init__(
        self,
        *,
        mode: str = "auto",
        backend: Backend | None = None,
        config: BackendConfig | None = None,
        rules_path: Path | None = None,
    ) -> None:
        self._load_rules(rules_path or _RULES_PATH)
        requested = _MODE_ALIASES.get(mode, mode)
        self.disabled = requested == "disabled"

        if backend is not None:
            self.backend: Backend | None = backend
        elif self.disabled or requested == "heuristic":
            self.backend = None
        else:
            cfg = config or BackendConfig.from_env(override=requested)
            self.backend = build_backend(cfg)

        self.mode = "disabled" if self.disabled else (self.backend.name if self.backend else "heuristic")

    @property
    def is_degraded(self) -> bool:
        """True when running the gate alone (no model backend) and not disabled."""
        return self.backend is None and not self.disabled

    def _load_rules(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.patterns: list[_Pattern] = [
            _Pattern(id=p["id"], regex=re.compile(p["regex"], re.IGNORECASE), note=p.get("note", ""))
            for p in data.get("patterns", [])
        ]
        self.benign_hints: list[str] = [h.lower() for h in data.get("benign_hints", [])]

    # -- stage 1: heuristic gate --------------------------------------------
    def prefilter(self, text: str) -> list[str]:
        return [p.id for p in self.patterns if p.regex.search(text)]

    def _looks_benign(self, text: str) -> bool:
        low = text.lower()
        return any(h in low for h in self.benign_hints)

    def _heuristic_verdict(self, text: str, matched: list[str]) -> Verdict:
        if not matched:
            return Verdict(False, 0.9, "no injection patterns matched", self.mode, matched)
        confidence = 0.45 if self._looks_benign(text) else 0.6
        return Verdict(
            malicious=True,
            confidence=confidence,
            reason=f"matched patterns (unverified): {', '.join(matched)}",
            mode=self.mode,
            matched_patterns=matched,
        )

    # -- stage 2: backend verdict -------------------------------------------
    def classify(self, text: str) -> Verdict:
        if self.disabled:
            return Verdict(False, 0.0, "classifier disabled", "disabled", [])
        matched = self.prefilter(text)

        if self.backend is None:
            return self._heuristic_verdict(text, matched)

        # gate_first backends only run on candidates to save calls.
        if self.backend.gate_first and not matched:
            return Verdict(False, 0.9, "no injection patterns matched", self.mode, matched)
        try:
            bv = self.backend.classify(text)
        except Exception as exc:  # noqa: BLE001 - never let a backend crash an audit
            v = self._heuristic_verdict(text, matched)
            v.reason = f"backend '{self.mode}' error, fell back to heuristic: {exc}; {v.reason}"
            return v

        # Union, not veto: a heuristic gate hit is never downgraded to fully
        # benign by the model (recall-favoring, the right bias for a security
        # auditor). The model REFINES severity via `backend_agreed`: a confirmed
        # hit is high-confidence; a gate hit the model did not confirm is still
        # flagged, at a lower severity for review.
        malicious = bool(matched) or bv.malicious
        if not malicious:
            return Verdict(False, bv.confidence, bv.reason, self.mode, matched, backend_agreed=False)
        return Verdict(
            malicious=True,
            confidence=bv.confidence,
            reason=bv.reason,
            mode=self.mode,
            matched_patterns=matched,
            backend_agreed=bv.malicious,
        )


def skill_text(name: str | None, description: str | None, examples: list[str] | None) -> str:
    parts = [name or "", description or ""]
    if examples:
        parts.extend(examples)
    return "\n".join(p for p in parts if p)
