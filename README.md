# a2a-audit

Security-posture auditor for [A2A (Agent2Agent)](https://a2a-protocol.org/) Agent Cards.

**Live demo:** https://dannyliv.github.io/a2a-audit/ (heuristic gate only; the CLI adds model-backed classification)

`a2a-audit` fetches an agent's canonical `/.well-known/agent-card.json`, parses it against the A2A object model (both the v0.2/v0.3 JSON shape and the v1.0 proto shape), runs security checks mapped to the [OWASP Top 10 for Agentic Applications (ASI 2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), and produces a risk-scored report: a human-readable table, machine JSON, and a non-zero exit code for CI.

## Why this exists

An A2A Agent Card is the agent's public contract: where it lives, how to authenticate, what it can do, who vouches for it. It is also attacker-reachable by definition. Most cards in the wild declare no auth, are unsigned, and a few are served over plaintext HTTP.

The tooling around cards splits into lanes. `a2a-inspector` and `a2a-tck` check **conformance**. Cisco's `a2a-scanner` does **per-finding detection** with severities. Neither produces a single, opinionated, comparable **posture grade**. That is the lane `a2a-audit` occupies: one transparent 0-100 score and letter grade per card, diffable over time, gate-able in CI.

This is a posture auditor, not a conformance checker. It interoperates with the conformance tools rather than duplicating them.

## How it works

```
discover  ->  fetch canonical card  ->  normalize (v0.3 JSON / v1.0 proto)
          ->  run checks  ->  score (0-100 + grade)  ->  report (table / JSON / CSV)
```

Every check is static and offline except the skill-description intent check, which calls an LLM. The fetch layer is SSRF-hardened (scheme allowlist, private/loopback/link-local/cloud-metadata IP blocking, redirect re-validation, response-size cap) because it retrieves attacker-influenced URLs.

## Install

```bash
pip install -e .          # installs deberta + gguf libs automatically
a2a-audit-pull-models     # fetches DeBERTa ONNX and Qwen GGUF weights into models/
a2a-audit --version
```

A plain `pip install` now includes the DeBERTa and GGUF classifier libraries.
After installation, run `a2a-audit-pull-models` once to download the model
weights (~700 MB DeBERTa + ~4.4 GB Qwen GGUF). The Qwen download compiles
`llama-cpp-python` from source, so a C compiler and cmake must be available.

With model weights present, the default `auto` mode selects `deberta`
(local, fast, deterministic). If weights are missing the tool falls back to
heuristic mode (clearly marked in output) and prints a hint to run
`a2a-audit-pull-models`.

The `openai` and `claude` backends are optional configuration changes only.
See [Skill classifier backends](#skill-classifier-backends).

## Usage

```bash
# Audit a live agent by domain or URL (fetches canonical card, tries both well-known paths)
a2a-audit https://example-agent.com

# Audit a card from stdin, fully offline
a2a-audit --paste < card.json

# Machine output + CI gate (exit 1 if any finding >= --fail-on, default HIGH)
a2a-audit https://example-agent.com --json --fail-on MEDIUM

# Aggregate posture across real registry cards (canonical re-fetch each)
a2a-audit --registry --limit 20 --json > corpus.json
```

Key flags:

| Flag | Default | Meaning |
|---|---|---|
| `--paste` | off | Read card JSON from stdin (no network) |
| `--url URL` | | Explicit card/agent URL |
| `--registry --limit N` | 20 | Audit N cards from a2aregistry.org |
| `--json` | off | Emit machine JSON to stdout |
| `--fail-on SEV` | HIGH | Min severity (INFO..CRITICAL) for non-zero exit |
| `--classifier MODE` | auto | `auto` / `llm` / `heuristic` / `disabled` |
| `--no-verify-sigs` | off | Skip cryptographic signature verification |
| `--no-refetch` | off | Registry: audit the embedded card, skip canonical re-fetch |
| `--out PATH` | | Write the report JSON to PATH |

### Example

```
╭─────────────────────── a2a-audit ────────────────────────╮
│ (stdin)                                                   │
│ score 52/100  grade F   spec v0.3   classifier heuristic  │
╰───────────────────────────────────────────────────────────╯
 Severity   ASI           Check       Finding
 MEDIUM     ASI03         auth        No authentication declared
 MEDIUM     ASI04         signature   Card is unsigned
 MEDIUM     ASI03         exposure    Extended card advertised without authentication
 MEDIUM     ASI07/ASI05   webhook     Push notifications enabled with no declared auth
 LOW        ASI04         transport   No provider information
Passed controls: skills, transport
```

## Skill classifier backends

The skill-intent check (ASI01) is a two-stage pipeline:

1. **Heuristic gate** (always on): a high-recall regex pre-filter selects candidate skills. It is tuned to over-flag, so a match is a candidate, not a verdict.
2. **Model backend** (pluggable): confirms or clears each candidate and sets severity. A confirmed hit is HIGH; a gate hit the model does not confirm stays flagged at MEDIUM for review. A gate hit is never silently dropped, which keeps recall high (the right bias for a security auditor).

Pick a backend with `--backend` (or the `A2A_AUDIT_BACKEND` env var):

| Backend | What it is | License | Install |
|---|---|---|---|
| `heuristic` | Gate only, no model (degraded, marked unverified) | n/a | default install (no weights) |
| `deberta` | Local [ProtectAI DeBERTa](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) injection classifier (ONNX, CPU, deterministic). Default auto-selected when weights are present. | Apache-2.0 | default install + `a2a-audit-pull-models` |
| `gguf` | Local [Qwen2.5-7B](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct) via llama.cpp (Metal). Reasoning + JSON verdict. | Apache-2.0 | default install + `a2a-audit-pull-models` |
| `openai` | Any OpenAI-compatible server: Ollama, llama-server, vLLM, OpenRouter | varies | core (`httpx`), explicit `--backend openai` |
| `claude` | Anthropic API | cloud | `pip install -e ".[llm]"` + `ANTHROPIC_API_KEY`, explicit `--backend claude` |
| `auto` | First available, local-first: deberta → gguf → openai → claude → heuristic | | default |

### Install the local models

The happy path after a plain `pip install -e .`:

```bash
# Download both default model weights (skip files already present)
a2a-audit-pull-models          # fetches deberta + gguf

# Selective download
a2a-audit-pull-models --deberta   # DeBERTa only (~700 MB)
a2a-audit-pull-models --gguf      # Qwen GGUF only (~4.4 GB)

# Run an audit — auto mode selects deberta
a2a-audit https://example-agent.com
```

### Route to any model

The `openai` backend speaks the OpenAI chat API, so any compatible server drops in:

```bash
# Ollama
ollama serve & ollama pull qwen2.5:7b
a2a-audit <url> --backend openai --backend-url http://localhost:11434/v1 --backend-model qwen2.5:7b

# vLLM / llama-server / OpenRouter: same shape, different --backend-url
```

Routing config resolves from `--backend*` flags, then `A2A_AUDIT_*` env vars (`A2A_AUDIT_BACKEND`, `A2A_AUDIT_DEBERTA_PATH`, `A2A_AUDIT_GGUF_PATH`, `A2A_AUDIT_OPENAI_BASE_URL`, `A2A_AUDIT_OPENAI_MODEL`), then auto-detect. Model weights live in `models/` and are never committed.

## Checks and ASI mapping

Each check maps to a primary [OWASP ASI 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) category (and a secondary where relevant).

| Check | What it inspects | Primary ASI | Secondary |
|---|---|---|---|
| `auth` | securitySchemes strength, whether auth is required, weak mechanisms (API key in query, HTTP Basic, deprecated OAuth flows) | ASI03 Agent Identity & Privilege Abuse | ASI07 |
| `signature` | JWS signature presence **and cryptographic verification** over the RFC 8785 JCS payload (detached JWS) | ASI04 Agentic Supply Chain Compromise | ASI07 |
| `transport` | HTTPS on endpoints and on the card fetch itself; provider presence and URL hygiene | ASI04 Agentic Supply Chain Compromise | ASI07 |
| `skills` | LLM-backed detection of prompt-injection / goal-hijack payloads in skill descriptions | ASI01 Agent Goal Hijack | ASI06 |
| `exposure` | Authenticated-extended-card over-exposure; skill id/tag hygiene | ASI03 Agent Identity & Privilege Abuse | ASI02 |
| `webhook` | Push-notification webhook SSRF / abuse posture | ASI07 Insecure Inter-Agent Communication | ASI05 |

Note: OWASP ASI07 emphasizes inter-agent message spoofing / Agent-in-the-Middle more than SSRF, so the `webhook` check's SSRF framing under ASI07 is partial; findings carry that caveat.

## Scoring

Score starts at 100. Each non-passing finding subtracts `severity_weight x check_weight`. Passing controls (a present, correct control) never subtract. Grades: A >= 90, B >= 80, C >= 70, D >= 60, else F. Weights are configurable so a team can tune the opinion without forking. Severity weights default to INFO 0, LOW 3, MEDIUM 8, HIGH 18, CRITICAL 30.

## How this is built

- **`schema.py`** parses both card serializations leniently (an auditor must ingest malformed input, not reject it) and normalizes them into one `NormalizedCard` the checks consume.
- **`fetch.py`** is the SSRF boundary: it DNS-resolves hosts and blocks private/reserved targets, re-validates every redirect hop, and caps response size.
- **`checks/`** holds one module per check, each exporting `META` and `run(card, ctx)`.
- **`classifier.py`** gates skills through a cheap heuristic YAML pre-filter, then routes candidates to a pluggable backend (`backends.py`: DeBERTa, GGUF/Qwen, any OpenAI-compatible server, or Claude). The card is untrusted input to any model call, so its text is wrapped in a delimited data block and never treated as instructions. A gate hit is never vetoed to benign; the model refines severity.
- **`score.py`** turns findings into the composite grade.
- **`registry.py`** enumerates real cards with offset pagination and backoff, treating embedded card fields as a stale index (it always re-fetches the canonical card).

See [ARCHITECTURE.md](ARCHITECTURE.md) for design decisions, the threat model, and the v2 sketch.

## Responsible disclosure

Aggregate corpus statistics only. `a2a-audit` does not label specific third-party agents as vulnerable, and it audits only advertised cards. It never sends adversarial traffic to live third-party agents.

## License

[Apache-2.0](LICENSE)
