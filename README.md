# a2a-audit

Security-posture auditor for [A2A (Agent2Agent)](https://a2a-protocol.org/) Agent Cards.

**Live demo:** https://dannyliv.github.io/a2a-audit/ (heuristic gate only; the CLI adds model-backed classification)

`a2a-audit` fetches an agent's canonical `/.well-known/agent-card.json`, parses it against the A2A object model (both the v0.2/v0.3 JSON shape and the v1.0 proto shape), runs security checks mapped to the [OWASP Top 10 for Agentic Applications (ASI 2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), and produces a risk-scored report: a human-readable table, machine JSON, and a non-zero exit code for CI.

## Why this exists

An A2A Agent Card is the agent's public contract: where it lives, how to authenticate, what it can do, who vouches for it. It is also attacker-reachable by definition. Most cards in the wild declare no auth, are unsigned, and a few are served over plaintext HTTP.

### What it does vs other A2A tools

**Valid is not the same as safe.** A card can be perfectly well-formed, pass every conformance test, and still require no authentication, carry no signature, and expose a webhook an attacker can abuse. Those are different questions, answered by different tools:

| Tool type | Question it answers | Examples | Output |
|---|---|---|---|
| **Conformance / validation** | Is the card valid, complete, and does the agent work? | [`a2a-inspector`](https://github.com/a2aproject/a2a-inspector), [`a2a-tck`](https://github.com/a2aproject/a2a-tck) | pass/fail against the spec |
| **Issue scanner** | What individual problems does this card have? | [Cisco `a2a-scanner`](https://github.com/cisco-ai-defense/a2a-scanner) | a list of findings with severities |
| **Posture auditor (this tool)** | How safe is this agent to trust, as one grade? | **`a2a-audit`** | one 0-100 score + A-F grade, diffable, CI-gate-able |

`a2a-audit` is a **security-posture auditor, not a conformance checker**. Conformance tools tell you the card is valid; `a2a-audit` tells you whether it is safe to trust, as a single comparable grade you can track over time and enforce in a release pipeline. It interoperates with the conformance tools rather than duplicating them, and unlike a plain issue scanner it rolls the findings into one opinionated, transparent grade.

## How it works

```
discover  ->  fetch canonical card  ->  normalize (v0.3 JSON / v1.0 proto)
          ->  run checks  ->  score (0-100 + grade)  ->  report (table / JSON / CSV)
```

Every check is static and offline except the skill-description intent check, which runs the skill classifier. The fetch layer is SSRF-hardened (scheme allowlist, private/loopback/link-local/cloud-metadata IP blocking, redirect re-validation, response-size cap) because it retrieves attacker-influenced URLs.

## Install

```bash
pip install -e .          # installs the deberta + gguf classifier libraries by default
a2a-audit-pull-models     # one-time: downloads DeBERTa ONNX + Qwen GGUF weights into models/
a2a-audit --version
```

A plain install includes the two local classifier backends. Run `a2a-audit-pull-models` once to fetch the weights (~700 MB DeBERTa + ~4.4 GB Qwen GGUF). The Qwen backend uses `llama-cpp-python`, which compiles from source, so a C compiler and cmake must be available.

With weights present, the default `auto` mode selects **`deberta`** (local, fast, deterministic). If weights are missing, the tool falls back to heuristic mode (clearly marked) and prints a hint to run `a2a-audit-pull-models`. The `openai` and `claude` backends are optional configuration changes only.

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
| `--backend MODE` | auto | `auto` / `deberta` / `gguf` / `openai` / `claude` / `heuristic` / `disabled` |
| `--backend-url URL` | | OpenAI-compatible base URL (Ollama, vLLM, ...) |
| `--backend-model M` | | Model name (openai/claude) or GGUF path (gguf) |
| `--no-verify-sigs` | off | Skip cryptographic signature verification |
| `--no-refetch` | off | Registry: audit the embedded card, skip canonical re-fetch |
| `--out PATH` | | Write the report JSON to PATH |

### Example

```
╭─────────────────────── a2a-audit ────────────────────────╮
│ (stdin)                                                   │
│ score 52/100  grade F   spec v0.3   classifier deberta    │
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

The two local backends ship by default; pick one with `--backend` (or `A2A_AUDIT_BACKEND`):

| Backend | What it is | License | Setup |
|---|---|---|---|
| `deberta` | Local [ProtectAI DeBERTa](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) injection classifier (ONNX, CPU, deterministic). **Default.** | Apache-2.0 | bundled + `a2a-audit-pull-models` |
| `gguf` | Local [Qwen2.5-7B](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct) via llama.cpp (Metal). Reasoning + JSON verdict. | Apache-2.0 | bundled + `a2a-audit-pull-models` |
| `openai` | Any OpenAI-compatible server: Ollama, llama-server, vLLM, OpenRouter | varies | optional config |
| `claude` | Anthropic API | cloud | `.[llm]` + `ANTHROPIC_API_KEY` |
| `heuristic` | Gate only, no model (degraded, marked unverified) | n/a | core |
| `auto` | First available, local-first: deberta → gguf → openai → claude → heuristic | | default |

### Download the local models

```bash
a2a-audit-pull-models            # both DeBERTa and Qwen GGUF
a2a-audit-pull-models --deberta  # DeBERTa only (~700 MB)
a2a-audit-pull-models --gguf     # Qwen GGUF only (~4.4 GB)
```

This downloads into `models/` at the paths the backends expect (skips files already present). Model weights are never committed.

### Route to any other model (optional)

The `openai` backend speaks the OpenAI chat API, so any compatible server drops in:

```bash
# Ollama
ollama serve & ollama pull qwen2.5:7b
a2a-audit <url> --backend openai --backend-url http://localhost:11434/v1 --backend-model qwen2.5:7b

# vLLM / llama-server / OpenRouter: same shape, different --backend-url
```

Routing resolves from `--backend*` flags, then `A2A_AUDIT_*` env vars (`A2A_AUDIT_BACKEND`, `A2A_AUDIT_DEBERTA_PATH`, `A2A_AUDIT_GGUF_PATH`, `A2A_AUDIT_OPENAI_BASE_URL`, `A2A_AUDIT_OPENAI_MODEL`), then auto-detect (local-first).

## Checks and ASI mapping

Each check maps to a primary [OWASP ASI 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) category (and a secondary where relevant).

| Check | What it inspects | Primary ASI | Secondary |
|---|---|---|---|
| `auth` | securitySchemes strength, whether auth is required, weak mechanisms (API key in query, HTTP Basic, deprecated OAuth flows) | ASI03 Agent Identity & Privilege Abuse | ASI07 |
| `signature` | JWS signature presence **and cryptographic verification** over the RFC 8785 JCS payload (detached JWS) | ASI04 Agentic Supply Chain Compromise | ASI07 |
| `transport` | HTTPS on endpoints and on the card fetch itself; provider presence and URL hygiene | ASI04 Agentic Supply Chain Compromise | ASI07 |
| `skills` | Model-backed detection of prompt-injection / goal-hijack payloads in skill descriptions | ASI01 Agent Goal Hijack | ASI06 |
| `exposure` | Authenticated-extended-card over-exposure; skill id/tag hygiene | ASI03 Agent Identity & Privilege Abuse | ASI02 |
| `webhook` | Push-notification webhook SSRF / abuse posture | ASI07 Insecure Inter-Agent Communication | ASI05 |

Note: OWASP ASI07 emphasizes inter-agent message spoofing / Agent-in-the-Middle more than SSRF, so the `webhook` check's SSRF framing under ASI07 is partial; findings carry that caveat.

## Scoring

Score starts at 100. Each non-passing finding subtracts `severity_weight x check_weight`. Passing controls never subtract. Grades: A >= 90, B >= 80, C >= 70, D >= 60, else F. Weights are configurable. Severity weights default to INFO 0, LOW 3, MEDIUM 8, HIGH 18, CRITICAL 30.

## How this is built

- **`schema.py`** parses both card serializations leniently and normalizes them into one `NormalizedCard` the checks consume.
- **`fetch.py`** is the SSRF boundary: it DNS-resolves hosts and blocks private/reserved targets, re-validates every redirect hop, and caps response size.
- **`checks/`** holds one module per check, each exporting `META` and `run(card, ctx)`.
- **`classifier.py`** gates skills through a heuristic YAML pre-filter, then routes candidates to a pluggable backend (`backends.py`: DeBERTa, GGUF/Qwen, any OpenAI-compatible server, or Claude). The card is untrusted input to any model call, so its text is wrapped in a delimited data block and never treated as instructions. A gate hit is never vetoed to benign; the model refines severity.
- **`score.py`** turns findings into the composite grade.
- **`registry.py`** enumerates real cards with offset pagination and backoff, treating embedded card fields as a stale index (it always re-fetches the canonical card).

See [ARCHITECTURE.md](ARCHITECTURE.md) for design decisions, the threat model, and the v2 sketch.

## Responsible disclosure

Aggregate corpus statistics only. `a2a-audit` audits only advertised cards, sends no adversarial traffic to live third-party agents, and the published demo presents posture snapshots of public cards (point-in-time, for education, not accusation).

## License

[Apache-2.0](LICENSE)
