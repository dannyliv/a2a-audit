# a2a-audit

Security-posture auditor for [A2A (Agent2Agent)](https://a2a-protocol.org/) Agent Cards.

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
uv pip install -e ".[llm]"     # llm extra enables the skill-intent classifier
# or
pip install -e ".[llm]"
a2a-audit --version
```

The skill-intent classifier needs `ANTHROPIC_API_KEY` in the environment. Without it (or without the `llm` extra) the classifier runs in **degraded heuristic mode**, which is clearly marked in the output.

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
- **`classifier.py`** gates skills through a cheap heuristic YAML pre-filter, then sends only candidates to an injection-hardened LLM prompt. The card is untrusted input to our own model call, so its text is wrapped in a delimited data block and never treated as instructions.
- **`score.py`** turns findings into the composite grade.
- **`registry.py`** enumerates real cards with offset pagination and backoff, treating embedded card fields as a stale index (it always re-fetches the canonical card).

See [ARCHITECTURE.md](ARCHITECTURE.md) for design decisions, the threat model, and the v2 sketch.

## Responsible disclosure

Aggregate corpus statistics only. `a2a-audit` does not label specific third-party agents as vulnerable, and it audits only advertised cards. It never sends adversarial traffic to live third-party agents.

## License

[Apache-2.0](LICENSE)
