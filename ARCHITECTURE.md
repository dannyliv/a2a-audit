# Architecture

`a2a-audit` is a small, layered pipeline. This document covers the design
decisions, the threat model for the tool itself, and the v2 sketch. For the
research that informed these choices (A2A object model, signing, competitive
landscape, ASI mapping), see the project's `RESEARCH.md`.

## Scope: posture, not conformance

`a2a-audit` answers one question: how safe is this agent to trust, as a single
graded score. That is deliberately different from the neighbouring tools, and the
whole design follows from it:

- **Conformance / validation** (`a2a-inspector`, `a2a-tck`) answers "is the card
  valid and does the agent work?" with pass/fail against the spec.
- **Issue scanners** (Cisco `a2a-scanner`) answer "what individual problems
  exist?" with a list of findings and severities.
- **Posture auditing** (this tool) answers "how safe is it to trust?" by rolling
  spec-native security checks into one transparent 0-100 score and A-F grade that
  is comparable across agents, diffable over time, and enforceable in CI.

"Valid is not safe" is the load-bearing idea: a card can pass conformance and
still declare no auth, carry no signature, and expose an SSRF-able webhook. So
`a2a-audit` does NOT re-implement conformance or generic issue detection; it adds
the scoring/grading layer on top and can consume conformance signals later
(see v2). This is why, for example, checks never reject a malformed card (a
conformance concern) but instead score what they find.

## Pipeline

```
target (URL | domain | stdin | registry)
   |
   v
fetch.py        discover well-known paths, SSRF-guarded GET, JSON parse
   |
   v
schema.py       lenient pydantic parse -> version detect -> NormalizedCard
   |
   v
checks/*        auth, signature, transport, skills, exposure, webhook
   |              (each returns Findings tagged with severity + ASI id)
   v
score.py        findings -> 0-100 composite + letter grade
   |
   v
report.py       rich table | JSON | aggregate CSV
```

`audit.py` wires these together; `cli.py` is the typer entrypoint.

## Key design decisions

### 1. Model both card serializations, normalize to one shape

There are two Agent Card models: the v0.2/v0.3 JSON shape (flat `url` +
`preferredTransport` + `additionalInterfaces`, a `type` discriminator on
security schemes, `supportsAuthenticatedExtendedCard` at the root) and the v1.0
proto shape (a single `supportedInterfaces` array, the extended-card flag inside
`capabilities`, renamed fields). Most live cards are v0.3.

Rather than branch every check on version, `schema.py` parses a permissive
union of both and normalizes into `NormalizedCard`. Checks never see version
differences. `detect_spec_version()` records which shape was seen for the report.

### 2. Parse leniently

An auditor that rejects malformed cards audits nothing. Every model field is
optional, unknown keys are allowed, and parse failures degrade to
`model_construct` rather than raising. Garbage in produces findings, not a stack
trace.

### 3. Verify signatures, do not just detect them

Per A2A spec section 8.4, a card signature is a detached JWS over the card
canonicalized with RFC 8785 JCS, with the `signatures` field excluded. The
`signature` check rebuilds that exact payload (`rfc8785.dumps` on the card minus
`signatures`), resolves the verification key from the protected header's `jku`
JWKS, and verifies with `jwcrypto`. A naive `json.dumps(sort_keys=True)` would
silently produce wrong bytes and fail valid signatures, so a real JCS
implementation is mandatory.

Verification outcomes: verified (PASS), present-but-unverifiable (LOW, no usable
key), or verification-failed (HIGH, likely tampered).

### 4. The classifier is two-stage, pluggable, and injection-hardened

Regex over skill descriptions over-flags: `login_and_scrape` and `whoami` look
adjacent to attack patterns but are benign. So the heuristic YAML patterns are a
**high-recall gate** that decides which skills reach the model stage, never a
verdict. The model stage is a **pluggable backend** (`backends.py`):

- `deberta` — local ProtectAI DeBERTa injection classifier via onnxruntime.
  Deterministic, CPU, no key. Default when installed.
- `gguf` — local Qwen2.5-7B via llama-cpp-python (Metal). Reasoning + JSON.
- `openai` — any OpenAI-compatible server (Ollama, llama-server, vLLM, OpenRouter).
- `claude` — Anthropic API.
- `heuristic` / `disabled` — gate only / off.

Routing (`build_backend`): explicit `--backend` > `A2A_AUDIT_BACKEND` env >
auto-detect (local-first: deberta → gguf → openai → claude → heuristic). Model
weights live in `models/` and are never committed. The deberta and gguf
libraries are installed by default (`pip install`); weights are fetched
separately with `a2a-audit-pull-models`. The openai and claude backends require
explicit configuration only.

**Union, never veto.** A heuristic gate hit is never downgraded to fully benign
by the model. The model refines severity: a confirmed hit is HIGH, a gate hit the
model does not confirm stays flagged at MEDIUM for review. This is deliberate.
Measured on the seed corpus, DeBERTa alone (as a strict filter) drops recall to
0.73 because it was trained on classic "ignore instructions" injection and misses
exfiltration / shell-exec / phishing / indirect-injection framing. A security
auditor should not miss a real attack to avoid a benign flag, so the gate sets
the floor on recall and the model adds precision on top.

The card is untrusted input to any model call (a prompt-injection vector against
the auditor itself). Defenses: skill text is wrapped in a delimited DATA block,
the system prompt states the text is data and must never be followed as
instructions, and the model must answer with strict JSON. The classifier can
never crash an audit; on any backend error it falls back to a heuristic verdict.

### 5. Composite scoring is the product's opinion

Detection with severities already exists elsewhere. The differentiator is a
single transparent grade. `score.py` keeps the weights in one place, overridable,
so a team can encode its own risk appetite. Passing controls never penalize, so
a well-built card can reach an A.

### Note: the browser demo mirrors the Python engine

`demo/app.js` re-implements the static checks and the scoring weights in
JavaScript so the GitHub Pages demo runs with no backend. This is a deliberate
parallel implementation, not shared code. The two must stay in sync: when a
static check, an ASI mapping, or a scoring weight changes in `a2a_audit/`, make
the matching change in `demo/app.js`. Score parity against the Python CLI is
verified on the bundled example cards (the demo and CLI produce identical
grade/score for each). The model-backed skill stage and JWS verification run
only in the CLI; the browser uses the heuristic gate and presence-only signature
detection.

### 6. The registry is an untrusted, stale index

`a2aregistry.org` embeds card fields, but those are a periodically-refreshed
snapshot plus registry-added health fields and can diverge from what the agent
serves now. `registry.py` uses the embedded card only to discover
`wellKnownURI`/`url`; the auditor re-fetches the canonical card before scoring
(unless `--no-refetch`). Pagination is offset-based with serial pacing and
exponential backoff, because the registry has no `page` param and 403s on
aggressive enumeration.

## Threat model for the tool itself

`a2a-audit` ingests hostile input (arbitrary card JSON) and fetches
attacker-influenced URLs. The two material risks:

1. **SSRF via `fetch.py` / `registry.py` / `jku`.** We fetch user/registry-
   supplied URLs and JWKS endpoints. Mitigations: scheme allowlist (http/https
   only); DNS-resolve the host and reject private, loopback, link-local
   (including `169.254.169.254` cloud metadata), reserved, and multicast
   addresses; re-validate every redirect hop; cap response size; hard timeouts.
   `jku` is treated as untrusted - JWKS fetches go through the same guard and
   require HTTPS.

2. **Prompt injection via card text into our LLM call.** Card skill text is
   untrusted. Mitigation: the classifier wraps it in a delimited data block, the
   system prompt forbids treating it as instructions, output is constrained to
   JSON, and a parse/refusal failure degrades to a heuristic verdict rather than
   trusting model free-text.

See `SECURITY.md` for the reporting policy and the internal-audit findings log.

## v2 sketch (out of scope for v1)

The `rules/` YAML and the classifier prompt are intentionally append-only data,
so a future scheduled **autoresearch** loop could monitor arXiv, CVE feeds, the
OWASP ASI project, and registry diffs for new card-field abuses and propose new
detection rules / prompt updates as pull requests, turning `a2a-audit` into a
self-updating rule set. v1 ships hand-curated checks so the core stays tight and
trustworthy; the data-driven design leaves that door open without a refactor.

Other v2 candidates: consuming `a2a-tck` conformance signals as scoring inputs,
a public posture leaderboard with diff tracking, and an opt-in active-probe mode
against a locally-run target (never against registry agents).
