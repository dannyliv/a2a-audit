# Security Policy

## Reporting a vulnerability

Please report security issues privately via a GitHub Security Advisory on this
repository (Security tab -> Report a vulnerability), or by opening a minimal
issue asking for a private contact channel. Do not file public exploit details
before a fix is available. We aim to acknowledge within 5 business days.

## Scope

`a2a-audit` is a defensive auditing tool. It reads Agent Cards and reports on
their security posture. It does not attack agents: it audits only advertised
cards, sends no adversarial traffic to live third-party agents, and publishes
only aggregate corpus statistics (never naming a specific agent as vulnerable).

## Threat model for the tool itself

The auditor ingests untrusted input (arbitrary card JSON) and fetches
attacker-influenced URLs, so it is its own attack surface. The two material
risks and their mitigations:

### 1. Server-Side Request Forgery (SSRF)

`fetch.py`, `registry.py`, and the signature check's `jku` JWKS retrieval all
fetch URLs that an attacker can influence (a target domain, a registry
`wellKnownURI`, or a `jku` in a card's signature header).

Mitigations in `fetch.assert_safe_url`:
- Scheme allowlist: only `http` / `https`.
- DNS-resolve the host and reject every resolved address that is private,
  loopback, link-local (covers `169.254.169.254` cloud metadata), reserved,
  multicast, or unspecified.
- Redirects are followed manually and **re-validated at every hop** (no blind
  redirect following into a private address).
- Response size cap (5 MiB) and hard timeouts.
- `jku` JWKS fetches additionally require HTTPS and go through the same guard;
  `jku` is treated as untrusted, so a verified signature proves integrity
  against that key, not trust in the issuer.

### 2. Prompt injection into our own LLM call

Skill descriptions are untrusted text sent to the skill-intent classifier
(`classifier.py`). A hostile card could try to hijack our classification call.

Mitigations:
- Card text is wrapped in a delimited DATA block.
- The system prompt instructs the model to treat the block strictly as data,
  never as instructions, even if it says to ignore rules or change roles.
- Output is constrained to a small strict-JSON verdict; free-text is parsed
  defensively and a parse/again failure degrades to a heuristic verdict.
- The classifier can never crash an audit; all errors fall back safely.

### Other hardening

- Lenient parsing: malformed cards produce findings, not crashes.
- No secrets in the repo. The LLM API key is read from an environment variable
  only and is never written to disk or logs.
- A broken individual check is caught and reported, never aborting the run.

## Internal audit findings log

Date: 2026-05-29. Tools: `bandit -ll -r a2a_audit`, `pip-audit`,
`detect-secrets scan`, and a full `git log -p` secret grep.

| Check | Result | Notes |
|---|---|---|
| bandit (medium+ severity) | PASS | No findings. |
| pip-audit (dependency CVEs) | PASS | No known vulnerabilities in dependencies. |
| Secret scan (git history) | PASS | `git log -p --all` grep for `sk-ant`/`AKIA`/PEM/`ghp_`/Slack tokens: none. |
| Secret scan (working tree) | PASS | All `detect-secrets` hits are in vendored `.venv` packages (gitignored) or a dummy placeholder JWS in `tests/fixtures/clean.json`. No real secret committed. |
| SSRF guard | PASS | Unit tests assert blocking of metadata/loopback/private/non-HTTP(S) targets (`tests/test_fetch_ssrf.py`). |
| Signature verification | PASS | Real detached-JWS + JCS verify tested, including the tamper-detection path (`tests/test_signature.py`). |

Re-run the internal audit with:

```bash
bandit -ll -r a2a_audit
pip-audit
detect-secrets scan --exclude-files '\.venv/.*'
```
