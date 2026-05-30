# Red-teaming the skill-intent classifier

Scope: this is not red-teaming a chat model. It measures whether
`a2a_audit.classifier` catches adversarially-crafted malicious skill / tool
descriptions (ASI01 Agent Goal Hijack) without flagging benign ones.

## Files

- `corpus.jsonl` - hand-authored labeled seed corpus (30 malicious across 10
  techniques + 30 benign, including adversarial-benign cases like
  `login_and_scrape`, `whoami`, `send_email`, "explains curl", openssl private
  key tutorials, and quoted "ignore previous").
- `eval.py` - runs the classifier over the corpus and reports recall /
  precision / FPR / accuracy against the thresholds (recall >= 0.90, FPR <= 0.10).
- `generate.py` - GOAT-style adversarial generator (Pavlova et al., Meta,
  arXiv:2410.01606): an attacker LLM reasons over a technique toolbox to produce
  diverse, evasive malicious descriptions. Requires `ANTHROPIC_API_KEY`.

## Method

The classifier is two-stage: a high-recall heuristic gate (`rules/injection_patterns.yaml`)
decides which skills reach the LLM intent classifier, which makes the final call.
Because a skill the gate misses never reaches the LLM, the **gate's recall caps
the whole classifier's recall**, so the gate is tuned for recall and the LLM
provides precision.

The GOAT adaptation: rather than multi-turn chat jailbreaks, the attacker LLM
generates malicious skill-description payloads aimed at evading a naive keyword
filter; `generate.py` records whether the current classifier already catches each
one, feeding the next round of pattern/prompt hardening.

## Methods evaluated / borrowed from

GOAT (primary, implemented). Also reviewed for technique coverage: PyRIT
(XPIAOrchestrator, indirect injection), DeepTeam (OWASP_ASI_2026 framework),
garak (breadth probes), PAIR and TAP (attacker-LLM refinement / tree search).
v2 watch-items for an active-probe mode against a locally-run target only: UDora,
PISmith.

## Running

```bash
python redteam/eval.py --mode heuristic       # offline baseline (no key)
python redteam/eval.py --mode llm             # full classifier (needs key)
python redteam/generate.py --n 20             # GOAT generation (needs key)
```

## Results

See the project `RESEARCH.md` section "Red-team evaluation" for recorded numbers
and the overfitting / held-out caveats.
