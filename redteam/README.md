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

## What is measured

Each example in the corpus is a single Agent Card skill / tool description. The
classifier makes one binary decision per description: injection-bearing
(malicious) or benign. Those decisions are compared against the hand-assigned
labels, producing four counts that feed every metric: true positives (tp,
attacks correctly flagged), false positives (fp, benign text wrongly flagged),
true negatives (tn, benign text correctly cleared), and false negatives (fn,
attacks that slipped through).

Recall is the share of real attacks the tool caught, tp / (tp + fn). Precision
is how often a flag was correct, tp / (tp + fp). FPR (false-positive rate) is
the share of benign descriptions that raised a false alarm, fp / (fp + tn).
F1 is the harmonic mean of precision and recall, a single balance score.

Recall is the headline metric. This is a security tool, so a missed attack (a
false negative) is the costly failure. We accept a higher false-positive rate
to avoid letting an injection-bearing skill description pass unflagged. That is
why the design is union, not veto: the heuristic gate is tuned for recall and
the LLM intent stage supplies the precision that the gate alone lacks.

## Results

The numbers below are for the **heuristic gate alone** (`--mode heuristic`, no
ML backend and no API key), recorded by `redteam/eval.py` into
`redteam/results.json`. The corpus is 60 descriptions: 30 malicious and 30
benign.

| mode | recall | precision | FPR | accuracy | F1 | tp | fp | tn | fn |
|------|--------|-----------|-----|----------|-----|----|----|----|----|
| heuristic gate | 1.000 | 0.968 | 0.033 | 0.983 | 0.984 | 30 | 1 | 29 | 0 |

The gate caught all 30 attacks (recall 1.000) with a single false positive: one
benign description (an item that explains common shell commands such as `curl`
and `wget` to beginners) tripped a pattern. F1 is computed from precision and
recall as their harmonic mean. The gate is deliberately a high-recall
pre-filter, and the LLM intent stage that downgrades borderline flags is what
trims false positives further; it is not exercised in heuristic mode. The
success thresholds the script checks are recall >= 0.90 and FPR <= 0.10, both
met here.

The DeBERTa, GGUF, openai, and claude backends require downloaded models or an
API key and were not run for this baseline, so their numbers are not reported
here. Re-run with the relevant `--mode` to record them.

## Reproduce

```bash
# Heuristic gate baseline (no model or API key needed)
python redteam/eval.py --mode heuristic --out redteam/results.json

# Full classifier and other backends (need downloaded models or an API key)
python redteam/eval.py --mode llm --out redteam/results.json
python redteam/eval.py --mode deberta --out redteam/results.json
python redteam/eval.py --mode gguf --out redteam/results.json

# GOAT adversarial generation (needs ANTHROPIC_API_KEY)
python redteam/generate.py --n 20
```
