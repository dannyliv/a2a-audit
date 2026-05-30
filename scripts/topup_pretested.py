#!/usr/bin/env python3
"""Top up demo/data/pretested.json past 110 entries from extra public sources."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import httpx

from a2a_audit.audit import audit_raw
from a2a_audit.classifier import SkillClassifier
from a2a_audit.fetch import fetch_card

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "demo" / "data" / "pretested.json"
AGG = REPO / "demo" / "data" / "aggregate.json"
TARGET = 114

data = json.loads(OUT.read_text())
entries = data["entries"]
seen = {e["url"] for e in entries}
clf = SkillClassifier(mode="deberta")
print("start:", len(entries))

# Extra public sources to scrape for candidate origins.
SOURCES = [
    "https://a2aagentlist.com/",
    "https://raw.githubusercontent.com/ai-boost/awesome-a2a/main/README.md",
    "https://raw.githubusercontent.com/pab1it0/awesome-a2a/main/README.md",
]
cands: list[str] = []
for src in SOURCES:
    try:
        txt = httpx.get(src, timeout=15.0, follow_redirects=True).text
        for m in re.findall(r"https?://[\w.-]+", txt):
            if m not in cands:
                cands.append(m)
    except Exception as exc:  # noqa: BLE001
        print("src failed", src, exc)

print("candidate hosts:", len(cands))
for origin in cands:
    if len(entries) >= TARGET:
        break
    if any(origin in u for u in seen):
        continue
    try:
        fr = fetch_card(origin, timeout=5.0)
        if fr.url in seen:
            continue
        res = audit_raw(fr.raw, target=fr.url, fetched_https=fr.url.startswith("https://"),
                        classifier=clf, verify_signatures=False)
        entries.append({"name": fr.raw.get("name") or fr.url, "url": fr.url,
                        "source": "directory", "card": fr.raw, "report": res.to_dict()})
        seen.add(fr.url)
        print("  added", fr.url, res.to_dict()["grade"])
    except Exception:  # noqa: BLE001, S112 - best-effort scraper, skip failures
        continue

entries.sort(key=lambda e: (e["name"] or "").lower())
data["entries"] = entries
data["count"] = len(entries)
OUT.write_text(json.dumps(data, indent=2))
print("final:", len(entries))

oks = [e["report"] for e in entries]
fc: Counter = Counter()
for r in oks:
    for f in r["findings"]:
        if not f["passed"]:
            fc[f["title"]] += 1
agg = {
    "n": len(oks), "source": "a2aregistry.org + public A2A directories (point-in-time)",
    "captured": "2026-05-29",
    "mean_score": round(sum(r["score"] for r in oks) / max(len(oks), 1), 1),
    "grades": dict(Counter(r["grade"] for r in oks)),
    "specs": dict(Counter(r["spec_version"] for r in oks)),
    "top_findings": fc.most_common(8),
}
AGG.write_text(json.dumps(agg, indent=2))
print("agg n", agg["n"], "mean", agg["mean_score"])
