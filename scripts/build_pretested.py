#!/usr/bin/env python3
"""Build demo/data/pretested.json: ~110 real A2A agent cards, audited on-device
with the full DeBERTa classifier, with results pre-computed for the demo.

Sources: a2aregistry.org (canonical re-fetch, embedded fallback) + awesome-a2a
top-up. Each entry: {name, url, source, card, report}. Aggregate stats are also
regenerated from this set.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

from a2a_audit.audit import audit_raw
from a2a_audit.classifier import SkillClassifier
from a2a_audit.fetch import FetchError, fetch_card
from a2a_audit.registry import RegistryClient

TARGET = 112
REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "demo" / "data" / "pretested.json"
AGG = REPO / "demo" / "data" / "aggregate.json"
AWESOME = "https://raw.githubusercontent.com/ai-boost/awesome-a2a/main/README.md"

clf = SkillClassifier(mode="deberta")  # full local classifier, loaded once
print("classifier:", clf.mode)

entries: list[dict] = []
seen_urls: set[str] = set()


def add(name, url, card, source):
    if not isinstance(card, dict) or not url or url in seen_urls:
        return False
    try:
        https = url.startswith("https://")
        res = audit_raw(card, target=url, fetched_https=https, classifier=clf, verify_signatures=False)
    except Exception as exc:  # noqa: BLE001
        print("  audit failed", url, exc)
        return False
    entries.append(
        {"name": name or card.get("name") or url, "url": url, "source": source,
         "card": card, "report": res.to_dict()}
    )
    seen_urls.add(url)
    return True


# 1) Registry: canonical re-fetch, embedded fallback.
print("== registry ==")
with RegistryClient() as rc:
    for ag in rc.iter_agents(total=200):
        tgt = ag.discovery_target()
        name = ag.name
        done = False
        if tgt:
            try:
                fr = fetch_card(tgt, timeout=6.0)
                done = add(name, fr.url, fr.raw, "canonical")
            except (FetchError, Exception):  # noqa: BLE001
                done = False
        if not done:
            url = tgt or (ag.embedded.get("url") or "")
            add(name, url, ag.embedded, "registry-snapshot")
    print(f"  after registry: {len(entries)}")

# 2) awesome-a2a top-up if short.
if len(entries) < TARGET:
    print("== awesome-a2a top-up ==")
    try:
        md = httpx.get(AWESOME, timeout=15.0, follow_redirects=True).text
        hosts = []
        for m in re.findall(r"https?://[\w.-]+(?:/[\w./-]*)?", md):
            host = re.match(r"https?://[\w.-]+", m)
            if host and host.group(0) not in hosts:
                hosts.append(host.group(0))
        for origin in hosts:
            if len(entries) >= TARGET:
                break
            try:
                fr = fetch_card(origin, timeout=6.0)
                add(fr.raw.get("name"), fr.url, fr.raw, "awesome-a2a")
            except Exception:  # noqa: BLE001
                continue
    except Exception as exc:  # noqa: BLE001
        print("  awesome fetch failed:", exc)
    print(f"  after top-up: {len(entries)}")

# Sort: worst grade first is alarmist; sort by name for neutral presentation.
entries.sort(key=lambda e: (e["name"] or "").lower())

OUT.write_text(json.dumps({"generated": "2026-05-29", "count": len(entries), "entries": entries}, indent=2))
print(f"wrote {OUT} with {len(entries)} entries")

# Regenerate aggregate from this larger set.
from collections import Counter  # noqa: E402

oks = [e["report"] for e in entries]
grades = Counter(r["grade"] for r in oks)
specs = Counter(r["spec_version"] for r in oks)
fc: Counter = Counter()
for r in oks:
    for f in r["findings"]:
        if not f["passed"]:
            fc[f["title"]] += 1
agg = {
    "n": len(oks),
    "source": "a2aregistry.org + awesome-a2a live cards (public, point-in-time)",
    "captured": "2026-05-29",
    "mean_score": round(sum(r["score"] for r in oks) / max(len(oks), 1), 1),
    "grades": dict(grades),
    "specs": dict(specs),
    "top_findings": fc.most_common(8),
}
AGG.write_text(json.dumps(agg, indent=2))
print(f"wrote {AGG}: n={agg['n']} mean={agg['mean_score']} grades={dict(grades)}")
