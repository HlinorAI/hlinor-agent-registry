#!/usr/bin/env python3
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

PATTERNS = {
    "missing_meta_description": ("weak_site_indicators_raw", "missing_meta_description"),
    "missing_h1": ("weak_site_indicators_raw", "missing_h1"),
    "no_visible_phone": ("weak_site_indicators_raw", "no_visible_phone"),
    "no_visible_email": ("weak_site_indicators_raw", "no_visible_email"),
    "no_contact_form": ("weak_site_indicators_raw", "no_contact_form_detected"),
    "no_reviews": ("weak_site_indicators_raw", "no_reviews_detected"),
    "no_viewport_meta": ("weak_site_indicators_raw", "no_viewport_meta"),
    "no_gallery_or_portfolio": ("trust_signals", "gallery_or_portfolio_present", True),
    "no_social_links": ("trust_signals", "social_links_present", True),
    "no_schema_org": ("trust_signals", "schema_org_present", True),
    "no_license_or_certification": ("trust_signals", "license_or_certification_present", True),
    "no_booking_or_schedule": ("conversion_signals", "booking_or_schedule_present", True),
}

def get_nested(record, path):
    cur = record
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur

def pattern_value(record, spec):
    invert = len(spec) == 3 and spec[2] is True
    value = get_nested(record, spec[:2])
    if value is None:
        return None
    return not value if invert else value

def load_records(path):
    out = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"WARN: skipped invalid JSON line {path}:{n}: {e}", file=sys.stderr)
    return out

def pct(n, total):
    return 0.0 if total == 0 else round((n / total) * 100, 1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-root", default="knowledge")
    ap.add_argument("--project", required=True)
    ap.add_argument("--vertical")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--list-domains", action="store_true")
    args = ap.parse_args()

    root = Path(args.input_root) / args.project
    paths = [root / args.vertical / "sites.jsonl"] if args.vertical else sorted(root.glob("*/sites.jsonl"))

    records = []
    for path in paths:
        records.extend(load_records(path))

    total = len(records)
    print(f"project: {args.project}")
    print(f"vertical: {args.vertical or 'all'}")
    print(f"records: {total}")
    print()

    if total == 0:
        return

    counts = Counter()
    missing = Counter()

    for r in records:
        for name, spec in PATTERNS.items():
            v = pattern_value(r, spec)
            if v is None:
                missing[name] += 1
            elif v is True:
                counts[name] += 1

    ranked = sorted(PATTERNS.keys(), key=lambda k: (counts[k], -missing[k], k), reverse=True)

    print("Top weakness patterns:")
    for name in ranked[: args.top]:
        print(f"- {name}: {counts[name]}/{total} ({pct(counts[name], total)}%), missing_data={missing[name]}")

    print()
    print("Practical read:")
    top3 = [name for name in ranked if counts[name] > 0][:3]
    if top3:
        print("Most common detected weaknesses: " + ", ".join(top3))
    else:
        print("No repeated weakness pattern detected yet.")

    if args.list_domains:
        print()
        print("Domains by detected weakness count:")
        scored = []
        for r in records:
            score = sum(1 for spec in PATTERNS.values() if pattern_value(r, spec) is True)
            scored.append((score, r.get("domain"), r.get("source_url")))
        for score, domain, url in sorted(scored, reverse=True):
            print(f"- score={score} {domain} {url}")

if __name__ == "__main__":
    main()
