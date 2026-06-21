#!/usr/bin/env python3
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

BOOL_FIELDS = {
    "phone_visible": ("conversion_signals", "phone_visible"),
    "email_visible": ("conversion_signals", "email_visible"),
    "contact_form_present": ("conversion_signals", "contact_form_present"),
    "booking_or_schedule_present": ("conversion_signals", "booking_or_schedule_present"),
    "reviews_or_testimonials_present": ("trust_signals", "reviews_or_testimonials_present"),
    "license_or_certification_present": ("trust_signals", "license_or_certification_present"),
    "gallery_or_portfolio_present": ("trust_signals", "gallery_or_portfolio_present"),
    "social_links_present": ("trust_signals", "social_links_present"),
    "schema_org_present": ("trust_signals", "schema_org_present"),
    "viewport_meta_present": ("ux_technical_signals", "viewport_meta_present"),
    "missing_meta_description": ("weak_site_indicators_raw", "missing_meta_description"),
    "missing_h1": ("weak_site_indicators_raw", "missing_h1"),
    "no_visible_phone": ("weak_site_indicators_raw", "no_visible_phone"),
    "no_visible_email": ("weak_site_indicators_raw", "no_visible_email"),
    "no_contact_form_detected": ("weak_site_indicators_raw", "no_contact_form_detected"),
    "no_reviews_detected": ("weak_site_indicators_raw", "no_reviews_detected"),
    "no_viewport_meta": ("weak_site_indicators_raw", "no_viewport_meta"),
}

def get_nested(record, path):
    cur = record
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur

def parse_bool(value):
    v = value.lower().strip()
    if v in {"true", "1", "yes"}:
        return True
    if v in {"false", "0", "no"}:
        return False
    raise ValueError(f"Expected boolean value, got: {value}")

def load_records(path):
    records = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"WARN: skipped invalid JSON line {n}: {e}", file=sys.stderr)
    return records

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-root", default="knowledge")
    ap.add_argument("--project", required=True)
    ap.add_argument("--vertical")
    ap.add_argument("--where", action="append", default=[], help="Filter, e.g. no_reviews_detected=true")
    ap.add_argument("--list", action="store_true", help="List matching domains")
    args = ap.parse_args()

    root = Path(args.input_root) / args.project
    paths = [root / args.vertical / "sites.jsonl"] if args.vertical else sorted(root.glob("*/sites.jsonl"))

    records = []
    for path in paths:
        records.extend(load_records(path))

    filters = []
    for item in args.where:
        if "=" not in item:
            raise SystemExit(f"Bad --where format: {item}")
        name, raw = item.split("=", 1)
        name = name.strip()
        if name not in BOOL_FIELDS:
            known = ", ".join(sorted(BOOL_FIELDS))
            raise SystemExit(f"Unknown field: {name}\nKnown fields: {known}")
        filters.append((name, parse_bool(raw)))

    for name, expected in filters:
        path = BOOL_FIELDS[name]
        records = [r for r in records if get_nested(r, path) is expected]

    print(f"records: {len(records)}")
    if args.vertical:
        print(f"project: {args.project}")
        print(f"vertical: {args.vertical}")
    else:
        print(f"project: {args.project}")
        print("vertical: all")

    print()
    for field, path in sorted(BOOL_FIELDS.items()):
        c = Counter(get_nested(r, path) for r in records)
        print(f"{field}: true={c.get(True, 0)} false={c.get(False, 0)} missing={c.get(None, 0)}")

    if args.list:
        print()
        print("matching_domains:")
        for r in records:
            print(f"- {r.get('domain')} {r.get('source_url')}")

if __name__ == "__main__":
    main()
