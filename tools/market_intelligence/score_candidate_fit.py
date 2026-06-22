#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

def get(record, *path):
    cur = record
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur

def score_record(r):
    domain = r.get("domain", "")
    title = get(r, "page", "title") or ""
    h1 = get(r, "page", "h1") or []

    phone = bool(get(r, "conversion_signals", "phone_visible"))
    email = bool(get(r, "conversion_signals", "email_visible"))
    form = bool(get(r, "conversion_signals", "contact_form_present"))
    contact = phone or email or form

    links = get(r, "structure_signals", "links_count") or 0
    images = get(r, "structure_signals", "images_count") or 0
    forms = get(r, "structure_signals", "forms_count") or 0

    weaknesses = [
        get(r, "weak_site_indicators_raw", "missing_meta_description"),
        get(r, "weak_site_indicators_raw", "no_reviews_detected"),
        get(r, "weak_site_indicators_raw", "no_contact_form_detected"),
        get(r, "weak_site_indicators_raw", "no_visible_phone"),
        not bool(get(r, "trust_signals", "gallery_or_portfolio_present")),
        not bool(get(r, "trust_signals", "schema_org_present")),
    ]
    weakness_count = sum(1 for x in weaknesses if x is True)

    reasons = []

    if domain in {"example.com", "example.org", "example.net"}:
        return "REJECT", 0, ["example/test domain"]

    if not title and not h1:
        return "NEEDS_BROWSER_CHECK", weakness_count, ["missing title and h1; simple HTML fetch may be incomplete"]

    if not contact:
        reasons.append("no visible contact signal")

    if links < 3 and images == 0 and forms == 0:
        reasons.append("too little business/page structure; may need browser rendering")

    if weakness_count == 0:
        reasons.append("no clear weak-site indicators")

    if title and links < 3 and images == 0 and forms == 0:
        verdict = "NEEDS_BROWSER_CHECK"
    elif not contact or links < 3:
        verdict = "LOW"
    elif 2 <= weakness_count <= 6:
        verdict = "HIGH"
    elif weakness_count >= 1:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return verdict, weakness_count, reasons or ["candidate has usable contact and visible weaknesses"]

def load_records(path):
    records = []
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
    ap.add_argument("--vertical", required=True)
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    path = Path(args.input_root) / args.project / args.vertical / "sites.jsonl"
    if not path.exists():
        raise SystemExit(f"No knowledge file found: {path}")

    records = load_records(path)[-args.limit:]

    for r in records:
        verdict, weakness_count, reasons = score_record(r)
        print(json.dumps({
            "domain": r.get("domain"),
            "source_url": r.get("source_url"),
            "fit": verdict,
            "weakness_count": weakness_count,
            "reasons": reasons,
        }, ensure_ascii=False))

if __name__ == "__main__":
    main()
