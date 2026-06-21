#!/usr/bin/env python3
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def normalize_domain(url):
    parsed = urlparse(url if "://" in url else "https://" + url)
    return parsed.netloc.lower().removeprefix("www.")

def fetch_html(url, timeout=15):
    if "://" not in url:
        url = "https://" + url
    req = Request(url, headers={"User-Agent": "Hlinor-Market-Intelligence-DryRun/0.1"})
    with urlopen(req, timeout=timeout) as r:
        return r.read(750000).decode("utf-8", errors="replace"), r.geturl()

def extract_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""

def extract_meta_description(html):
    m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""

def extract_ctas(html):
    texts = re.findall(r">(Get Quote|Free Estimate|Contact Us|Book Now|Call Now|Schedule|Request|Shop Now|Buy Now|Learn More)<", html, re.I)
    seen = []
    for t in texts:
        clean = t.strip()
        if clean.lower() not in [x.lower() for x in seen]:
            seen.append(clean)
    return seen[:10]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--vertical", required=True)
    ap.add_argument("--dry-run", action="store_true", default=False)
    args = ap.parse_args()

    html, final_url = fetch_html(args.url)
    domain = normalize_domain(final_url)
    ts = now_iso()

    record = {
        "project_id": args.project,
        "vertical": args.vertical,
        "domain": domain,
        "source_url": final_url,
        "captured_at": ts,
        "freshness_at": ts,
        "dedupe_key": f"domain:{domain}",
        "confidence": "medium",
        "provenance": "single-url live HTML snapshot",
        "title": extract_title(html),
        "meta_description": extract_meta_description(html),
        "cta_candidates": extract_ctas(html),
        "html_bytes_sampled": len(html.encode("utf-8", errors="replace")),
        "dry_run": bool(args.dry_run),
    }

    print(json.dumps(record, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
