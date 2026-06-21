#!/usr/bin/env python3
import argparse, json, re, sys
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urlparse
from urllib.request import Request, urlopen

CTA_WORDS = r"Get Quote|Free Estimate|Contact Us|Book Now|Call Now|Schedule|Request|Shop Now|Buy Now|Learn More|Order Now|Start Now"

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def clean(s):
    return re.sub(r"\s+", " ", unescape(s or "")).strip()

def strip_tags(s):
    return clean(re.sub(r"<[^>]+>", " ", s or ""))

def normalize_domain(url):
    p = urlparse(url if "://" in url else "https://" + url)
    return p.netloc.lower().removeprefix("www.")

def fetch_html(url, timeout=15):
    if "://" not in url:
        url = "https://" + url
    req = Request(url, headers={"User-Agent": "Hlinor-Market-Intelligence/0.2"})
    with urlopen(req, timeout=timeout) as r:
        raw = r.read(1000000)
        return raw.decode("utf-8", errors="replace"), r.geturl(), dict(r.headers)

def first_match(pattern, html):
    m = re.search(pattern, html, re.I | re.S)
    return clean(m.group(1)) if m else ""

def all_text(pattern, html, limit=20):
    vals = [strip_tags(x) for x in re.findall(pattern, html, re.I | re.S)]
    out = []
    for v in vals:
        if v and v.lower() not in [x.lower() for x in out]:
            out.append(v)
    return out[:limit]

def has(pattern, html):
    return bool(re.search(pattern, html, re.I | re.S))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--vertical", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    html, final_url, headers = fetch_html(args.url)
    domain = normalize_domain(final_url)
    ts = now_iso()

    visible_text = strip_tags(re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.I | re.S))

    phones = re.findall(r"(\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})", visible_text)
    emails = re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", visible_text, re.I)

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
        "dry_run": bool(args.dry_run),

        "page": {
            "title": first_match(r"<title[^>]*>(.*?)</title>", html),
            "meta_description": first_match(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', html),
            "h1": all_text(r"<h1[^>]*>(.*?)</h1>", html, 5),
            "h2": all_text(r"<h2[^>]*>(.*?)</h2>", html, 10),
            "html_bytes_sampled": len(html.encode("utf-8", errors="replace")),
        },

        "structure_signals": {
            "nav_items": all_text(r"<nav[^>]*>(.*?)</nav>", html, 3),
            "links_count": len(re.findall(r"<a\b", html, re.I)),
            "images_count": len(re.findall(r"<img\b", html, re.I)),
            "forms_count": len(re.findall(r"<form\b", html, re.I)),
            "buttons_count": len(re.findall(r"<button\b", html, re.I)),
        },

        "conversion_signals": {
            "cta_candidates": all_text(r">(" + CTA_WORDS + r")<", html, 20),
            "phone_visible": bool(phones),
            "email_visible": bool(emails),
            "phones_found": sorted(set(clean(x) for x in phones))[:5],
            "emails_found": sorted(set(emails))[:5],
            "contact_form_present": has(r"<form\b|contact-form|wpforms|gravityform|forminator", html),
            "booking_or_schedule_present": has(r"book now|schedule|appointment|calendly|acuity|booking", visible_text),
        },

        "trust_signals": {
            "reviews_or_testimonials_present": has(r"review|reviews|testimonial|testimonials|stars?|rating", visible_text),
            "license_or_certification_present": has(r"licensed|insured|certified|certification|bonded|accredited", visible_text),
            "gallery_or_portfolio_present": has(r"gallery|portfolio|our work|projects|before.?after", visible_text),
            "social_links_present": has(r"facebook\.com|instagram\.com|linkedin\.com|youtube\.com|tiktok\.com", html),
            "schema_org_present": has(r"schema\.org|application/ld\+json", html),
        },

        "ux_technical_signals": {
            "viewport_meta_present": has(r'<meta[^>]+name=["\']viewport["\']', html),
            "alt_attributes_count": len(re.findall(r"<img[^>]+alt=", html, re.I)),
            "empty_alt_count": len(re.findall(r'<img[^>]+alt=["\']\s*["\']', html, re.I)),
            "inline_style_count": len(re.findall(r"\sstyle=", html, re.I)),
            "external_css_count": len(re.findall(r'<link[^>]+stylesheet', html, re.I)),
            "script_count": len(re.findall(r"<script\b", html, re.I)),
        },

        "weak_site_indicators_raw": {
            "missing_meta_description": not bool(first_match(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', html)),
            "missing_h1": not bool(all_text(r"<h1[^>]*>(.*?)</h1>", html, 1)),
            "no_visible_phone": not bool(phones),
            "no_visible_email": not bool(emails),
            "no_contact_form_detected": not has(r"<form\b|contact-form|wpforms|gravityform|forminator", html),
            "no_reviews_detected": not has(r"review|reviews|testimonial|testimonials|stars?|rating", visible_text),
            "no_viewport_meta": not has(r'<meta[^>]+name=["\']viewport["\']', html),
        }
    }

    print(json.dumps(record, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
