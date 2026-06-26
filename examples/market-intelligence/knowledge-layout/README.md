# Market Intelligence Knowledge Layout Example

This is an example layout only. It contains no live production data.

Suggested future structure:

```text
knowledge/
  <project_id>/
    <vertical>/
      sites.jsonl
      screenshots/
      benchmarks.md
      weak-patterns.md
      repair-patterns.md
      provenance-ledger.jsonl
```

Example verticals:

```text
knowledge/
  k16/
    roofing/
    hvac/
    dentistry/
    landscaping/
    pest-control/
  example-project/
    vertical-retailers/
    parts-distributors/
    accessory-manufacturers/
```

Each future record should include project_id, vertical, domain, source_url, captured_at, freshness_at, dedupe_key, confidence, provenance, and notes.
