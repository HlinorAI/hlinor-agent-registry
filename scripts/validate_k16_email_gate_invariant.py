#!/usr/bin/env python3
from pathlib import Path
import json
import sys

required_files = [
    Path("docs/policies/k16-email-gate-before-acceptance-invariant.md"),
    Path("knowledge/k16/policies/k16-email-gate-before-acceptance-invariant.md"),
    Path("knowledge/k16/policies/k16-email-gate-before-acceptance-invariant.json"),
    Path("CLAUDE.md"),
    Path(".claude/CLAUDE.md"),
]

required_terms = [
    "HARD_INVARIANT",
    "no_email_skipped",
    "verified recipient email",
    "accepted candidate",
    "Visual/website proof",
]

errors = []

for path in required_files:
    if not path.exists():
        errors.append(f"missing required file: {path}")
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    for term in required_terms:
        if term not in text:
            errors.append(f"{path}: missing required term: {term}")

json_path = Path("knowledge/k16/policies/k16-email-gate-before-acceptance-invariant.json")
if json_path.exists():
    data = json.loads(json_path.read_text(encoding="utf-8"))
    hard = data.get("hard_rules", {})
    for key in [
        "email_gate_before_accepted",
        "email_gate_before_materialization",
        "email_gate_before_visual_proof",
        "email_gate_before_preview",
        "email_gate_before_owner_review_packet",
        "email_gate_before_draft",
        "email_gate_before_send_ready",
        "unknown_email_verification_is_not_verified",
        "accepted_candidate_requires_verified_email",
    ]:
        if hard.get(key) is not True:
            errors.append(f"json hard_rules.{key} must be true")

    if hard.get("no_verified_email_status") != "no_email_skipped":
        errors.append("json hard_rules.no_verified_email_status must be no_email_skipped")

if errors:
    print("K16_EMAIL_GATE_INVARIANT_VALIDATION_FAILED")
    for e in errors:
        print(f"- {e}")
    sys.exit(1)

print("K16_EMAIL_GATE_INVARIANT_VALIDATION_OK")
