#!/usr/bin/env python3
from pathlib import Path
import sys

# In hlinor-agent-registry, knowledge/ is intentionally ignored:
# .gitignore contains knowledge/
# Therefore this validator must check only tracked policy/context files.
required_files = [
    Path("docs/policies/k16-email-gate-before-acceptance-invariant.md"),
    Path("CLAUDE.md"),
    Path(".claude/CLAUDE.md"),
    Path("reports/k16/policy-assertions/k16_email_gate_before_acceptance_invariant_20260625.md"),
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

if errors:
    print("K16_EMAIL_GATE_INVARIANT_VALIDATION_FAILED")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print("K16_EMAIL_GATE_INVARIANT_VALIDATION_OK")
