#!/usr/bin/env python3
"""Refuse to commit internal material into this public repository.

CLAUDE.md scopes the repository to a generic, public agent registry and
governance specification: no private runtime logic, production pipelines,
credentials, real operational data, or business-specific workflow details.

That rule was already violated once. The files were later deleted from the
working tree, but deleting a file does not remove it from a published git
history, and the cleanup cost far exceeded the cost of never committing them.
This hook is the cheap end of that trade.

Usage:
    check_public_scope.py [PATH ...]

Exits non-zero and names the offending path when a staged file is out of scope.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

#: Directories that belong to private tooling, never to the public spec.
BLOCKED_PATH_PREFIXES = (
    "tools/",
    "reports/",
    ".claude/",
    ".codex/",
)

#: Path fragments that name a specific internal programme or pipeline.
BLOCKED_PATH_PATTERNS = (
    re.compile(r"(^|/)k16[-_]", re.IGNORECASE),
    re.compile(r"(^|/)market[-_]intelligence(/|$)", re.IGNORECASE),
    re.compile(r"validate_k16", re.IGNORECASE),
)

#: One-off patch scripts of the "open a source file and splice a string into
#: it" kind. Two of these reached the public repository with an absolute path
#: from a maintainer's laptop baked in.
BLOCKED_FILENAME_PATTERNS = (
    re.compile(r"^fix_.*\.py$"),
    re.compile(r"^add_.*_command\.py$"),
    re.compile(r"^patch_.*\.py$"),
)

#: Content that should never appear in a tracked file regardless of its path.
BLOCKED_CONTENT_PATTERNS = (
    (
        re.compile(r"/Users/[^/\s\"']+/"),
        "absolute path from a local machine",
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "private key material",
    ),
)

#: Files whose job is to describe the incident and the rules themselves.
ALLOWED_EXCEPTIONS = {
    "AUDIT.md",
    "CLAUDE.md",
    "scripts/check_public_scope.py",
    "docs/internal/h2-history-cleanup-runbook.md",
    "docs/internal/h2-cleanup.sh",
}

TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".sh",
    ".txt",
    ".cfg",
    ".ini",
    ".html",
}


def path_violations(relative_path: str) -> list[str]:
    problems = []
    if relative_path.startswith(BLOCKED_PATH_PREFIXES):
        problems.append("path is reserved for internal tooling")
    for pattern in BLOCKED_PATH_PATTERNS:
        if pattern.search(relative_path):
            problems.append(f"path names an internal programme ({pattern.pattern})")
    name = Path(relative_path).name
    for pattern in BLOCKED_FILENAME_PATTERNS:
        if pattern.match(name):
            problems.append("looks like a one-off patch script")
    return problems


def content_violations(path: Path) -> list[str]:
    if path.suffix not in TEXT_SUFFIXES:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    return [
        description
        for pattern, description in BLOCKED_CONTENT_PATTERNS
        if pattern.search(text)
    ]


def main(argv: list[str]) -> int:
    failures: list[tuple[str, list[str]]] = []

    for argument in argv:
        path = Path(argument)
        relative_path = path.as_posix()
        if relative_path in ALLOWED_EXCEPTIONS:
            continue

        problems = path_violations(relative_path)
        if path.is_file():
            problems.extend(content_violations(path))
        if problems:
            failures.append((relative_path, problems))

    if not failures:
        return 0

    print("Refusing to commit: this is a public repository.", file=sys.stderr)
    print(file=sys.stderr)
    for relative_path, problems in failures:
        print(f"  {relative_path}", file=sys.stderr)
        for problem in problems:
            print(f"      - {problem}", file=sys.stderr)
    print(file=sys.stderr)
    print(
        "See the scope rule in CLAUDE.md. Deleting a file later does not remove\n"
        "it from a published history; see docs/internal/"
        "h2-history-cleanup-runbook.md\n"
        "for what that cleanup actually costs.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
