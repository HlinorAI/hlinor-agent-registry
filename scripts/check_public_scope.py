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

#: Optional, one pattern per line, regular expressions matched against the
#: path. Project-specific programme names belong here rather than in this file:
#: a public denylist that spells out what you are hiding defeats itself. The
#: file is gitignored, so add it on each machine and in CI as a secret if the
#: names themselves are sensitive.
DENYLIST_FILE = ".public-scope-denylist"

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
    (
        # This repository is read by people who do not share the maintainers'
        # first language. Working notes written in another script tend to be
        # the ones that were never meant to be published in the first place,
        # so the rule doubles as a scope check.
        re.compile(r"[\u0400-\u04FF]"),
        "non-Latin script; this repository is English-only",
    ),
)

#: This file states the rules, so it necessarily contains examples of them.
ALLOWED_EXCEPTIONS = {
    "scripts/check_public_scope.py",
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


def load_denylist() -> list[re.Pattern[str]]:
    """Load optional local path patterns.

    Absent by default. A missing or unreadable file is not an error: the
    directory rules above already cover the common cases, and this exists so a
    deployment can add names it does not want written down in a public file.
    """
    try:
        lines = Path(DENYLIST_FILE).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    patterns = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            patterns.append(re.compile(line, re.IGNORECASE))
        except re.error:
            print(
                f"Ignoring invalid pattern in {DENYLIST_FILE}: {line}", file=sys.stderr
            )
    return patterns


def path_violations(relative_path: str, denylist: list[re.Pattern[str]]) -> list[str]:
    problems = []
    if relative_path.startswith(BLOCKED_PATH_PREFIXES):
        problems.append("path is reserved for internal tooling")
    for pattern in denylist:
        if pattern.search(relative_path):
            problems.append("path matches a locally configured denylist entry")
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
    denylist = load_denylist()

    for argument in argv:
        path = Path(argument)
        relative_path = path.as_posix()
        if relative_path in ALLOWED_EXCEPTIONS:
            continue

        problems = path_violations(relative_path, denylist)
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
        "it from a published history, and rewriting that history is expensive:\n"
        "tags, releases and pull request refs all keep the old objects alive.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
