"""Matching an action request against the patterns an agent declares.

An action list entry is a glob over a colon-separated key. The key is the
action alone when a request names no resource, and ``action:resource`` when it
does:

    read                            matches action "read" with no resource
    read:report:quarterly/*         matches action "read" on those reports
    send:email:external:*           matches any external email send

Deliberately small. ``*`` and ``?`` are the whole vocabulary. There is no
``**``, no character class, no alternation, no regular expression, and no
negation. The point of this layer is that a decision stays something a
non-engineer can verify by reading the YAML; anything that needs a condition
belongs in a policy object, not in a pattern.

``*`` crosses ``:``. ``send:email:*`` therefore matches
``send:email:external:someone`` as well as ``send:email:internal:someone``.
That is the single sharpest edge here: a broad allow pattern grants more than
its shape suggests, and the block list is what narrows it. The linter warns
when an allow pattern is broader than a block pattern beside it.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

#: Separates the action from the resource, and resource segments from each
#: other. Chosen because it does not appear in the action names this project
#: has used, and because it reads as a scope rather than a path.
SEGMENT_SEPARATOR = ":"

#: Everything the pattern syntax accepts. Anything else in a pattern is a
#: mistake worth reporting rather than a construct worth guessing at.
WILDCARD_CHARACTERS = ("*", "?")

#: Rejected outright. Each of these means something in fnmatch or in a regular
#: expression, and accepting any of them starts the slide toward a policy
#: language this layer exists to avoid.
UNSUPPORTED_PATTERN_TOKENS = {
    "**": "recursive wildcards; '*' already crosses ':'",
    "[": "character classes",
    "]": "character classes",
    "!": "negation; use blocked_actions instead",
    "{": "alternation",
    "}": "alternation",
}


def request_key(action: str, resource: str | None = None) -> str:
    """Build the string an action list is matched against.

    Without a resource the key is the action, so an agent written before
    resources existed keeps matching exactly as it did.
    """
    if resource is None or not resource.strip():
        return action
    return f"{action}{SEGMENT_SEPARATOR}{resource}"


def pattern_errors(pattern: str) -> list[str]:
    """Return why a pattern is not accepted, or an empty list."""
    errors = []
    for token, meaning in UNSUPPORTED_PATTERN_TOKENS.items():
        if token in pattern:
            errors.append(f"unsupported {meaning}: {token!r}")
    if pattern.strip() != pattern:
        errors.append("surrounding whitespace")
    if not pattern.strip():
        errors.append("empty pattern")
    return errors


def is_pattern(value: str) -> bool:
    """True when the entry uses a wildcard rather than naming one action."""
    return any(character in value for character in WILDCARD_CHARACTERS)


def matches(pattern: str, key: str, *, ignore_case: bool = False) -> bool:
    """Test one pattern against one request key.

    Uses ``fnmatchcase`` rather than ``fnmatch``. ``fnmatch`` runs both sides
    through ``os.path.normcase``, which lowercases on Windows, so the same
    signed bundle would produce different decisions on different operating
    systems. Case handling is done here instead, where it is visible.
    """
    if ignore_case:
        return fnmatchcase(key.casefold(), pattern.casefold())
    return fnmatchcase(key, pattern)


def patterns_can_overlap(left: str, right: str) -> bool:
    """True when some request key would match both patterns.

    Decided exactly rather than approximated. A prefix test looks like it would
    do -- ``send:email:*`` against ``send:email:external:*`` is caught by one --
    but it misses ``read:queue/support/*`` against ``read:*credentials/*``,
    where the shared keys are described by neither pattern string. A linter
    that misses cases teaches people to trust it, which is worse than no
    linter.

    Because the vocabulary is only ``*`` and ``?``, walking both patterns
    together is complete: at each position either the characters must agree, or
    a ``*`` absorbs one character from the other side.
    """
    cache: dict[tuple[int, int], bool] = {}

    def walk(i: int, j: int) -> bool:
        key = (i, j)
        cached = cache.get(key)
        if cached is not None:
            return cached

        if i == len(left):
            # Only stars can still match the empty remainder.
            result = all(character == "*" for character in right[j:])
        elif j == len(right):
            result = all(character == "*" for character in left[i:])
        elif left[i] == "*":
            # The star matches nothing, or absorbs whatever right[j] produces.
            result = walk(i + 1, j) or walk(i, j + 1)
        elif right[j] == "*":
            result = walk(i, j + 1) or walk(i + 1, j)
        elif left[i] == "?" or right[j] == "?":
            # Some character satisfies both single-character positions.
            result = walk(i + 1, j + 1)
        else:
            result = left[i] == right[j] and walk(i + 1, j + 1)

        cache[key] = result
        return result

    return walk(0, 0)


def overlapping_allow_patterns(
    allowed: list[str],
    blocked: list[str],
) -> list[tuple[str, str]]:
    """Find allow patterns whose reach is narrowed only by the block list.

    ``*`` crosses ``:``, so ``send:email:*`` already covers
    ``send:email:external:someone``. When the block list also carries
    ``send:email:external:*``, the author has told us what they meant: the
    allow pattern is broader than their intent, and the only thing standing
    between the agent and an external send is one entry in a second list.

    That is a legitimate way to write a policy and the runtime honours it --
    blocked always wins. It is worth saying out loud anyway, because deleting
    a line from ``blocked_actions`` then silently widens what is permitted,
    and the allow list gives no hint that it would.

    Identical entries on both lists are skipped: that already has its own
    warning, and saying one fact twice trains people to skim the output.

    Returns (allow_pattern, block_pattern) pairs.
    """
    findings: list[tuple[str, str]] = []
    for allow in allowed:
        if not isinstance(allow, str) or not is_pattern(allow):
            continue
        for block in blocked:
            if not isinstance(block, str) or block == allow:
                continue
            if patterns_can_overlap(allow, block):
                findings.append((allow, block))
    return findings


def find_match(
    patterns: object,
    key: str,
    *,
    ignore_case: bool = False,
) -> str | None:
    """Return the first pattern matching the key, or None.

    The pattern itself is returned rather than a boolean because a decision
    should be able to say what matched. "Denied by ``send:email:external:*``"
    is reviewable; "denied" is not.

    Non-string entries are skipped rather than raising: bundle shape is checked
    at load time, and a matcher that throws mid-evaluation would turn a denial
    into an exception.
    """
    if not isinstance(patterns, (list, tuple)):
        return None
    for pattern in patterns:
        if isinstance(pattern, str) and matches(pattern, key, ignore_case=ignore_case):
            return pattern
    return None
