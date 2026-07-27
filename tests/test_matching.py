"""Tests for the action pattern syntax.

The pattern language is deliberately tiny, and its value is that a reader can
predict what it does. These tests are the specification: if a case here is
surprising, the syntax is wrong, not the test.
"""

from __future__ import annotations

import pytest

from hlinor_registry._matching import (
    find_match,
    is_pattern,
    matches,
    overlapping_allow_patterns,
    pattern_errors,
    patterns_can_overlap,
    request_key,
)


class TestRequestKey:
    def test_no_resource_yields_the_bare_action(self):
        """Agents written before resources existed must match as they did."""
        assert request_key("read") == "read"
        assert request_key("read", None) == "read"

    def test_blank_resource_is_treated_as_absent(self):
        """An empty string is a caller mistake, not a resource named ''."""
        assert request_key("read", "") == "read"
        assert request_key("read", "   ") == "read"

    def test_resource_is_appended_after_a_colon(self):
        assert request_key("read", "report:quarterly") == "read:report:quarterly"


class TestBackwardCompatibility:
    """A pattern with no wildcard is an exact match, and nothing more."""

    def test_bare_name_matches_itself(self):
        assert matches("read", "read")

    def test_bare_name_does_not_match_a_scoped_request(self):
        """Otherwise every existing allow list would silently widen."""
        assert not matches("read", "read:report:quarterly")

    def test_bare_name_does_not_match_a_longer_name(self):
        assert not matches("read", "read_all")
        assert not matches("read", "reader")


class TestWildcards:
    def test_star_matches_a_trailing_segment(self):
        assert matches("read:report:*", "read:report:quarterly")

    def test_star_crosses_the_separator(self):
        """The sharpest edge in the syntax, asserted so nobody rediscovers it.

        There is no '**', so '*' spans everything including ':'. A pattern that
        looks scoped to one level is not.
        """
        assert matches("send:email:*", "send:email:external:someone@example.invalid")
        assert matches("read:*", "read:report:quarterly/q1/appendix")

    def test_question_mark_matches_exactly_one_character(self):
        assert matches("read:q?", "read:q1")
        assert not matches("read:q?", "read:q12")

    def test_star_matches_empty(self):
        assert matches("read:report:*", "read:report:")


class TestCaseHandling:
    def test_exact_matching_is_case_sensitive(self):
        assert not matches("read:Report", "read:report")

    def test_ignore_case_matches_either_way(self):
        assert matches("read:Report", "read:report", ignore_case=True)
        assert matches("read:report", "read:REPORT", ignore_case=True)

    def test_case_behaviour_does_not_depend_on_the_platform(self):
        """fnmatch normalises case per OS; fnmatchcase does not.

        Using fnmatch here would make one signed bundle produce different
        decisions on Linux and Windows, which is the opposite of what a signed
        artifact is for.
        """
        import hlinor_registry._matching as matching_module

        source = matching_module.__file__
        with open(source, encoding="utf-8") as stream:
            text = stream.read()

        assert "fnmatchcase" in text
        assert "from fnmatch import fnmatchcase" in text
        # The case-normalising entry point must not be imported at all.
        assert "import fnmatch\n" not in text


class TestFindMatch:
    def test_returns_the_matching_pattern_for_provenance(self):
        """A decision should be able to say what matched, not just that it did."""
        patterns = ["read:report:*", "classify:ticket:*"]
        assert find_match(patterns, "classify:ticket:99") == "classify:ticket:*"

    def test_returns_none_when_nothing_matches(self):
        assert find_match(["read:*"], "send:email") is None

    def test_first_match_wins(self):
        patterns = ["read:*", "read:report:*"]
        assert find_match(patterns, "read:report:q1") == "read:*"

    def test_non_string_entries_are_skipped_not_raised(self):
        """Bundle shape is checked at load; a matcher must not throw mid-decision."""
        assert find_match([None, 42, "read:*"], "read:x") == "read:*"

    def test_non_list_input_matches_nothing(self):
        assert find_match(None, "read") is None
        assert find_match("read", "read") is None


class TestPatternValidation:
    @pytest.mark.parametrize(
        "pattern",
        ["read", "read:report:*", "send:email:internal:*", "read:q?", "*"],
    )
    def test_supported_patterns_are_accepted(self, pattern):
        assert pattern_errors(pattern) == []

    @pytest.mark.parametrize(
        ("pattern", "fragment"),
        [
            ("read:**:secret", "recursive wildcards"),
            ("read:[abc]", "character classes"),
            ("read:!secret", "negation"),
            ("read:{a,b}", "alternation"),
        ],
    )
    def test_unsupported_syntax_is_reported_with_a_reason(self, pattern, fragment):
        """Rejecting is not enough; the message has to say what to use instead."""
        errors = pattern_errors(pattern)
        assert errors, f"{pattern} was accepted"
        assert any(fragment in error for error in errors)

    def test_whitespace_and_emptiness_are_rejected(self):
        assert pattern_errors(" read") != []
        assert pattern_errors("") != []
        assert pattern_errors("   ") != []


class TestIsPattern:
    def test_distinguishes_a_wildcard_from_a_name(self):
        assert is_pattern("read:*")
        assert is_pattern("read:q?")
        assert not is_pattern("read")
        assert not is_pattern("read:report:quarterly")


class TestPatternOverlap:
    """`patterns_can_overlap` decides whether some key matches both patterns.

    The linter is built on it, and a linter that misses cases is worse than
    no linter: it teaches people that silence means safety.
    """

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            ("send:email:*", "send:email:external:*"),
            ("read:report:*", "read:report:secret*"),
            ("*", "anything:at:all"),
            ("read:q?", "read:q1"),
            ("a*b", "*c*"),
        ],
    )
    def test_overlapping_patterns_are_detected(self, left, right):
        assert patterns_can_overlap(left, right)
        assert patterns_can_overlap(right, left), "must not depend on argument order"

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            ("read:report:*", "delete:report:*"),
            ("read:public:*", "read:secret:*"),
            ("read", "write"),
            ("read:q?", "read:q12"),
            ("a*", "b*"),
        ],
    )
    def test_disjoint_patterns_are_not_flagged(self, left, right):
        assert not patterns_can_overlap(left, right)
        assert not patterns_can_overlap(right, left)

    def test_overlap_is_not_a_prefix_test(self):
        """The case that motivated deciding this exactly.

        Neither pattern string starts with the other's literal prefix, and a
        prefix comparison calls them unrelated. They both match
        'read:queue/support/credentials/id_rsa'.
        """
        allow = "read:queue/support/*"
        block = "read:*credentials/*"
        assert not block.startswith(allow.rstrip("*"))
        assert patterns_can_overlap(allow, block)

        witness = "read:queue/support/credentials/id_rsa"
        assert matches(allow, witness)
        assert matches(block, witness)

    def test_agrees_with_brute_force_on_every_short_pattern_pair(self):
        """No claim without an example, and no silence without a proof.

        Every pattern of up to three symbols over one literal, the separator,
        and both wildcards is checked against every other, in both directions,
        against an exhaustive search for a key that matches both. Two literals
        would add nothing: 'a' against ':' already exercises the mismatch.
        Keys run to twice the pattern length, which is past the longest
        witness any of these pairs can need.
        """
        import itertools
        from fnmatch import fnmatchcase

        patterns = [
            "".join(candidate)
            for length in (1, 2, 3)
            for candidate in itertools.product("a:*?", repeat=length)
        ]
        keys = [
            "".join(candidate)
            for length in range(7)
            for candidate in itertools.product("a:", repeat=length)
        ]

        for left in patterns:
            for right in patterns:
                witness = next(
                    (k for k in keys if fnmatchcase(k, left) and fnmatchcase(k, right)),
                    None,
                )
                assert patterns_can_overlap(left, right) == (witness is not None), (
                    f"{left!r} vs {right!r} (witness={witness!r})"
                )


class TestOverlappingAllowPatterns:
    def test_reports_the_pair_so_the_message_can_name_both(self):
        findings = overlapping_allow_patterns(
            ["send:email:*"], ["send:email:external:*"]
        )
        assert findings == [("send:email:*", "send:email:external:*")]

    def test_a_literal_allow_entry_is_never_reported(self):
        """A name without a wildcard grants exactly itself; nothing to warn about."""
        assert overlapping_allow_patterns(["send_email"], ["send_email_external"]) == []

    def test_an_identical_entry_on_both_lists_is_left_to_the_duplicate_check(self):
        assert overlapping_allow_patterns(["read:*"], ["read:*"]) == []

    def test_non_string_entries_do_not_raise(self):
        assert overlapping_allow_patterns([None, "read:*"], [42, "read:secret:*"]) == [
            ("read:*", "read:secret:*")
        ]
