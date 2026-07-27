"""Tests for typed policy handlers.

These are the specification for what a policy can establish. Each handler
verifies something the caller can get wrong by accident; none of them verifies
that the caller is telling the truth. Where a test asserts a refusal, it is
worth reading what the refusal protects against, because the value of the whole
layer is in those specific cases and not in the general idea.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from hlinor_registry import ActionRequest
from hlinor_registry.enums import ReasonCode
from hlinor_registry.policies import (
    POLICY_KINDS,
    PolicyRule,
    load_policy_rules,
    policy_definition_errors,
)

NOW = datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc)


def approval_rule(**requires: object) -> PolicyRule:
    spec = {"approver_role": "security-lead", **requires}
    return PolicyRule(
        policy_id="needs-approval",
        kind="requires_approval",
        trigger=("send:email:external:*",),
        spec=spec,
    )


def request_with(**signals: object) -> ActionRequest:
    return ActionRequest(
        agent_id="mailer",
        action="send",
        resource="email:external:someone@example.invalid",
        signals=signals,
    )


class TestTriggerMatching:
    def test_a_policy_applies_only_to_the_keys_its_trigger_covers(self):
        rule = approval_rule()
        assert rule.applies_to("send:email:external:someone")
        assert not rule.applies_to("send:email:internal:someone")
        assert not rule.applies_to("read:report:q1")


class TestApproval:
    def test_a_missing_signal_is_reported_as_missing_not_as_a_failed_check(self):
        """ "Nobody reported this" and "this was reported and fails" differ.

        The first is usually a wiring bug in the adapter; the second is the
        control working. Collapsing them into one reason code makes a
        misconfigured deployment look like a policy doing its job.
        """
        outcome = approval_rule().check(request_with(), now=NOW)
        assert not outcome.satisfied
        assert outcome.reason_code is ReasonCode.POLICY_SIGNAL_MISSING

    def test_the_approver_role_must_match(self):
        outcome = approval_rule().check(
            request_with(
                approval={
                    "approver_role": "intern",
                    "granted_for": "send:email:external:*",
                }
            ),
            now=NOW,
        )
        assert not outcome.satisfied
        assert outcome.reason_code is ReasonCode.APPROVAL_REQUIRED
        assert "security-lead" in outcome.detail

    def test_an_approval_cannot_be_replayed_onto_a_different_request(self):
        """The check with the most practical value in this handler.

        An approval legitimately obtained for one action is otherwise a token
        that unlocks every other action the agent is permitted to attempt.
        """
        outcome = approval_rule().check(
            request_with(
                approval={
                    "approver_role": "security-lead",
                    "granted_for": "send:email:internal:*",
                }
            ),
            now=NOW,
        )
        assert not outcome.satisfied
        assert outcome.reason_code is ReasonCode.APPROVAL_REQUIRED
        assert "not" in outcome.detail

    def test_an_approval_may_be_granted_for_a_scope(self):
        """granted_for is a pattern, so an approver can permit a set at once."""
        outcome = approval_rule().check(
            request_with(
                approval={
                    "approver_role": "security-lead",
                    "granted_for": "send:email:external:*",
                }
            ),
            now=NOW,
        )
        assert outcome.satisfied

    def test_binding_can_be_switched_off_but_is_on_by_default(self):
        unbound = approval_rule(bind_to_request=False).check(
            request_with(approval={"approver_role": "security-lead"}), now=NOW
        )
        assert unbound.satisfied

        bound = approval_rule().check(
            request_with(approval={"approver_role": "security-lead"}), now=NOW
        )
        assert not bound.satisfied

    def test_a_stale_approval_is_refused(self):
        rule = approval_rule(max_age_seconds=900)
        outcome = rule.check(
            request_with(
                approval={
                    "approver_role": "security-lead",
                    "granted_for": "send:email:external:*",
                    "granted_at": (NOW - timedelta(hours=2)).isoformat(),
                }
            ),
            now=NOW,
        )
        assert not outcome.satisfied
        assert "old" in outcome.detail

    @pytest.mark.parametrize(
        "granted_at",
        [
            "2026-07-27T11:55:00Z",
            "2026-07-27T11:55:00+00:00",
            "2026-07-27T13:55:00+02:00",
        ],
    )
    def test_timestamps_parse_the_same_on_every_supported_interpreter(self, granted_at):
        """datetime.fromisoformat did not accept 'Z' before Python 3.11.

        This package supports 3.10, so a policy that read a 'Z' timestamp
        would refuse every request on 3.10 and accept them on 3.12 -- one
        signed bundle deciding differently per interpreter, the same class of
        defect fnmatchcase avoids in the matcher. The offset form is included
        so the three spellings of one instant are known to agree.
        """
        rule = approval_rule(max_age_seconds=900)
        outcome = rule.check(
            request_with(
                approval={
                    "approver_role": "security-lead",
                    "granted_for": "send:email:external:*",
                    "granted_at": granted_at,
                }
            ),
            now=NOW,
        )
        assert outcome.satisfied, outcome.detail

    def test_a_naive_timestamp_is_refused_rather_than_assumed_to_be_utc(self):
        """Guessing an offset silently shifts the window by hours."""
        rule = approval_rule(max_age_seconds=900)
        outcome = rule.check(
            request_with(
                approval={
                    "approver_role": "security-lead",
                    "granted_for": "send:email:external:*",
                    "granted_at": "2026-07-27T11:55:00",
                }
            ),
            now=NOW,
        )
        assert not outcome.satisfied
        assert "timezone-aware" in outcome.detail


def evidence_rule(**requires: object) -> PolicyRule:
    spec = {"evidence_types": ["source_document"], **requires}
    return PolicyRule(
        policy_id="needs-evidence",
        kind="requires_evidence",
        trigger=("publish:*",),
        spec=spec,
    )


def publish_request(*claims: object) -> ActionRequest:
    return ActionRequest(
        agent_id="writer",
        action="publish",
        resource="report:q1",
        signals={"evidence": list(claims)},
    )


class TestEvidence:
    def test_each_required_type_must_be_present(self):
        outcome = evidence_rule().check(
            publish_request({"type": "screenshot", "resource": "report:q1"}), now=NOW
        )
        assert not outcome.satisfied
        assert outcome.reason_code is ReasonCode.EVIDENCE_REQUIRED
        assert "source_document" in outcome.detail

    def test_evidence_about_another_resource_does_not_count(self):
        """The schema's same_object_verified flag is a claim about itself.

        A claim that asserts its own correctness establishes nothing, so the
        comparison is computed here instead of trusted.
        """
        outcome = evidence_rule().check(
            publish_request({"type": "source_document", "resource": "report:q4"}),
            now=NOW,
        )
        assert not outcome.satisfied
        assert "different resource" in outcome.detail

    def test_a_self_declared_fresh_flag_does_not_substitute_for_a_timestamp(self):
        outcome = evidence_rule(max_age_seconds=3600).check(
            publish_request(
                {
                    "type": "source_document",
                    "resource": "report:q1",
                    "freshness_status": "fresh",
                    "same_object_verified": True,
                }
            ),
            now=NOW,
        )
        assert not outcome.satisfied
        assert "observed_at" in outcome.detail

    def test_stale_evidence_is_refused(self):
        outcome = evidence_rule(max_age_seconds=3600).check(
            publish_request(
                {
                    "type": "source_document",
                    "resource": "report:q1",
                    "observed_at": (NOW - timedelta(days=1)).isoformat(),
                }
            ),
            now=NOW,
        )
        assert not outcome.satisfied

    def test_one_fresh_matching_claim_is_enough(self):
        outcome = evidence_rule(max_age_seconds=3600).check(
            publish_request(
                {"type": "source_document", "resource": "report:q4"},
                {
                    "type": "source_document",
                    "resource": "report:q1",
                    "observed_at": (NOW - timedelta(minutes=5)).isoformat(),
                },
            ),
            now=NOW,
        )
        assert outcome.satisfied


def breaker_rule(**threshold: object) -> PolicyRule:
    spec = {"counter": "payment-api", "max_consecutive_failures": 3, **threshold}
    return PolicyRule(
        policy_id="payment-breaker",
        kind="failure_threshold",
        trigger=("call:payment-api:*",),
        spec=spec,
    )


def call_request(counts: object) -> ActionRequest:
    return ActionRequest(
        agent_id="biller",
        action="call",
        resource="payment-api:charge",
        signals={"failure_counts": counts},
    )


class TestFailureThreshold:
    def test_below_the_threshold_passes(self):
        assert breaker_rule().check(call_request({"payment-api": 2}), now=NOW).satisfied

    def test_at_the_threshold_stops(self):
        outcome = breaker_rule().check(call_request({"payment-api": 3}), now=NOW)
        assert not outcome.satisfied
        assert outcome.reason_code is ReasonCode.FAILURE_THRESHOLD_REACHED

    def test_an_unreported_counter_fails_closed(self):
        """A breaker that assumes zero when unreported never opens.

        Defaulting to zero would make the control disappear the moment an
        adapter forgets to wire the counter, which is exactly when it is
        needed and exactly when nobody is looking.
        """
        outcome = breaker_rule().check(call_request({}), now=NOW)
        assert not outcome.satisfied
        assert outcome.reason_code is ReasonCode.POLICY_SIGNAL_MISSING

    @pytest.mark.parametrize("reported", ["3", True, -1, None, 2.5])
    def test_a_non_integer_count_is_not_guessed_at(self, reported):
        outcome = breaker_rule().check(call_request({"payment-api": reported}), now=NOW)
        assert not outcome.satisfied
        assert outcome.reason_code is ReasonCode.POLICY_SIGNAL_MISSING

    def test_counters_are_independent(self):
        assert (
            breaker_rule()
            .check(call_request({"other-api": 99, "payment-api": 0}), now=NOW)
            .satisfied
        )


class TestDefinitionValidation:
    def test_a_policy_without_a_kind_stays_valid_prose(self):
        assert policy_definition_errors({"id": "x", "enforcement": "by review"}) == []

    def test_an_unknown_kind_is_refused_rather_than_ignored(self):
        """A silently skipped policy reads, in the registry, like a live one."""
        errors = policy_definition_errors({"kind": "requires_aproval"})
        assert errors
        assert "Unsupported kind" in errors[0]
        for kind in POLICY_KINDS:
            assert kind in errors[0]

    def test_a_trigger_is_required_and_must_use_the_supported_syntax(self):
        assert any(
            "trigger" in error
            for error in policy_definition_errors({"kind": "requires_approval"})
        )
        errors = policy_definition_errors(
            {"kind": "requires_approval", "trigger": ["send:**:external"]}
        )
        assert any("recursive wildcards" in error for error in errors)

    def test_each_kind_declares_the_fields_it_cannot_work_without(self):
        errors = policy_definition_errors(
            {"kind": "failure_threshold", "trigger": ["call:*"], "threshold": {}}
        )
        assert any("threshold.counter" in error for error in errors)
        assert any("threshold.max_consecutive_failures" in error for error in errors)

    @pytest.mark.parametrize("bad_age", [0, -5, "900", True])
    def test_a_freshness_window_must_be_a_positive_number(self, bad_age):
        errors = policy_definition_errors(
            {
                "kind": "requires_approval",
                "trigger": ["send:*"],
                "requires": {"max_age_seconds": bad_age},
            }
        )
        assert any("max_age_seconds" in error for error in errors)


class TestLoadPolicyRules:
    def test_prose_policies_produce_no_rule(self):
        rules = load_policy_rules(
            {"documented": {"config": {"id": "documented", "enforcement": "by review"}}}
        )
        assert rules == {}

    def test_a_typed_policy_becomes_a_rule(self):
        rules = load_policy_rules(
            {
                "gate": {
                    "config": {
                        "id": "gate",
                        "kind": "requires_approval",
                        "trigger": ["send:*"],
                        "requires": {"approver_role": "lead"},
                    }
                }
            }
        )
        assert rules["gate"].kind == "requires_approval"
        assert rules["gate"].trigger == ("send:*",)
        assert rules["gate"].spec["approver_role"] == "lead"

    def test_malformed_entries_are_skipped_rather_than_raising(self):
        """Bundle shape is checked at load; a rule builder must not throw."""
        assert load_policy_rules(None) == {}
        assert load_policy_rules({"a": None, "b": {"config": None}}) == {}
