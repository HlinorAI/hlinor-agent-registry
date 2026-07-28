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
        assert "does not name resource" in outcome.detail

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

    def test_a_non_mapping_argument_yields_no_rules(self):
        """A bundle with no policies section at all is not an error."""
        assert load_policy_rules(None) == {}
        assert load_policy_rules({}) == {}

    def test_malformed_entries_raise_rather_than_being_skipped(self):
        """This assertion is the reverse of what it originally said.

        The first version required that a malformed entry be skipped, on the
        reasoning that "bundle shape is checked at load, so a rule builder must
        not throw". The reasoning was circular: this function *is* the load,
        and nothing downstream re-checked the shapes it dropped. What the rule
        actually produced was a typed policy disappearing from an agent while
        the agent file still declared it.
        """
        with pytest.raises((ValueError, TypeError)):
            load_policy_rules({"a": None})
        with pytest.raises((ValueError, TypeError)):
            load_policy_rules({"b": {"config": None}})


class TestFreshnessWindow:
    """Both ends of the window, at the boundary, against a fixed clock.

    The upper bound alone was shipped first. Age is `now - timestamp`, so a
    future timestamp gives a negative age and `age > max_age` is false for it:
    an approval dated a year ahead read as fresher than one issued a second
    ago. The whole control inverted by a minus sign, and no test noticed
    because every test used a past timestamp.
    """

    def approval_at(self, moment: datetime) -> ActionRequest:
        return request_with(
            approval={
                "approver_role": "security-lead",
                "granted_for": "send:email:external:*",
                "granted_at": moment.isoformat(),
            }
        )

    def test_a_timestamp_a_year_ahead_cannot_satisfy_freshness(self):
        rule = approval_rule(max_age_seconds=900)
        outcome = rule.check(self.approval_at(NOW + timedelta(days=365)), now=NOW)
        assert not outcome.satisfied
        assert outcome.reason_code is ReasonCode.APPROVAL_REQUIRED
        assert "future" in outcome.detail

    @pytest.mark.parametrize(
        ("offset_seconds", "accepted"),
        [
            (0, True),  # exactly now
            (29, True),  # inside the clock-skew allowance
            (30, True),  # exactly at the allowance
            (31, False),  # past it
            (-899, True),  # inside the window
            (-900, True),  # exactly at max age
            (-901, False),  # past max age
        ],
    )
    def test_both_boundaries_are_inclusive_on_the_accepting_side(
        self, offset_seconds, accepted
    ):
        """Boundary values, not sleeps: a clock-dependent test proves nothing."""
        rule = approval_rule(max_age_seconds=900)
        outcome = rule.check(
            self.approval_at(NOW + timedelta(seconds=offset_seconds)), now=NOW
        )
        assert outcome.satisfied is accepted, outcome.detail

    def test_evidence_uses_the_same_window_as_approval(self):
        """One helper for both, so the two cannot drift apart."""
        rule = evidence_rule(max_age_seconds=3600)
        future = publish_request(
            {
                "type": "source_document",
                "resource": "report:q1",
                "observed_at": (NOW + timedelta(days=365)).isoformat(),
            }
        )
        assert not rule.check(future, now=NOW).satisfied

        inside_skew = publish_request(
            {
                "type": "source_document",
                "resource": "report:q1",
                "observed_at": (NOW + timedelta(seconds=20)).isoformat(),
            }
        )
        assert rule.check(inside_skew, now=NOW).satisfied

    def test_a_negative_age_is_reported_not_clamped_to_zero(self):
        """Clamping would let a fabricated timestamp read as merely fresh."""
        rule = approval_rule(max_age_seconds=900)
        outcome = rule.check(self.approval_at(NOW + timedelta(hours=5)), now=NOW)
        assert "18000s in the future" in outcome.detail


class TestSameResourceFailsClosed:
    def test_a_request_with_no_resource_cannot_satisfy_same_resource(self):
        """Missing data must deny, not switch the binding off.

        Skipping the comparison when the request named no resource meant the
        check disabled itself in exactly the case where nothing else
        constrained which object the evidence was about.
        """
        rule = evidence_rule()
        request = ActionRequest(
            agent_id="writer",
            action="publish",
            signals={"evidence": [{"type": "source_document", "resource": "anything"}]},
        )
        outcome = rule.check(request, now=NOW)
        assert not outcome.satisfied
        assert outcome.reason_code is ReasonCode.EVIDENCE_REQUIRED
        assert "must name a resource" in outcome.detail

    def test_an_evidence_claim_with_no_resource_is_refused(self):
        outcome = evidence_rule().check(
            publish_request({"type": "source_document"}), now=NOW
        )
        assert not outcome.satisfied

    def test_a_wrong_resource_claim_cannot_hide_behind_a_right_typed_one(self):
        """Only the wrong-resource claim carries the required type."""
        outcome = evidence_rule().check(
            publish_request(
                {"type": "source_document", "resource": "report:q4"},
                {"type": "screenshot", "resource": "report:q1"},
            ),
            now=NOW,
        )
        assert not outcome.satisfied
        assert "does not name resource" in outcome.detail

    def test_same_resource_false_does_not_require_a_request_resource(self):
        rule = evidence_rule(same_resource=False)
        request = ActionRequest(
            agent_id="writer",
            action="publish",
            signals={"evidence": [{"type": "source_document"}]},
        )
        assert rule.check(request, now=NOW).satisfied


class TestBooleanOptionsAreStrict:
    @pytest.mark.parametrize("bad", [0, 1, "false", "yes", None, [], {}])
    @pytest.mark.parametrize(
        ("kind", "field"),
        [
            ("requires_approval", "bind_to_request"),
            ("requires_evidence", "same_resource"),
        ],
    )
    def test_authoring_rejects_anything_that_is_not_a_boolean(self, kind, field, bad):
        """Truthiness is not a governance contract.

        `bind_to_request: 0` reads, to Python, as "turn the binding off". A
        file that says that is either a mistake or an attempt to disable a
        security check while appearing to configure one.
        """
        spec: dict[str, object] = {field: bad}
        if kind == "requires_evidence":
            spec["evidence_types"] = ["doc"]
        errors = policy_definition_errors(
            {"kind": kind, "trigger": ["send:*"], "requires": spec}
        )
        assert any(field in error and "boolean" in error for error in errors), errors

    @pytest.mark.parametrize("good", [True, False])
    def test_real_booleans_are_accepted(self, good):
        assert (
            policy_definition_errors(
                {
                    "kind": "requires_approval",
                    "trigger": ["send:*"],
                    "requires": {"bind_to_request": good},
                }
            )
            == []
        )

    def test_omitting_the_field_keeps_the_secure_default(self):
        assert (
            policy_definition_errors(
                {"kind": "requires_approval", "trigger": ["send:*"], "requires": {}}
            )
            == []
        )
        assert approval_rule().spec.get("bind_to_request") is None
        # Absence still binds: the check runs.
        outcome = approval_rule().check(
            request_with(approval={"approver_role": "security-lead"}), now=NOW
        )
        assert not outcome.satisfied

    @pytest.mark.parametrize("bad", [0, "yes", None])
    def test_a_compiled_bundle_carrying_a_non_boolean_fails_to_load(self, bad):
        """Authoring validation is not the last word.

        A bundle can be produced by another implementation or edited by hand.
        A runtime that trusts the artifact it is verifying verifies nothing.
        """
        # Authoring validation now runs first during load and produces a
        # ValueError naming the field, which is a better message than the
        # runtime TypeError it used to reach. Either way the bundle is refused.
        with pytest.raises((TypeError, ValueError), match="must be a boolean"):
            load_policy_rules(
                {
                    "gate": {
                        "config": {
                            "id": "gate",
                            "kind": "requires_approval",
                            "trigger": ["send:*"],
                            "requires": {"bind_to_request": bad},
                        }
                    }
                }
            )


class TestMalformedCompiledPoliciesFailClosed:
    """A typed policy that cannot become a rule must reject the bundle.

    The first version treated every unusable shape as though it were prose: an
    unknown kind, a trigger that was not a list, a config that was not an
    object. Each one made the policy vanish from the agent's rules while the
    agent file still declared it, so the action it was meant to gate was simply
    allowed. Not a weaker control -- no control, reported as an allowance.

    The official compiler refuses these, so the path is not reachable by
    authoring a YAML file. It is reachable by another implementation, a custom
    signing pipeline, a hand-edited development bundle, or a version skew
    between compiler and runtime. A signature proves who produced the bytes,
    not that the policy inside them can be enforced.
    """

    def bundle(self, **config: object) -> dict:
        base = {
            "id": "gate",
            "kind": "requires_approval",
            "trigger": ["send:*"],
            "requires": {"approver_role": "lead"},
        }
        base.update(config)
        return {"gate": {"config": base}}

    @pytest.mark.parametrize(
        ("label", "config"),
        [
            ("unknown kind", {"kind": "requires_aproval"}),
            ("trigger is not a list", {"trigger": "send:*"}),
            ("trigger is empty", {"trigger": []}),
            ("trigger holds a non-string", {"trigger": [123]}),
            ("invalid freshness window", {"requires": {"max_age_seconds": 0}}),
        ],
    )
    def test_an_unusable_typed_policy_rejects_the_bundle(self, label, config):
        with pytest.raises((ValueError, TypeError), match="gate"):
            load_policy_rules(self.bundle(**config))

    @pytest.mark.parametrize(
        ("label", "policies"),
        [
            ("entry is not an object", {"gate": "oops"}),
            ("config is not an object", {"gate": {"config": "oops"}}),
            ("config is missing", {"gate": {}}),
            ("policy id is empty", {"": {"config": {"kind": "requires_approval"}}}),
        ],
    )
    def test_a_malformed_bundle_entry_rejects_the_bundle(self, label, policies):
        with pytest.raises((ValueError, TypeError)):
            load_policy_rules(policies)

    def test_a_missing_required_field_rejects_the_bundle(self):
        with pytest.raises(ValueError, match="counter"):
            load_policy_rules(
                {
                    "breaker": {
                        "config": {
                            "id": "breaker",
                            "kind": "failure_threshold",
                            "trigger": ["call:*"],
                            "threshold": {},
                        }
                    }
                }
            )

    def test_a_trigger_is_never_narrowed_by_filtering(self):
        """Dropping the entries that do not fit is not a fix.

        Filtering a bad trigger item would turn an invalid policy into a valid
        one covering fewer actions -- the silent weakening this whole check
        exists to stop, wearing the costume of robustness.
        """
        with pytest.raises(ValueError):
            load_policy_rules(self.bundle(trigger=[None, "send:*"]))

    def test_a_policy_with_no_kind_is_still_prose(self):
        """The one shape that legitimately produces no rule."""
        rules = load_policy_rules(
            {"documented": {"config": {"id": "documented", "enforcement": "by review"}}}
        )
        assert rules == {}

    def test_a_valid_typed_policy_still_loads(self):
        rules = load_policy_rules(self.bundle())
        assert rules["gate"].trigger == ("send:*",)


class TestNonFiniteNumbersAreRefused:
    """`value <= 0` does not reject NaN, because no comparison with NaN is true.

    PyYAML parses `.nan` and `.inf` as floats, so a freshness window could be
    authored as either and pass validation. Canonical JSON refuses non-finite
    numbers later, so the official compile path stopped it -- but validation
    and compilation disagreeing about what is valid is its own defect, and the
    error the user got named neither the field nor the reason.
    """

    def errors_for(self, value: object) -> list[str]:
        return policy_definition_errors(
            {
                "kind": "requires_approval",
                "trigger": ["send"],
                "requires": {"max_age_seconds": value},
            }
        )

    @pytest.mark.parametrize(
        "value",
        [float("nan"), float("inf"), float("-inf"), 0, -5, True, "900", None],
    )
    def test_rejected(self, value):
        errors = self.errors_for(value)
        assert errors, f"{value!r} was accepted"
        assert any("max_age_seconds" in error for error in errors)
        assert any("finite positive" in error for error in errors)

    @pytest.mark.parametrize("value", [1, 900, 0.5, 3600.0])
    def test_accepted(self, value):
        assert self.errors_for(value) == []
