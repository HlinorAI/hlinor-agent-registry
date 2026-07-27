"""Tests for bundle-based PolicyChecker enforcement."""

import json
from pathlib import Path

import pytest
import yaml

from hlinor_registry import (
    ActionRequest,
    DecisionResult,
    PolicyChecker,
    ReasonCode,
    __version__,
)
from hlinor_registry.cli import main


def write_bundle(
    tmp_path: Path,
    *,
    agent_id: str = "test-agent",
    allowed_actions: list[str] | None = None,
    blocked_actions: list[str] | None = None,
    enforcement_mode: str | None = None,
    policies: list[str] | None = None,
) -> Path:
    """Write a valid agent policy and compile it into a bundle."""
    source_path = tmp_path / "policies" / "agent.yaml"
    source_path.parent.mkdir(parents=True)
    config = {
        "id": agent_id,
        "name": "Test Agent",
        "department": "testing",
        "description": "Agent used for runtime governance tests.",
        "skills": ["test"],
        "validators": ["test-validator"],
        "policies": policies or [],
        "allowed_actions": allowed_actions or [],
        "blocked_actions": blocked_actions or [],
    }
    if enforcement_mode is not None:
        config["enforcement_mode"] = enforcement_mode
    source_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    manifest_path = tmp_path / "registry.yaml"
    manifest = {
        "version": "1.0",
        "policies": [{"path": "policies/agent.yaml"}],
        "metadata": {"environment": "test", "compiled_by": "pytest"},
    }
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    bundle_path = tmp_path / "dist" / "policy-bundle.json"

    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--output",
                str(bundle_path),
            ]
        )
        == 0
    )
    return bundle_path


def test_blocklist_has_priority(tmp_path: Path) -> None:
    """Blocklist always wins, even if action is in the allowlist."""
    bundle_path = write_bundle(
        tmp_path,
        agent_id="finance",
        allowed_actions=["read"],
        blocked_actions=["read"],
    )

    decision = PolicyChecker(str(bundle_path)).check_action("finance", "read")

    assert decision.denied
    assert decision.reason_code == "ACTION_BLOCKLISTED"


def test_allowlist_denies_unspecified_action(tmp_path: Path) -> None:
    """In strict mode, actions not in the allowlist are denied."""
    bundle_path = write_bundle(tmp_path, allowed_actions=["search"])
    checker = PolicyChecker(str(bundle_path))

    decision = checker.check_action("test-agent", "search")
    decision2 = checker.check_action("test-agent", "delete")

    assert decision.allowed
    assert decision2.denied
    assert decision2.reason_code == "ACTION_NOT_ALLOWLISTED"


def test_strict_mode_is_default(tmp_path: Path) -> None:
    """By default, agents without an allowlist are denied."""
    bundle_path = write_bundle(tmp_path)
    decision = PolicyChecker(str(bundle_path)).check_action("test-agent", "read")

    assert decision.denied
    assert decision.reason_code == "ACTION_NOT_ALLOWLISTED"


def test_permissive_mode_allows_by_default(tmp_path: Path) -> None:
    """In permissive mode, actions are allowed unless blocked."""
    bundle_path = write_bundle(tmp_path, enforcement_mode="permissive")
    decision = PolicyChecker(str(bundle_path)).check_action("test-agent", "read")

    assert decision.allowed


def test_unknown_agent_is_denied(tmp_path: Path) -> None:
    """Unknown agents are always denied."""
    bundle_path = write_bundle(tmp_path)
    decision = PolicyChecker(str(bundle_path)).check_action("missing", "read")

    assert decision.denied
    assert decision.reason_code == "UNKNOWN_AGENT"


def test_policy_bundle_digest_is_verified(tmp_path: Path) -> None:
    """Runtime loading fails closed if the compiled bundle is modified."""
    bundle_path = write_bundle(tmp_path, allowed_actions=["read"])
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["agents"]["test-agent"]["config"]["allowed_actions"] = ["delete"]
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(ValueError, match="digest mismatch"):
        PolicyChecker(str(bundle_path))


def test_policy_checker_reloads_a_recompiled_bundle(tmp_path: Path) -> None:
    """A long-lived checker adopts a newly compiled policy bundle."""
    bundle_path = write_bundle(tmp_path, allowed_actions=["read"])
    checker = PolicyChecker(str(bundle_path))

    source_path = tmp_path / "policies" / "agent.yaml"
    config = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    config["allowed_actions"] = ["write"]
    source_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    assert (
        main(
            [
                "compile",
                "--manifest",
                str(tmp_path / "registry.yaml"),
                "--output",
                str(bundle_path),
            ]
        )
        == 0
    )
    assert checker.reload_if_changed()
    assert checker.check_action("test-agent", "read").denied
    assert checker.check_action("test-agent", "write").allowed


def test_audit_event_records_bundle_provenance(tmp_path: Path) -> None:
    """Audit records identify the exact policy bundle used for enforcement."""
    bundle_path = write_bundle(tmp_path, allowed_actions=["read"])
    checker = PolicyChecker(str(bundle_path))

    event = checker.audit_event(checker.check_action("test-agent", "read"))

    assert event["schema_version"] == "1.1"
    assert event["event_type"] == "policy_decision"
    assert event["policy_bundle_digest"] == checker.bundle_digest
    assert event["request_id"]
    assert event["request_digest"].startswith("sha256:")


def test_missing_policy_bundle_fails_closed(tmp_path: Path) -> None:
    """Runtime loading requires an explicit compiled bundle."""
    with pytest.raises(FileNotFoundError, match="Run `hlinor-registry compile`"):
        PolicyChecker(str(tmp_path / "missing.json"))


def test_policy_decision_has_required_fields(tmp_path: Path) -> None:
    """PolicyDecision should preserve the runtime audit fields."""
    bundle_path = write_bundle(tmp_path, allowed_actions=["read"])
    decision = PolicyChecker(str(bundle_path)).check_action("test-agent", "read")

    assert decision.decision_id
    assert decision.agent_id == "test-agent"
    assert decision.action == "read"
    assert decision.result is DecisionResult.ALLOWED
    assert decision.result == "allowed"
    assert decision.reason_code is ReasonCode.EXPLICITLY_ALLOWED
    assert decision.reason_code == "EXPLICITLY_ALLOWED"
    assert str(decision.reason_code) == "EXPLICITLY_ALLOWED"
    assert decision.checked_at
    assert decision.request_id
    assert decision.request_digest.startswith("sha256:")
    assert decision.bundle_digest == PolicyChecker(str(bundle_path)).bundle_digest


def test_decision_enums_have_exactly_one_definition() -> None:
    """Guard against a second, drifting copy of the decision enums.

    ``PolicyChecker`` builds denials with ``enums.ReasonCode`` while
    ``PolicyDecision.deny`` re-validates through the name it imported. If those
    ever become distinct types, any reason code missing from the second copy
    raises ``ValueError`` while constructing a denial, turning a fail-closed
    path into a crash.
    """
    from hlinor_registry import decision as decision_module
    from hlinor_registry import enums as enums_module

    assert decision_module.ReasonCode is enums_module.ReasonCode
    assert decision_module.DecisionResult is enums_module.DecisionResult

    from hlinor_registry import DecisionResult as exported_result
    from hlinor_registry import ReasonCode as exported_reason

    assert exported_reason is enums_module.ReasonCode
    assert exported_result is enums_module.DecisionResult

    # Every code the evaluator may emit must round-trip through the value-based
    # lookup that PolicyDecision.deny performs.
    for code in enums_module.ReasonCode:
        assert decision_module.ReasonCode(code.value) is code


def test_evaluate_binds_exact_request_and_bundle(tmp_path: Path) -> None:
    bundle_path = write_bundle(
        tmp_path,
        blocked_actions=["send_email"],
        policies=["no_pii_in_logs"],
    )
    checker = PolicyChecker(str(bundle_path))
    request = ActionRequest(
        request_id="req-finance-1",
        agent_id="test-agent",
        action="send_email",
        actor_id="service:finance-prod",
        tool_id="mail-api",
        resource="mailbox:finance",
        arguments_digest="sha256:arguments",
        attributes={"recipient_class": "external", "pii": True},
        environment="production",
        requested_at="2026-07-26T05:00:00+00:00",
    )

    decision = checker.evaluate(request)

    assert decision.denied
    assert decision.request_id == request.request_id
    assert decision.request_digest == request.request_digest
    assert decision.bundle_digest == checker.bundle_digest
    # Policy attribution is not implemented: the decision came from the block
    # list, not from evaluating the declared "no_pii_in_logs" policy, so the
    # audit record must not claim that policy was matched.
    assert decision.matched_policy_ids == ()
    assert decision.environment == "production"
    assert decision.actor_id == "service:finance-prod"
    assert decision.bundle_schema_version == "1.0"
    assert decision.compiler_version == __version__


def test_audit_event_uses_decision_provenance(tmp_path: Path) -> None:
    first_bundle = write_bundle(tmp_path / "first", allowed_actions=["read"])
    second_bundle = write_bundle(tmp_path / "second", allowed_actions=["read"])
    first_checker = PolicyChecker(str(first_bundle))
    second_checker = PolicyChecker(str(second_bundle))
    decision = first_checker.check_action("test-agent", "read")

    event = second_checker.audit_event(decision)

    assert event["policy_bundle_digest"] == first_checker.bundle_digest


def test_blocked_action_cannot_be_reached_through_a_case_variant(
    tmp_path: Path,
) -> None:
    """A case variant of a blocked action must not slip past the block list.

    Reproduces the audit PoC: in permissive mode the block list was the only
    control, and exact string matching let "initiate_transfer" through while
    "Initiate_Transfer" was denied.
    """
    bundle_path = write_bundle(
        tmp_path,
        blocked_actions=["Initiate_Transfer"],
        enforcement_mode="permissive",
    )
    checker = PolicyChecker(str(bundle_path))

    for variant in ("Initiate_Transfer", "initiate_transfer", "INITIATE_TRANSFER"):
        decision = checker.check_action("test-agent", variant)
        assert decision.denied, f"{variant} was not blocked"
        assert decision.reason_code is ReasonCode.ACTION_BLOCKLISTED


def test_allow_list_matching_stays_exact(tmp_path: Path) -> None:
    """Case-insensitive block matching must not loosen the allow list."""
    bundle_path = write_bundle(tmp_path, allowed_actions=["read_database"])
    checker = PolicyChecker(str(bundle_path))

    assert checker.check_action("test-agent", "read_database").allowed
    denied = checker.check_action("test-agent", "Read_Database")
    assert denied.denied
    assert denied.reason_code is ReasonCode.ACTION_NOT_ALLOWLISTED


def test_permissive_allowance_is_not_reported_as_explicit(tmp_path: Path) -> None:
    """Permissive mode must not claim an action was explicitly permitted.

    Nothing in the policy mentions the action; it is allowed because the mode
    has no opinion. Recording that as EXPLICITLY_ALLOWED puts a claim into the
    audit record that the policy does not support, which is the same defect
    class as fabricated policy attribution.
    """
    bundle_path = write_bundle(
        tmp_path,
        allowed_actions=["read"],
        blocked_actions=["delete"],
        enforcement_mode="permissive",
    )
    checker = PolicyChecker(str(bundle_path))

    unmentioned = checker.check_action("test-agent", "something_nobody_listed")
    assert unmentioned.allowed
    assert unmentioned.reason_code is ReasonCode.ALLOWED_NOT_BLOCKLISTED

    listed = checker.check_action("test-agent", "read")
    assert listed.allowed
    assert listed.reason_code is ReasonCode.EXPLICITLY_ALLOWED

    blocked = checker.check_action("test-agent", "delete")
    assert blocked.denied
    assert blocked.reason_code is ReasonCode.ACTION_BLOCKLISTED


def test_strict_mode_allowance_stays_explicit(tmp_path: Path) -> None:
    """In strict mode every allowance is by definition explicit."""
    bundle_path = write_bundle(tmp_path, allowed_actions=["read"])

    decision = PolicyChecker(str(bundle_path)).check_action("test-agent", "read")

    assert decision.reason_code is ReasonCode.EXPLICITLY_ALLOWED


def test_permissive_allowance_reaches_the_audit_event(tmp_path: Path) -> None:
    """The distinction has to survive into the JSONL record, not just the API."""
    bundle_path = write_bundle(tmp_path, enforcement_mode="permissive")
    checker = PolicyChecker(str(bundle_path))

    event = checker.audit_event(checker.check_action("test-agent", "anything"))

    assert event["result"] == "allowed"
    assert event["reason_code"] == "ALLOWED_NOT_BLOCKLISTED"


def test_oversized_bundle_is_refused_before_parsing(tmp_path: Path) -> None:
    """A wrong file should fail with a diagnosis, not by exhausting memory."""
    from hlinor_registry import _limits

    bundle_path = write_bundle(tmp_path, allowed_actions=["read"])
    tiny_limit = 16

    original = _limits.MAX_BUNDLE_BYTES
    try:
        _limits.MAX_BUNDLE_BYTES = tiny_limit
        import hlinor_registry.policy_checker as checker_module

        checker_module.MAX_BUNDLE_BYTES = tiny_limit
        with pytest.raises(_limits.FileTooLargeError, match="above the"):
            PolicyChecker(str(bundle_path))
    finally:
        _limits.MAX_BUNDLE_BYTES = original
        import hlinor_registry.policy_checker as checker_module

        checker_module.MAX_BUNDLE_BYTES = original


def test_size_limits_are_stated_not_arbitrary() -> None:
    """The limits should be ordered by the role of the file they guard."""
    from hlinor_registry._limits import (
        MAX_BUNDLE_BYTES,
        MAX_SOURCE_BYTES,
        MAX_TRUST_STORE_BYTES,
    )

    assert MAX_TRUST_STORE_BYTES < MAX_SOURCE_BYTES < MAX_BUNDLE_BYTES


def test_compiled_capabilities_are_readable_but_not_enforced(tmp_path: Path) -> None:
    """Capabilities are inventory, and the distinction has to be visible.

    The compiler writes them into the bundle. Leaving them unreachable made
    them dead data inside an enforcement artifact; letting them influence a
    decision would claim an enforcement that does not exist. They are exposed,
    and evaluate() ignores them.
    """
    source = tmp_path / "sources" / "capability.yaml"
    source.parent.mkdir(parents=True)
    source.write_text(
        yaml.safe_dump(
            {
                "id": "sample-capability",
                "type": "capability",
                "name": "Sample Capability",
                "description": "Capability used to test bundle inventory.",
                "repository": "https://example.invalid/sample",
                "version": "1.0.0",
                "interfaces": {
                    "inputs": [{"name": "query", "type": "string"}],
                    "outputs": [{"name": "result", "type": "string"}],
                },
                "policies": [
                    {"id": "p1", "description": "Sample policy", "severity": "low"}
                ],
                "validators": ["sample-validator"],
                "metadata": {
                    "owner": "tests",
                    "compliance_level": "none",
                    "last_audit": "2026-07-27",
                },
            }
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "registry.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "version": "1.0",
                "policies": [{"path": "sources/capability.yaml"}],
                "metadata": {"environment": "test"},
            }
        ),
        encoding="utf-8",
    )
    bundle_path = tmp_path / "bundle.json"
    assert (
        main(["compile", "--manifest", str(manifest), "--output", str(bundle_path)])
        == 0
    )

    checker = PolicyChecker(str(bundle_path))

    assert "sample-capability" in checker.capabilities
    assert checker.get_capability_info("sample-capability") is not None
    assert checker.get_capability_info("absent") is None

    # A capability is not an agent, and naming one does not grant anything.
    decision = checker.check_action("sample-capability", "anything")
    assert decision.denied
    assert decision.reason_code is ReasonCode.UNKNOWN_AGENT


def test_capability_info_is_a_defensive_copy(tmp_path: Path) -> None:
    """Callers must not be able to mutate the loaded bundle through it."""
    bundle_path = write_bundle(tmp_path, allowed_actions=["read"])
    checker = PolicyChecker(str(bundle_path))
    checker.capabilities["injected"] = {"config": {}}

    info = checker.get_capability_info("injected")
    assert info is not None
    info["config"]["tampered"] = True

    assert checker.capabilities["injected"]["config"] == {}


def test_resource_scoped_allow_and_block(tmp_path: Path) -> None:
    """A pattern scopes an action to the resources it may touch."""
    bundle_path = write_bundle(
        tmp_path,
        allowed_actions=["read:report:quarterly/*", "classify:ticket:*"],
        blocked_actions=["read:report:quarterly/secret*"],
    )
    checker = PolicyChecker(str(bundle_path))

    def decide(action: str, resource: str | None = None):
        return checker.evaluate(
            ActionRequest(agent_id="test-agent", action=action, resource=resource)
        )

    assert decide("read", "report:quarterly/q1").allowed
    assert decide("classify", "ticket:1234").allowed

    # Blocked wins even though the allow pattern also covers it.
    blocked = decide("read", "report:quarterly/secret-q1")
    assert blocked.denied
    assert blocked.reason_code is ReasonCode.ACTION_BLOCKLISTED

    # A resource outside every allow pattern is denied in strict mode.
    outside = decide("read", "report:annual/2026")
    assert outside.denied
    assert outside.reason_code is ReasonCode.ACTION_NOT_ALLOWLISTED


def test_decision_records_which_pattern_matched(tmp_path: Path) -> None:
    """Provenance a reviewer can act on, computed rather than guessed.

    This is the field matched_policy_ids pretended to be. The difference is
    that this one is derived from the comparison that produced the decision.
    """
    bundle_path = write_bundle(
        tmp_path,
        allowed_actions=["read:report:*"],
        blocked_actions=["send:email:external:*"],
    )
    checker = PolicyChecker(str(bundle_path))

    allowed = checker.evaluate(
        ActionRequest(agent_id="test-agent", action="read", resource="report:q1")
    )
    assert allowed.matched_pattern == "read:report:*"

    denied = checker.evaluate(
        ActionRequest(
            agent_id="test-agent",
            action="send",
            resource="email:external:someone@example.invalid",
        )
    )
    assert denied.matched_pattern == "send:email:external:*"

    # Nothing matched, so there is nothing to point at.
    unmatched = checker.evaluate(
        ActionRequest(agent_id="test-agent", action="delete", resource="report:q1")
    )
    assert unmatched.denied
    assert unmatched.matched_pattern is None

    event = checker.audit_event(denied)
    assert event["matched_pattern"] == "send:email:external:*"


def test_existing_bare_action_lists_are_unchanged(tmp_path: Path) -> None:
    """Every bundle written before patterns existed must decide as it did."""
    bundle_path = write_bundle(
        tmp_path,
        allowed_actions=["read", "analyze"],
        blocked_actions=["delete_records"],
    )
    checker = PolicyChecker(str(bundle_path))

    assert checker.check_action("test-agent", "read").allowed
    assert checker.check_action("test-agent", "analyze").allowed
    assert checker.check_action("test-agent", "delete_records").denied
    assert checker.check_action("test-agent", "something_else").denied

    # A bare entry does not silently widen into a prefix match.
    scoped = checker.evaluate(
        ActionRequest(agent_id="test-agent", action="read", resource="anything")
    )
    assert scoped.denied
    assert scoped.reason_code is ReasonCode.ACTION_NOT_ALLOWLISTED


def test_block_patterns_ignore_case_and_allow_patterns_do_not(
    tmp_path: Path,
) -> None:
    """The asymmetry from 0.6.0 survives the move to patterns."""
    bundle_path = write_bundle(
        tmp_path,
        allowed_actions=["read:report:*"],
        blocked_actions=["send:email:External:*"],
    )
    checker = PolicyChecker(str(bundle_path))

    for spelling in ("email:external:x", "email:EXTERNAL:x", "email:External:x"):
        decision = checker.evaluate(
            ActionRequest(agent_id="test-agent", action="send", resource=spelling)
        )
        assert decision.denied, spelling
        assert decision.reason_code is ReasonCode.ACTION_BLOCKLISTED

    # The allow side stays exact: a case variant is not an approval.
    wrong_case = checker.evaluate(
        ActionRequest(agent_id="test-agent", action="Read", resource="report:q1")
    )
    assert wrong_case.denied


def test_a_broad_allow_pattern_relies_on_the_block_list(tmp_path: Path) -> None:
    """Documents the sharp edge rather than pretending it is not there.

    '*' crosses ':', so 'send:email:*' covers external sends too. What keeps
    them out is the block list, and that is worth an explicit test so the
    behaviour is not discovered in production.
    """
    bundle_path = write_bundle(
        tmp_path,
        allowed_actions=["send:email:*"],
        blocked_actions=["send:email:external:*"],
    )
    checker = PolicyChecker(str(bundle_path))

    internal = checker.evaluate(
        ActionRequest(agent_id="test-agent", action="send", resource="email:internal:x")
    )
    assert internal.allowed

    external = checker.evaluate(
        ActionRequest(agent_id="test-agent", action="send", resource="email:external:x")
    )
    assert external.denied
    assert external.matched_pattern == "send:email:external:*"
