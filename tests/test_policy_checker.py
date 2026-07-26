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
