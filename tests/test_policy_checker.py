"""Tests for bundle-based PolicyChecker enforcement."""

import json
from pathlib import Path

import pytest
import yaml

from hlinor_registry import PolicyChecker
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
    source_path.parent.mkdir()
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
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    bundle_path = tmp_path / "dist" / "policy-bundle.json"

    assert main(
        [
            "compile",
            "--manifest",
            str(manifest_path),
            "--output",
            str(bundle_path),
        ]
    ) == 0
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
    assert decision.result == "allowed"
    assert decision.reason_code == "EXPLICITLY_ALLOWED"
    assert decision.checked_at
