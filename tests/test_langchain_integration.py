"""Tests for LangChain integration with PolicyDecision."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from hlinor_registry import GovernanceDeniedError
from hlinor_registry.cli import main
from hlinor_registry.integrations.langchain import GovernedTool


class FakeTool:
    """Minimal fake tool for testing."""
    
    name = "fake_tool"
    
    def run(self, *args: Any, **kwargs: Any) -> str:
        return f"result: {args[0] if args else 'no-args'}"


def write_agent(
    tmp_path: Path,
    allowed: list[str],
    blocked: list[str] | None = None,
) -> Path:
    """Helper to write and compile a test agent policy."""
    source_dir = tmp_path / "policies"
    source_dir.mkdir()
    config = {
        "id": "test-agent",
        "name": "Test Agent",
        "department": "testing",
        "description": "Agent used for integration tests.",
        "skills": ["test"],
        "validators": ["test-validator"],
        "policies": [],
        "allowed_actions": allowed,
        "blocked_actions": blocked or [],
    }
    source_path = source_dir / "agent.yaml"
    source_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    manifest_path = tmp_path / "registry.yaml"
    manifest_path.write_text(
        yaml.safe_dump(
            {
                "version": "1.0",
                "policies": [{"path": "policies/agent.yaml"}],
                "metadata": {"environment": "test", "compiled_by": "pytest"},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
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


def test_governed_tool_allows_and_delegates(tmp_path: Path) -> None:
    """Tool should execute when action is allowed."""
    tool = FakeTool()
    wrapper = GovernedTool(
        tool,
        "test-agent",
        str(write_agent(tmp_path, ["search"])),
        action_name="search",
    )
    
    assert wrapper.run("query") == "result: query"


def test_governed_tool_blocks_before_delegation(tmp_path: Path) -> None:
    """Tool should raise GovernanceDeniedError when action is blocked."""
    tool = FakeTool()
    wrapper = GovernedTool(
        tool,
        "test-agent",
        str(write_agent(tmp_path, ["search"], ["send_email"])),
        action_name="send_email",
    )
    
    with pytest.raises(GovernanceDeniedError) as exc_info:
        wrapper.run("message")
    
    assert exc_info.value.decision.denied
    assert exc_info.value.decision.reason_code == "ACTION_BLOCKLISTED"


def test_governed_agent_wraps_nested_tools() -> None:
    """Smoke test for GovernedAgent initialization."""
    # This is a basic smoke test; full integration tests require LangChain
    from hlinor_registry.integrations.langchain import GovernedAgent
    
    class FakeExecutor:
        tools = [FakeTool()]
    
    # Should not raise
    executor = FakeExecutor()
    GovernedAgent(executor, "test-agent", "/tmp")
