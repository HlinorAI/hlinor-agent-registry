"""Tests for LangChain integration with PolicyDecision."""

from pathlib import Path
from typing import Any

import pytest

from hlinor_registry import GovernanceDeniedError
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
    """Helper to write a test agent YAML."""
    lines = [f"id: test-agent", f"allowed_actions: {allowed}"]
    if blocked:
        lines.append(f"blocked_actions: {blocked}")
    (tmp_path / "agent.yaml").write_text("\n".join(lines), encoding="utf-8")
    return tmp_path


def test_governed_tool_allows_and_delegates(tmp_path: Path) -> None:
    """Tool should execute when action is allowed."""
    tool = FakeTool()
    wrapper = GovernedTool(
        tool, 
        "test-agent", 
        str(write_agent(tmp_path, ["search"])),
        action_name="search",  # <-- ДОБАВИТЬ ЭТО
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