"""Tests for LangChain integration with PolicyDecision."""

import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml

pytest.importorskip("langchain_core")

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.tools import BaseTool, StructuredTool

from hlinor_registry import (
    ActionRequest,
    GovernanceDeniedError,
    PolicyChecker,
    PolicyDecision,
)
from hlinor_registry.cli import main
from hlinor_registry.integrations.langchain import GovernedTool


class FakeTool:
    """Minimal fake tool for testing."""

    name = "fake_tool"

    def run(self, *args: Any, **kwargs: Any) -> str:
        return f"result: {args[0] if args else 'no-args'}"


class RecordingCallbacks(BaseCallbackHandler):
    """Record LangChain callback propagation without external services."""

    def __init__(self) -> None:
        self.starts = 0
        self.ends = 0
        self.errors = 0

    def on_tool_start(self, *args: Any, **kwargs: Any) -> None:
        self.starts += 1

    def on_tool_end(self, *args: Any, **kwargs: Any) -> None:
        self.ends += 1

    def on_tool_error(self, *args: Any, **kwargs: Any) -> None:
        self.errors += 1


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


def test_governed_agent_wraps_tools_on_the_executor() -> None:
    """The executor's own tool list is replaced with governed wrappers."""
    from hlinor_registry.integrations.langchain import GovernedAgent, GovernedTool

    class FakeExecutor:
        def __init__(self) -> None:
            self.tools = [FakeTool()]

    executor = FakeExecutor()
    GovernedAgent(executor, "test-agent", "/tmp")

    assert executor.tools
    assert all(isinstance(tool, GovernedTool) for tool in executor.tools)


def test_governed_agent_writes_wrapped_tools_back_to_their_owner() -> None:
    """Tools discovered on the inner agent must be replaced on the inner agent.

    Writing the wrapped list to the executor instead would leave the original
    ungoverned tools reachable on ``executor.agent``, removing the boundary
    this wrapper exists to add.
    """
    from hlinor_registry.integrations.langchain import GovernedAgent, GovernedTool

    class FakeInnerAgent:
        def __init__(self) -> None:
            self.tools = [FakeTool()]

    class FakeExecutor:
        def __init__(self) -> None:
            self.tools = []
            self.agent = FakeInnerAgent()

    executor = FakeExecutor()
    original_tool = executor.agent.tools[0]
    GovernedAgent(executor, "test-agent", "/tmp")

    assert all(isinstance(tool, GovernedTool) for tool in executor.agent.tools)
    assert original_tool not in executor.agent.tools
    assert executor.agent.tools[0].tool is original_tool


def test_governed_agent_refuses_an_executor_without_tools() -> None:
    """Governing nothing must fail loudly rather than silently succeed."""
    from hlinor_registry.integrations.langchain import GovernedAgent

    class EmptyExecutor:
        def __init__(self) -> None:
            self.tools = []

    with pytest.raises(ValueError, match="found no tools to govern"):
        GovernedAgent(EmptyExecutor(), "test-agent", "/tmp")


def test_real_langchain_tool_preserves_schema_metadata_and_callbacks(
    tmp_path: Path,
) -> None:
    side_effects: list[str] = []

    def search(query: str) -> str:
        """Search a controlled test index."""
        side_effects.append(query)
        return f"result: {query}"

    tool = StructuredTool.from_function(
        func=search,
        name="search",
        description="Search a controlled test index",
        return_direct=True,
        tags=["integration"],
        metadata={"owner": "tests"},
    )
    wrapper = GovernedTool(
        tool,
        "test-agent",
        str(write_agent(tmp_path, ["search"])),
    )
    callbacks = RecordingCallbacks()

    result = wrapper.invoke(
        {"query": "governance"},
        config={"callbacks": [callbacks]},
    )

    assert isinstance(wrapper, BaseTool)
    assert wrapper.args_schema is tool.args_schema
    assert wrapper.return_direct is True
    assert wrapper.tags == ["integration"]
    assert wrapper.metadata == {"owner": "tests"}
    assert result == "result: governance"
    assert side_effects == ["governance"]
    assert callbacks.starts >= 1
    assert callbacks.ends >= 1
    assert callbacks.errors == 0


def test_real_langchain_denial_emits_once_without_side_effect(
    tmp_path: Path,
) -> None:
    side_effect_count = 0
    emitted: list[PolicyDecision] = []
    bundle_path = write_agent(tmp_path, ["search"], ["send_email"])
    checker = PolicyChecker(str(bundle_path))
    original_evaluate = checker.evaluate
    evaluation_count = 0

    def send_email(message: str) -> str:
        """Send a test email."""
        nonlocal side_effect_count
        side_effect_count += 1
        return message

    def evaluate_once(request: ActionRequest) -> PolicyDecision:
        nonlocal evaluation_count
        evaluation_count += 1
        return original_evaluate(request)

    checker.evaluate = evaluate_once  # type: ignore[method-assign]
    tool = StructuredTool.from_function(
        func=send_email,
        name="send_email",
        description="Send a test email",
    )
    wrapper = GovernedTool(
        tool,
        "test-agent",
        str(bundle_path),
        checker=checker,
        decision_sink=emitted.append,
    )
    callbacks = RecordingCallbacks()

    with pytest.raises(GovernanceDeniedError) as error:
        wrapper.invoke(
            {"message": "blocked"},
            config={"callbacks": [callbacks]},
        )

    assert evaluation_count == 1
    assert emitted == [error.value.decision]
    assert side_effect_count == 0
    assert callbacks.errors == 1


def test_real_langchain_async_allow_and_deny_have_parity(tmp_path: Path) -> None:
    side_effects: list[str] = []
    emitted: list[PolicyDecision] = []
    bundle_path = write_agent(tmp_path, ["search"], ["send_email"])

    async def async_tool(query: str) -> str:
        """Execute an asynchronous test tool."""
        side_effects.append(query)
        await asyncio.sleep(0)
        return query

    tool = StructuredTool.from_function(
        coroutine=async_tool,
        name="search",
        description="Execute an asynchronous test tool",
    )
    allowed = GovernedTool(
        tool,
        "test-agent",
        str(bundle_path),
        decision_sink=emitted.append,
    )

    assert asyncio.run(allowed.ainvoke({"query": "allowed"})) == "allowed"
    assert side_effects == ["allowed"]
    assert len(emitted) == 1
    assert emitted[0].allowed

    denied = GovernedTool(
        tool,
        "test-agent",
        str(bundle_path),
        action_name="send_email",
        decision_sink=emitted.append,
    )
    with pytest.raises(GovernanceDeniedError):
        asyncio.run(denied.ainvoke({"query": "blocked"}))

    assert side_effects == ["allowed"]
    assert len(emitted) == 2
    assert emitted[1].denied
