"""Contract tests for the optional CrewAI integration."""

import asyncio
from pathlib import Path

import pytest
import yaml

pytest.importorskip("crewai")

from crewai.tools import BaseTool
from pydantic import BaseModel

from hlinor_registry import (
    ActionRequest,
    GovernanceDeniedError,
    PolicyChecker,
    PolicyDecision,
)
from hlinor_registry.cli import main
from hlinor_registry.integrations.crewai import GovernedCrewTool


def write_bundle(tmp_path: Path) -> Path:
    """Compile a policy bundle with one allowed and one blocked action."""
    source_path = tmp_path / "agent.yaml"
    source_path.write_text(
        yaml.safe_dump(
            {
                "id": "crewai-agent",
                "name": "CrewAI Test Agent",
                "department": "testing",
                "description": "Agent used for CrewAI integration tests.",
                "skills": [],
                "validators": [],
                "policies": [],
                "allowed_actions": ["read"],
                "blocked_actions": ["send_email"],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    manifest_path = tmp_path / "registry.yaml"
    manifest_path.write_text(
        yaml.safe_dump(
            {"version": "1.0", "policies": [{"path": "agent.yaml"}]},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    bundle_path = tmp_path / "bundle.json"
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


def test_governed_crewai_tool_delegates_allowed_action(tmp_path: Path) -> None:
    bundle_path = write_bundle(tmp_path)
    tool = GovernedCrewTool(
        executor=lambda query: f"result: {query}",
        name="read",
        description="Read test data",
        agent_id="crewai-agent",
        action_name="read",
        bundle_path=str(bundle_path),
    )

    assert tool._run(query="report") == "result: report"


def test_governed_crewai_tool_raises_on_denied_action(tmp_path: Path) -> None:
    bundle_path = write_bundle(tmp_path)
    tool = GovernedCrewTool(
        executor=lambda message: f"sent: {message}",
        name="send_email",
        description="Send an email",
        agent_id="crewai-agent",
        action_name="send_email",
        bundle_path=str(bundle_path),
    )

    with pytest.raises(GovernanceDeniedError) as error:
        tool._run(message="hello")

    assert error.value.decision.reason_code == "ACTION_BLOCKLISTED"


def test_governed_crewai_denial_evaluates_and_emits_once(
    tmp_path: Path,
) -> None:
    bundle_path = write_bundle(tmp_path)
    checker = PolicyChecker(str(bundle_path))
    original_evaluate = checker.evaluate
    evaluation_count = 0
    side_effect_count = 0
    emitted: list[PolicyDecision] = []

    def evaluate_once(request: ActionRequest) -> PolicyDecision:
        nonlocal evaluation_count
        evaluation_count += 1
        return original_evaluate(request)

    def send_email(message: str) -> str:
        nonlocal side_effect_count
        side_effect_count += 1
        return message

    checker.evaluate = evaluate_once  # type: ignore[method-assign]
    tool = GovernedCrewTool(
        executor=send_email,
        name="send_email",
        description="Send an email",
        agent_id="crewai-agent",
        action_name="send_email",
        bundle_path=str(bundle_path),
        checker=checker,
        decision_sink=emitted.append,
    )

    with pytest.raises(GovernanceDeniedError) as error:
        tool._run(message="blocked")

    assert evaluation_count == 1
    assert emitted == [error.value.decision]
    assert side_effect_count == 0


def test_governed_crewai_reuses_checker_across_invocations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_path = write_bundle(tmp_path)
    checker = PolicyChecker(str(bundle_path))
    reload_count = 0
    original_reload = checker.reload_if_changed

    def reload_once() -> bool:
        nonlocal reload_count
        reload_count += 1
        return original_reload()

    monkeypatch.setattr(checker, "reload_if_changed", reload_once)
    tool = GovernedCrewTool(
        executor=lambda query: query,
        name="read",
        description="Read test data",
        agent_id="crewai-agent",
        action_name="read",
        bundle_path=str(bundle_path),
        checker=checker,
    )

    assert tool._run(query="one") == "one"
    assert tool._run(query="two") == "two"
    assert reload_count == 2


def test_governed_crewai_preserves_real_tool_schema(tmp_path: Path) -> None:
    class QueryInput(BaseModel):
        query: str

    class EchoTool(BaseTool):
        name: str = "read"
        description: str = "Read test data"
        args_schema: type[BaseModel] = QueryInput

        def _run(self, query: str) -> str:
            return query

    bundle_path = write_bundle(tmp_path)
    original = EchoTool()
    governed_tool = GovernedCrewTool(
        executor=original,
        agent_id="crewai-agent",
        action_name="read",
        bundle_path=str(bundle_path),
    )

    assert governed_tool.args_schema is original.args_schema
    assert governed_tool.run(query="report") == "report"


def test_governed_crewai_async_allow_and_deny_have_parity(tmp_path: Path) -> None:
    bundle_path = write_bundle(tmp_path)
    side_effects: list[str] = []
    emitted: list[PolicyDecision] = []

    async def executor(query: str) -> str:
        side_effects.append(query)
        await asyncio.sleep(0)
        return query

    allowed = GovernedCrewTool(
        executor=executor,
        name="read",
        description="Read test data",
        agent_id="crewai-agent",
        action_name="read",
        bundle_path=str(bundle_path),
        decision_sink=emitted.append,
    )
    assert asyncio.run(allowed._arun(query="allowed")) == "allowed"

    denied = GovernedCrewTool(
        executor=executor,
        name="send_email",
        description="Send an email",
        agent_id="crewai-agent",
        action_name="send_email",
        bundle_path=str(bundle_path),
        decision_sink=emitted.append,
    )
    with pytest.raises(GovernanceDeniedError):
        asyncio.run(denied._arun(query="blocked"))

    assert side_effects == ["allowed"]
    assert len(emitted) == 2
    assert emitted[0].allowed
    assert emitted[1].denied
