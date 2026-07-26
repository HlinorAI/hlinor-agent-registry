"""Tests for framework-agnostic governed function wrappers."""

import asyncio
import inspect
from pathlib import Path

import pytest
import yaml

from hlinor_registry import ActionRequest, GovernanceDeniedError, PolicyChecker
from hlinor_registry.cli import main
from hlinor_registry.decision import PolicyDecision
from hlinor_registry.integrations._gate import InvocationContext
from hlinor_registry.integrations.decorators import PolicyViolationError, governed


def write_bundle(tmp_path: Path, allowed_actions: list[str]) -> Path:
    """Compile a test policy bundle for decorator tests."""
    source_path = tmp_path / "agent.yaml"
    source_path.write_text(
        yaml.safe_dump(
            {
                "id": "decorator-agent",
                "name": "Decorator Agent",
                "department": "testing",
                "description": "Agent used for decorator tests.",
                "skills": [],
                "validators": [],
                "policies": [],
                "allowed_actions": allowed_actions,
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


def test_governed_decorator_allows_permitted_action(tmp_path: Path) -> None:
    bundle_path = write_bundle(tmp_path, ["read"])

    @governed("decorator-agent", "read", str(bundle_path))
    def read_record() -> str:
        return "record"

    assert read_record() == "record"


def test_governed_decorator_uses_standard_denial_contract(tmp_path: Path) -> None:
    bundle_path = write_bundle(tmp_path, ["read"])

    @governed("decorator-agent", "send_email", str(bundle_path))
    def send_email() -> str:
        return "sent"

    with pytest.raises(PolicyViolationError) as error:
        send_email()

    assert PolicyViolationError is GovernanceDeniedError
    assert isinstance(error.value, GovernanceDeniedError)
    assert error.value.decision.reason_code == "ACTION_BLOCKLISTED"


def test_governed_decorator_refreshes_changed_bundle(tmp_path: Path) -> None:
    bundle_path = write_bundle(tmp_path, ["read"])

    @governed("decorator-agent", "read", str(bundle_path))
    def read_record() -> str:
        return "record"

    assert read_record() == "record"

    source_path = tmp_path / "agent.yaml"
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

    with pytest.raises(GovernanceDeniedError):
        read_record()


def test_governed_decorator_preserves_native_async_contract(tmp_path: Path) -> None:
    bundle_path = write_bundle(tmp_path, ["read"])
    checker = PolicyChecker(str(bundle_path))
    original_evaluate = checker.evaluate
    evaluated: list[ActionRequest] = []
    emitted: list[PolicyDecision] = []
    contexts: list[InvocationContext] = []
    side_effects: list[str] = []

    def evaluate_once(request: ActionRequest) -> PolicyDecision:
        evaluated.append(request)
        return original_evaluate(request)

    checker.evaluate = evaluate_once  # type: ignore[method-assign]

    def request_factory(context: InvocationContext) -> ActionRequest:
        contexts.append(context)
        return ActionRequest(
            agent_id=context.agent_id,
            action=context.action,
            tool_id=context.tool_id,
            actor_id="service:async-test",
            environment=context.environment,
        )

    @governed(
        "decorator-agent",
        "read",
        str(bundle_path),
        checker=checker,
        decision_sink=emitted.append,
        request_factory=request_factory,
        tool_id="async-reader",
    )
    async def read_record(record_id: str, *, fresh: bool) -> str:
        side_effects.append(record_id)
        await asyncio.sleep(0)
        return record_id

    assert inspect.iscoroutinefunction(read_record)
    assert asyncio.run(read_record("record-1", fresh=True)) == "record-1"
    assert side_effects == ["record-1"]
    assert len(evaluated) == 1
    assert len(emitted) == 1
    assert emitted[0].request_id == evaluated[0].request_id
    assert evaluated[0].actor_id == "service:async-test"
    assert contexts[0].args == ("record-1",)
    assert dict(contexts[0].kwargs) == {"fresh": True}


def test_governed_async_denial_has_no_side_effect(tmp_path: Path) -> None:
    bundle_path = write_bundle(tmp_path, ["read"])
    checker = PolicyChecker(str(bundle_path))
    original_evaluate = checker.evaluate
    evaluation_count = 0
    emitted: list[PolicyDecision] = []
    side_effect_count = 0

    def evaluate_once(request: ActionRequest) -> PolicyDecision:
        nonlocal evaluation_count
        evaluation_count += 1
        return original_evaluate(request)

    checker.evaluate = evaluate_once  # type: ignore[method-assign]

    @governed(
        "decorator-agent",
        "send_email",
        str(bundle_path),
        checker=checker,
        decision_sink=emitted.append,
    )
    async def send_email() -> str:
        nonlocal side_effect_count
        side_effect_count += 1
        return "sent"

    with pytest.raises(GovernanceDeniedError):
        asyncio.run(send_email())

    assert evaluation_count == 1
    assert len(emitted) == 1
    assert emitted[0].denied
    assert side_effect_count == 0
