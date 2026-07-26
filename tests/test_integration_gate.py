"""Framework-neutral contract tests for governed invocations."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from hlinor_registry import ActionRequest, GovernanceDeniedError, PolicyDecision
from hlinor_registry.decision import ReasonCode
from hlinor_registry.integrations._gate import GovernanceGate, InvocationContext


class RecordingChecker:
    """Minimal checker double that records exact evaluation behavior."""

    environment = "test"

    def __init__(self, *, denied: bool = False) -> None:
        self.denied = denied
        self.reload_count = 0
        self.requests: list[ActionRequest] = []

    def reload_if_changed(self) -> bool:
        self.reload_count += 1
        return False

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        self.requests.append(request)
        provenance: dict[str, Any] = {
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "environment": request.environment,
        }
        if self.denied:
            return PolicyDecision.deny(
                request.agent_id,
                request.action,
                ReasonCode.ACTION_BLOCKLISTED,
                **provenance,
            )
        return PolicyDecision.allow(
            request.agent_id,
            request.action,
            **provenance,
        )


class ConcurrentChecker(RecordingChecker):
    """Checker double that detects overlapping evaluations."""

    def __init__(self) -> None:
        super().__init__()
        self.active_evaluations = 0
        self.maximum_active_evaluations = 0
        self._counter_lock = threading.Lock()

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        with self._counter_lock:
            self.active_evaluations += 1
            self.maximum_active_evaluations = max(
                self.maximum_active_evaluations,
                self.active_evaluations,
            )
        try:
            time.sleep(0.02)
            return super().evaluate(request)
        finally:
            with self._counter_lock:
                self.active_evaluations -= 1


def test_gate_evaluates_and_emits_exactly_once() -> None:
    checker = RecordingChecker()
    emitted: list[PolicyDecision] = []
    contexts: list[InvocationContext] = []

    def request_factory(context: InvocationContext) -> ActionRequest:
        contexts.append(context)
        return ActionRequest(
            agent_id=context.agent_id,
            action=context.action,
            tool_id=context.tool_id,
            actor_id="service:test",
            environment=context.environment,
        )

    gate = GovernanceGate(
        agent_id="agent",
        action="read",
        bundle_path="unused.json",
        tool_id="database",
        checker=checker,  # type: ignore[arg-type]
        decision_sink=emitted.append,
        request_factory=request_factory,
    )

    decision = gate.authorize(("record-1",), {"fresh": True})

    assert decision.allowed
    assert checker.reload_count == 1
    assert len(checker.requests) == 1
    assert emitted == [decision]
    assert contexts[0].args == ("record-1",)
    assert dict(contexts[0].kwargs) == {"fresh": True}
    assert checker.requests[0].actor_id == "service:test"
    assert checker.requests[0].tool_id == "database"


def test_gate_denies_before_the_adapter_can_execute() -> None:
    checker = RecordingChecker(denied=True)
    emitted: list[PolicyDecision] = []
    gate = GovernanceGate(
        agent_id="agent",
        action="delete",
        bundle_path="unused.json",
        checker=checker,  # type: ignore[arg-type]
        decision_sink=emitted.append,
    )

    with pytest.raises(GovernanceDeniedError) as error:
        gate.authorize()

    assert len(checker.requests) == 1
    assert emitted == [error.value.decision]


def test_gates_serialize_access_to_a_shared_checker() -> None:
    checker = ConcurrentChecker()
    gates = [
        GovernanceGate(
            agent_id=f"agent-{index}",
            action="read",
            bundle_path="unused.json",
            checker=checker,  # type: ignore[arg-type]
        )
        for index in range(2)
    ]
    ready = threading.Barrier(2)

    def authorize(gate: GovernanceGate) -> PolicyDecision:
        ready.wait()
        return gate.authorize()

    with ThreadPoolExecutor(max_workers=2) as executor:
        decisions = list(executor.map(authorize, gates))

    assert all(decision.allowed for decision in decisions)
    assert checker.maximum_active_evaluations == 1
    assert checker.reload_count == 2
    assert len(checker.requests) == 2


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (
            lambda context: ActionRequest(
                agent_id="other-agent",
                action=context.action,
                tool_id=context.tool_id,
            ),
            "agent_id",
        ),
        (
            lambda context: ActionRequest(
                agent_id=context.agent_id,
                action="other-action",
                tool_id=context.tool_id,
            ),
            "action",
        ),
        (
            lambda context: ActionRequest(
                agent_id=context.agent_id,
                action=context.action,
                tool_id="other-tool",
            ),
            "tool_id",
        ),
    ],
)
def test_gate_rejects_request_factory_target_changes(
    factory: Any,
    message: str,
) -> None:
    checker = RecordingChecker()
    gate = GovernanceGate(
        agent_id="agent",
        action="read",
        bundle_path="unused.json",
        tool_id="database",
        checker=checker,  # type: ignore[arg-type]
        request_factory=factory,
    )

    with pytest.raises(ValueError, match=message):
        gate.authorize()

    assert checker.requests == []
