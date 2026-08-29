"""Framework-neutral contract tests for governed invocations."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from hlinor_registry import (
    ActionRequest,
    ExecutionScope,
    ExecutionScopeError,
    GovernanceDeniedError,
    PolicyDecision,
)
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


def test_gate_injects_explicit_scope_and_can_derive_it_per_invocation() -> None:
    checker = RecordingChecker()
    gate = GovernanceGate(
        agent_id="agent",
        action="read",
        bundle_path="unused.json",
        checker=checker,  # type: ignore[arg-type]
        execution_scope=lambda context: ExecutionScope(
            "project-1", context.kwargs["workspace_id"]
        ),
        require_execution_scope=True,
    )

    gate.authorize(kwargs={"workspace_id": "workspace-1"})

    request = checker.requests[0]
    assert request.project_id == "project-1"
    assert request.workspace_id == "workspace-1"
    assert request.signals["execution_scope"]["verified"] is True


def test_gate_requires_scope_and_rejects_forged_scope_signal() -> None:
    checker = RecordingChecker()
    required = GovernanceGate(
        agent_id="agent",
        action="read",
        bundle_path="unused.json",
        checker=checker,  # type: ignore[arg-type]
        require_execution_scope=True,
    )

    with pytest.raises(ExecutionScopeError, match="EXECUTION_SCOPE_REQUIRED"):
        required.authorize()

    forged = GovernanceGate(
        agent_id="agent",
        action="read",
        bundle_path="unused.json",
        checker=checker,  # type: ignore[arg-type]
        signals={"execution_scope": {"project_id": "forged"}},
    )
    with pytest.raises(ValueError, match="not signals"):
        forged.authorize()


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


class TestResourceAndSignalsReachTheRequest:
    """Without these, the wrappers cannot use what 0.8.0 added.

    `@governed` and the framework wrappers built every request with an action
    name and nothing else. An agent whose allow list scopes an action to a
    resource, or whose policy requires an approval, was therefore unreachable
    through the integrations the README recommends -- the two headline
    features of the release could only be used by calling PolicyChecker
    directly. Both were denied for the wrong reason, which is the worst kind of
    working: it looks like enforcement.
    """

    def gate(self, checker: RecordingChecker, **kwargs: Any) -> GovernanceGate:
        return GovernanceGate(
            agent_id="agent",
            action="refund_payment",
            bundle_path="unused.json",
            checker=checker,
            **kwargs,
        )

    def test_a_static_resource_reaches_the_request(self) -> None:
        checker = RecordingChecker()
        self.gate(checker, resource="order/1234").authorize()
        assert checker.requests[-1].resource == "order/1234"

    def test_a_resource_can_be_derived_from_the_call(self) -> None:
        """The common case: the resource is an argument, not a constant."""
        checker = RecordingChecker()
        gate = self.gate(
            checker, resource=lambda call: f"order/{call.kwargs['order_id']}"
        )
        gate.authorize(kwargs={"order_id": "9999"})
        assert checker.requests[-1].resource == "order/9999"

    def test_signals_reach_the_request(self) -> None:
        checker = RecordingChecker()
        approval = {"approval": {"approver_role": "support-lead"}}
        self.gate(checker, signals=approval).authorize()
        assert checker.requests[-1].signals["approval"]["approver_role"] == (
            "support-lead"
        )

    def test_signals_can_be_derived_from_the_call(self) -> None:
        checker = RecordingChecker()
        gate = self.gate(checker, signals=lambda call: call.kwargs["signals"])
        gate.authorize(kwargs={"signals": {"failure_counts": {"api": 3}}})
        assert checker.requests[-1].signals["failure_counts"]["api"] == 3

    def test_omitting_them_still_produces_a_valid_request(self) -> None:
        checker = RecordingChecker()
        self.gate(checker).authorize()
        request = checker.requests[-1]
        assert request.resource is None
        assert dict(request.signals) == {}

    def test_combining_a_request_factory_with_resource_is_refused(self) -> None:
        """Silently dropping one of them is the defect class, not the fix.

        A request factory builds the whole request. Accepting a resource
        alongside it would mean the resource is configured and ignored, which
        is exactly the shape of every fail-open case in this codebase's
        history.
        """
        checker = RecordingChecker()
        with pytest.raises(ValueError, match="not both"):
            self.gate(
                checker,
                request_factory=lambda call: ActionRequest(
                    agent_id="agent", action="refund_payment"
                ),
                resource="order/1234",
            )

        with pytest.raises(ValueError, match="not both"):
            self.gate(
                checker,
                request_factory=lambda call: ActionRequest(
                    agent_id="agent", action="refund_payment"
                ),
                signals={"approval": {}},
            )
