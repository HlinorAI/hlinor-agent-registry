"""Tests for dependency-free correlation hooks."""

from __future__ import annotations

from typing import Any

import pytest

from hlinor_registry import (
    ActionRequest,
    BoundTool,
    CorrelationContext,
    CorrelationValidationError,
    PolicyDecision,
    attach_correlation_fields,
    bind_tool,
    load_correlation_fixture,
)
from hlinor_registry.integrations._gate import GovernanceGate, InvocationContext


def correlation() -> CorrelationContext:
    return CorrelationContext(
        trace_id="0123456789abcdef0123456789abcdef",
        span_id="0123456789abcdef",
        run_id="run:synthetic-1",
        parent_id="run:synthetic-parent",
    )


def tool_contract() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "type": "tool_contract",
        "id": "observability-tools",
        "name": "Observability tools",
        "description": "Synthetic correlation fixture.",
        "version": "1.0.0",
        "tools": [
            {
                "id": "records.read",
                "action": "read_record",
                "description": "Read one synthetic record.",
                "input_schema": {
                    "type": "object",
                    "properties": {"record_id": {"type": "string"}},
                    "required": ["record_id"],
                    "additionalProperties": False,
                },
                "resource_patterns": ["record/*"],
                "effects": ["database_read"],
                "annotations": {
                    "read_only": True,
                    "destructive": False,
                    "idempotent": True,
                },
            }
        ],
        "metadata": {"owner": "tests", "source": "synthetic"},
    }


class Checker:
    environment = "test"

    def __init__(self) -> None:
        self.requests: list[ActionRequest] = []

    def reload_if_changed(self) -> bool:
        return False

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        self.requests.append(request)
        return PolicyDecision.allow(
            request.agent_id,
            request.action,
            request_id=request.request_id,
            request_digest=request.request_digest,
            environment=request.environment,
        )


class RecordingSink:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def append(self, receipt: dict[str, Any]) -> dict[str, Any]:
        stored = dict(receipt)
        self.records.append(stored)
        return stored


def test_context_exports_namespaced_attributes_and_receipt_fields() -> None:
    context = correlation()

    assert context.as_attributes() == {
        "hlinor.correlation.trace_id": context.trace_id,
        "hlinor.correlation.span_id": context.span_id,
        "hlinor.correlation.run_id": context.run_id,
        "hlinor.correlation.parent_id": context.parent_id,
    }
    assert context.as_receipt_fields() == {
        "trace_id": context.trace_id,
        "span_id": context.span_id,
        "run_id": context.run_id,
        "parent_id": context.parent_id,
    }


def test_public_fixture_loads_as_the_same_validated_context() -> None:
    loaded = load_correlation_fixture("examples/observability/correlation-context.yaml")

    assert loaded == correlation()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("trace_id", "0" * 32),
        ("trace_id", "A" * 32),
        ("span_id", "0" * 16),
        ("span_id", "not-a-span"),
        ("run_id", "bad run id"),
        ("parent_id", ""),
    ],
)
def test_context_rejects_malformed_or_zero_identifiers(field: str, value: str) -> None:
    values: dict[str, Any] = {
        "trace_id": "0123456789abcdef0123456789abcdef",
        "span_id": "0123456789abcdef",
        "run_id": "run:synthetic-1",
        "parent_id": "run:synthetic-parent",
    }
    values[field] = value

    with pytest.raises(CorrelationValidationError):
        CorrelationContext(**values)


def test_attach_correlation_fields_rejects_caller_overwrite() -> None:
    context = correlation()

    assert (
        attach_correlation_fields({"phase": "completed"}, context)["trace_id"]
        == context.trace_id
    )
    with pytest.raises(CorrelationValidationError, match="CORRELATION_FIELD_COLLISION"):
        attach_correlation_fields({"trace_id": "forged"}, context)


def test_gate_propagates_context_without_making_it_a_policy_signal() -> None:
    checker = Checker()
    contexts: list[InvocationContext] = []

    def request_factory(context: InvocationContext) -> ActionRequest:
        contexts.append(context)
        return ActionRequest(
            agent_id=context.agent_id,
            action=context.action,
            tool_id=context.tool_id,
            environment=context.environment,
        )

    gate = GovernanceGate(
        agent_id="agent",
        action="read",
        bundle_path="unused.json",
        tool_id="records.read",
        checker=checker,  # type: ignore[arg-type]
        request_factory=request_factory,
    )
    context = correlation()

    gate.authorize(correlation=context)

    assert contexts[0].correlation == context
    assert "trace_id" not in checker.requests[0].to_dict()
    assert "span_id" not in checker.requests[0].to_dict()


def test_bound_tool_propagates_context_to_all_receipts() -> None:
    bound: BoundTool = bind_tool(
        tool_contract(),
        tool_contract(),
        tool_id="records.read",
        target=lambda *, record_id: {"record_id": record_id},
    )
    sink = RecordingSink()
    context = correlation()

    result = bound.invoke(
        Checker(),  # type: ignore[arg-type]
        agent_id="reader",
        resource="record/123",
        receipt_sink=sink,  # type: ignore[arg-type]
        correlation=context,
        kwargs={"record_id": "123"},
    )

    assert result == {"record_id": "123"}
    assert len(sink.records) == 2
    assert all(
        record["trace_id"] == context.trace_id
        and record["span_id"] == context.span_id
        and record["run_id"] == context.run_id
        and record["parent_id"] == context.parent_id
        for record in sink.records
    )


def test_bound_tool_rejects_mapping_shaped_context_before_dispatch() -> None:
    calls: list[str] = []
    bound = bind_tool(
        tool_contract(),
        tool_contract(),
        tool_id="records.read",
        target=lambda *, record_id: calls.append(record_id),
    )

    with pytest.raises(CorrelationValidationError, match="CORRELATION_CONTEXT_INVALID"):
        bound.invoke(
            Checker(),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            correlation={"trace_id": "forged"},  # type: ignore[arg-type]
            kwargs={"record_id": "123"},
        )

    assert calls == []
