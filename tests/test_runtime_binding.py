"""Security tests for trusted Tool Contract runtime binding."""

from __future__ import annotations

from typing import Any

import pytest

from hlinor_registry import (
    ActionRequest,
    ArgumentValidationError,
    BoundToolRegistry,
    ContractBindingError,
    PolicyDecision,
    RuntimeBindingError,
    bind_tool,
    compute_arguments_digest,
    compute_tool_contract_digest,
)
from hlinor_registry.decision import ReasonCode


def contract() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "type": "tool_contract",
        "id": "runtime-tools",
        "name": "Runtime tools",
        "description": "Synthetic runtime binding fixture.",
        "version": "1.0.0",
        "tools": [
            {
                "id": "records.read",
                "action": "read_record",
                "description": "Read one synthetic record.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "record_id": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1},
                    },
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

    def __init__(self, denied: bool = False) -> None:
        self.denied = denied
        self.requests: list[ActionRequest] = []

    def reload_if_changed(self) -> bool:
        return False

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        self.requests.append(request)
        provenance = {
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
            request_id=request.request_id,
            request_digest=request.request_digest,
            environment=request.environment,
        )


def test_contract_and_argument_digests_use_stable_jcs_bytes() -> None:
    first = contract()
    second = {key: first[key] for key in reversed(list(first))}
    assert compute_tool_contract_digest(first) == compute_tool_contract_digest(second)
    assert compute_arguments_digest({"b": 1, "a": 2}) == compute_arguments_digest(
        {"a": 2, "b": 1}
    )
    assert compute_arguments_digest({"a": 2}) != compute_arguments_digest({"a": 3})


def test_binding_holds_the_exact_runtime_object_and_dispatches_it() -> None:
    calls: list[dict[str, Any]] = []

    def read_record(*, record_id: str, limit: int = 10) -> dict[str, Any]:
        calls.append({"record_id": record_id, "limit": limit})
        return calls[-1]

    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=read_record,
    )
    checker = Checker()

    result = bound.invoke(
        checker,  # type: ignore[arg-type]
        agent_id="reader",
        resource="record/123",
        kwargs={"record_id": "123"},
    )

    assert result == {"record_id": "123", "limit": 10}
    assert calls == [result]
    assert checker.requests[0].arguments_digest == compute_arguments_digest(result)


def test_reviewed_tool_does_not_bind_to_a_drifted_observed_contract() -> None:
    observed = contract()
    observed["tools"][0]["action"] = "delete_record"

    with pytest.raises(ContractBindingError, match="CONTRACT_DRIFT"):
        bind_tool(
            contract(),
            observed,
            tool_id="records.read",
            target=lambda *, record_id: record_id,
        )


def test_registry_rejects_runtime_tool_set_changes() -> None:
    with pytest.raises(ContractBindingError, match="RUNTIME_TOOL_SET_CHANGED"):
        BoundToolRegistry.bind(
            contract(),
            contract(),
            {"different.tool": lambda: None},
        )


def test_registry_keeps_the_exact_object_after_source_mapping_changes() -> None:
    calls: list[str] = []

    def first(*, record_id: str) -> str:
        calls.append("first")
        return record_id

    def replacement(*, record_id: str) -> str:
        calls.append("replacement")
        return record_id

    runtime_tools = {"records.read": first}
    registry = BoundToolRegistry.bind(contract(), contract(), runtime_tools)
    runtime_tools["records.read"] = replacement

    result = registry.invoke(
        "records.read",
        Checker(),  # type: ignore[arg-type]
        agent_id="reader",
        resource="record/123",
        kwargs={"record_id": "123"},
    )

    assert result == "123"
    assert calls == ["first"]


def test_invalid_arguments_are_rejected_before_policy_evaluation_or_dispatch() -> None:
    calls: list[str] = []

    def read_record(*, record_id: str, limit: int = 10) -> str:
        calls.append(record_id)
        return record_id

    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=read_record,
    )
    checker = Checker()

    with pytest.raises(ArgumentValidationError, match="record_id"):
        bound.invoke(
            checker,  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            kwargs={"record_id": 123},
        )

    assert calls == []
    assert checker.requests == []


def test_resource_drift_is_rejected_before_policy_evaluation() -> None:
    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=lambda *, record_id: record_id,
    )
    checker = Checker()

    with pytest.raises(RuntimeBindingError, match="RESOURCE_OUT_OF_SCOPE"):
        bound.invoke(
            checker,  # type: ignore[arg-type]
            agent_id="reader",
            resource="customer/123",
            kwargs={"record_id": "123"},
        )

    assert checker.requests == []


def test_policy_denial_happens_before_exact_dispatch() -> None:
    calls: list[str] = []
    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=lambda *, record_id: calls.append(record_id),
    )

    with pytest.raises(PermissionError):
        bound.invoke(
            Checker(denied=True),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            kwargs={"record_id": "123"},
        )

    assert calls == []


def test_unsupported_variadic_callable_fails_closed() -> None:
    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=lambda **kwargs: kwargs,
    )

    with pytest.raises(RuntimeBindingError, match="TOOL_SIGNATURE_UNSUPPORTED"):
        bound.normalize_arguments(record_id="123")
