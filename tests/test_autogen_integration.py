"""Compatibility tests for Microsoft AutoGen Tool Contract export."""

import asyncio
from typing import Any, ClassVar

import pytest

pytest.importorskip("autogen_core")

from autogen_core import CancellationToken
from autogen_core.tools import FunctionTool

from hlinor_registry import (
    ActionRequest,
    ExecutionScope,
    GovernanceDeniedError,
    PolicyDecision,
    ToolContractExportError,
    ToolGovernance,
)
from hlinor_registry.decision import ReasonCode
from hlinor_registry.integrations.autogen import (
    GovernedAutoGenTool,
    export_autogen_tool_contract,
)
from hlinor_registry.tool_contract import tool_contract_errors


class RecordingChecker:
    environment = "test"

    def __init__(self, *, denied: bool = False) -> None:
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
        return PolicyDecision.allow(request.agent_id, request.action, **provenance)


def test_real_autogen_function_tool_exports_without_invocation() -> None:
    calls = 0

    async def search_records(query: str, limit: int = 10) -> list[str]:
        nonlocal calls
        calls += 1
        return [query] * limit

    tool = FunctionTool(
        search_records,
        name="search_records",
        description="Search a synthetic record index.",
    )
    contract = export_autogen_tool_contract(
        [tool],
        contract_id="autogen-tools",
        name="AutoGen Tools",
        description="Synthetic AutoGen tools.",
        version="1.0.0",
        owner="Test Team",
        governance={
            "search_records": ToolGovernance(
                read_only=True,
                destructive=False,
                idempotent=True,
                resource_patterns=("record/*",),
                effects=("database_read",),
            )
        },
    )

    assert calls == 0
    assert tool_contract_errors(contract) == []
    assert contract["metadata"]["source"] == "autogen"
    assert contract["tools"][0]["input_schema"]["properties"]["query"]["type"] == (
        "string"
    )
    assert contract["tools"][0]["input_schema"]["additionalProperties"] is False


def test_autogen_export_refuses_missing_governance() -> None:
    def search_records(query: str) -> list[str]:
        return [query]

    tool = FunctionTool(
        search_records,
        description="Search a synthetic record index.",
    )

    with pytest.raises(ToolContractExportError, match="missing governance"):
        export_autogen_tool_contract(
            [tool],
            contract_id="autogen-tools",
            name="AutoGen Tools",
            description="Synthetic AutoGen tools.",
            version="1.0.0",
            owner="Test Team",
            governance={},
        )


def test_autogen_export_refuses_non_mapping_schema() -> None:
    class InvalidTool:
        name = "invalid"
        description = "Invalid synthetic tool."
        schema: Any = None

    with pytest.raises(ToolContractExportError, match="schema mapping"):
        export_autogen_tool_contract(
            [InvalidTool()],
            contract_id="autogen-tools",
            name="AutoGen Tools",
            description="Synthetic AutoGen tools.",
            version="1.0.0",
            owner="Test Team",
            governance={
                "invalid": ToolGovernance(
                    read_only=True,
                    destructive=False,
                    idempotent=True,
                )
            },
        )


def test_autogen_export_refuses_schema_without_parameters() -> None:
    class InvalidTool:
        name = "invalid"
        description = "Invalid synthetic tool."
        schema: ClassVar[dict[str, Any]] = {
            "name": "invalid",
            "description": "Invalid synthetic tool.",
        }

    with pytest.raises(ToolContractExportError, match="does not expose a supported"):
        export_autogen_tool_contract(
            [InvalidTool()],
            contract_id="autogen-tools",
            name="AutoGen Tools",
            description="Synthetic AutoGen tools.",
            version="1.0.0",
            owner="Test Team",
            governance={
                "invalid": ToolGovernance(
                    read_only=True,
                    destructive=False,
                    idempotent=True,
                )
            },
        )


def test_governed_autogen_tool_authorizes_run_json_and_propagates_scope() -> None:
    calls: list[str] = []

    async def search_records(query: str) -> list[str]:
        calls.append(query)
        return [query]

    checker = RecordingChecker()
    tool = FunctionTool(
        search_records,
        name="search_records",
        description="Search a synthetic record index.",
    )
    governed = GovernedAutoGenTool(
        tool,
        "agent-b",
        checker=checker,  # type: ignore[arg-type]
        execution_scope=ExecutionScope("project-alpha", "workspace-1"),
        require_execution_scope=True,
    )

    result = asyncio.run(governed.run_json({"query": "hello"}, CancellationToken()))

    assert result == ["hello"]
    assert calls == ["hello"]
    assert checker.requests[0].project_id == "project-alpha"
    assert checker.requests[0].workspace_id == "workspace-1"
    assert checker.requests[0].signals["execution_scope"]["verified"] is True


def test_governed_autogen_tool_denies_before_wrapped_tool_runs() -> None:
    calls = 0

    async def search_records(query: str) -> list[str]:
        nonlocal calls
        calls += 1
        return [query]

    governed = GovernedAutoGenTool(
        FunctionTool(
            search_records,
            name="search_records",
            description="Search a synthetic record index.",
        ),
        "agent-b",
        checker=RecordingChecker(denied=True),  # type: ignore[arg-type]
    )

    with pytest.raises(GovernanceDeniedError, match="ACTION_BLOCKLISTED"):
        asyncio.run(governed.run_json({"query": "blocked"}, CancellationToken()))
    assert calls == 0
