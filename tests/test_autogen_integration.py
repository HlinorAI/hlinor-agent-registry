"""Compatibility tests for Microsoft AutoGen Tool Contract export."""

from typing import Any, ClassVar

import pytest

pytest.importorskip("autogen_core")

from autogen_core.tools import FunctionTool

from hlinor_registry import ToolContractExportError, ToolGovernance
from hlinor_registry.integrations.autogen import export_autogen_tool_contract
from hlinor_registry.tool_contract import tool_contract_errors


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
