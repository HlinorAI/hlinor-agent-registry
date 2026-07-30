"""Tests for framework-neutral custom Python Tool Contract export."""

from typing import Any

import pytest

from hlinor_registry import (
    CustomToolDescriptor,
    ToolContractExportError,
    ToolGovernance,
)
from hlinor_registry.integrations.custom import export_custom_tool_contract
from hlinor_registry.tool_contract import tool_contract_errors


def input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"record_id": {"type": "string"}},
        "required": ["record_id"],
        "additionalProperties": False,
    }


def governance() -> dict[str, ToolGovernance]:
    return {
        "read_record": ToolGovernance(
            read_only=True,
            destructive=False,
            idempotent=True,
            resource_patterns=("record/*",),
            effects=("database_read",),
        )
    }


def export(tools: list[CustomToolDescriptor]) -> dict[str, Any]:
    return export_custom_tool_contract(
        tools,
        contract_id="custom-tools",
        name="Custom Tools",
        description="Synthetic custom Python tools.",
        version="1.0.0",
        owner="Test Team",
        governance=governance(),
    )


def test_custom_export_uses_callable_identity_without_invocation() -> None:
    calls = 0

    def read_record(record_id: str) -> dict[str, str]:
        """Read one synthetic record."""
        nonlocal calls
        calls += 1
        return {"id": record_id}

    contract = export(
        [CustomToolDescriptor(callable=read_record, input_schema=input_schema())]
    )

    assert calls == 0
    assert tool_contract_errors(contract) == []
    assert contract["metadata"]["source"] == "custom-python"
    assert contract["tools"][0]["id"] == "read_record"
    assert contract["tools"][0]["action"] == "read_record"
    assert contract["tools"][0]["description"] == "Read one synthetic record."


def test_custom_export_accepts_explicit_public_names() -> None:
    def implementation(value: str) -> str:
        return value

    contract = export_custom_tool_contract(
        [
            CustomToolDescriptor(
                callable=implementation,
                input_schema=input_schema(),
                name="read_record",
                description="Read one synthetic record.",
                action_name="record.read",
            )
        ],
        contract_id="custom-tools",
        name="Custom Tools",
        description="Synthetic custom Python tools.",
        version="1.0.0",
        owner="Test Team",
        governance={
            "read_record": ToolGovernance(
                read_only=True,
                destructive=False,
                idempotent=True,
                tool_id="record.reader",
            )
        },
    )

    assert contract["tools"][0]["id"] == "record.reader"
    assert contract["tools"][0]["action"] == "record.read"


def test_custom_export_copies_input_schema() -> None:
    schema = input_schema()

    def read_record(record_id: str) -> dict[str, str]:
        """Read one synthetic record."""
        return {"id": record_id}

    contract = export([CustomToolDescriptor(callable=read_record, input_schema=schema)])
    schema["properties"]["record_id"]["type"] = "integer"

    assert contract["tools"][0]["input_schema"]["properties"]["record_id"] == {
        "type": "string"
    }


def test_custom_export_requires_a_description() -> None:
    def read_record(record_id: str) -> dict[str, str]:
        return {"id": record_id}

    with pytest.raises(ToolContractExportError, match="description"):
        export(
            [CustomToolDescriptor(callable=read_record, input_schema=input_schema())]
        )


def test_custom_export_rejects_non_descriptors() -> None:
    with pytest.raises(ToolContractExportError, match="CustomToolDescriptor"):
        export_custom_tool_contract(
            [object()],  # type: ignore[list-item]
            contract_id="custom-tools",
            name="Custom Tools",
            description="Synthetic custom Python tools.",
            version="1.0.0",
            owner="Test Team",
            governance={},
        )


def test_custom_export_rejects_non_callable_identity() -> None:
    descriptor = CustomToolDescriptor(
        callable=object(),  # type: ignore[arg-type]
        input_schema=input_schema(),
        name="read_record",
        description="Read one synthetic record.",
    )

    with pytest.raises(ToolContractExportError, match="must be callable"):
        export([descriptor])
