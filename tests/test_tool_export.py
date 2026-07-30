import json
from pathlib import Path
from typing import ClassVar

import pytest
import yaml

from hlinor_registry import (
    ToolContractExportError,
    ToolContractValidationError,
    ToolGovernance,
    write_tool_contract,
)
from hlinor_registry.tool_contract import load_tool_contract
from hlinor_registry.tool_export import (
    _export_framework_tool_contract,
    _framework_tool,
)


def valid_contract() -> dict:
    return {
        "schema_version": "1.0",
        "type": "tool_contract",
        "id": "exported-tools",
        "name": "Exported Tools",
        "description": "Synthetic exported tools.",
        "version": "1.0.0",
        "tools": [
            {
                "id": "record.read",
                "action": "read_record",
                "description": "Read one record.",
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
        "metadata": {"owner": "Test Team", "source": "test"},
    }


class InputModel:
    @classmethod
    def model_json_schema(cls) -> dict:
        return {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        }


class FakeTool:
    name = "search"
    description = "Search a synthetic index."
    args_schema = InputModel


def export_fake(
    tools: list[object] | None = None,
    governance: dict[str, object] | None = None,
) -> dict:
    selected_tools = [FakeTool()] if tools is None else tools
    selected_governance = (
        {
            "search": ToolGovernance(
                read_only=True,
                destructive=False,
                idempotent=True,
                resource_patterns=("record/*",),
                effects=("database_read",),
            )
        }
        if governance is None
        else governance
    )

    def descriptor(tool: object):
        return _framework_tool(
            tool,
            framework="test-framework",
            schema_source=getattr(tool, "args_schema", None),
        )

    return _export_framework_tool_contract(
        selected_tools,
        framework="test-framework",
        contract_id="exported-tools",
        name="Exported Tools",
        description="Synthetic exported tools.",
        version="1.0.0",
        owner="Test Team",
        governance=selected_governance,  # type: ignore[arg-type]
        descriptor=descriptor,
        repository="https://github.com/example/tools",
        revision="test-revision",
    )


def test_governance_normalizes_sequences_to_immutable_tuples() -> None:
    config = ToolGovernance(
        read_only=True,
        destructive=False,
        idempotent=True,
        resource_patterns=["record/*"],  # type: ignore[arg-type]
        effects=["database_read"],  # type: ignore[arg-type]
    )

    assert config.resource_patterns == ("record/*",)
    assert config.effects == ("database_read",)


def test_framework_export_preserves_schema_defaults_without_execution() -> None:
    contract = export_fake()

    assert contract["tools"][0]["input_schema"]["additionalProperties"] is True
    assert contract["tools"][0]["action"] == "search"
    assert contract["metadata"] == {
        "owner": "Test Team",
        "source": "test-framework",
        "repository": "https://github.com/example/tools",
        "revision": "test-revision",
    }


def test_framework_export_sorts_tools_effects_and_resource_patterns() -> None:
    class WriteTool:
        name = "write"
        description = "Write a synthetic record."
        args_schema: ClassVar[dict] = {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        }

    contract = export_fake(
        tools=[WriteTool(), FakeTool()],
        governance={
            "search": ToolGovernance(
                read_only=True,
                destructive=False,
                idempotent=True,
                resource_patterns=("record/z/*", "record/a/*"),
                effects=("personal_data_access", "database_read"),
                tool_id="record.search",
            ),
            "write": ToolGovernance(
                read_only=False,
                destructive=False,
                idempotent=False,
                effects=("database_write",),
                tool_id="record.write",
            ),
        },
    )

    assert [tool["id"] for tool in contract["tools"]] == [
        "record.search",
        "record.write",
    ]
    assert contract["tools"][0]["effects"] == [
        "database_read",
        "personal_data_access",
    ]
    assert contract["tools"][0]["resource_patterns"] == [
        "record/a/*",
        "record/z/*",
    ]


def test_framework_export_uses_explicit_action_and_tool_id() -> None:
    contract = export_fake(
        governance={
            "search": ToolGovernance(
                read_only=True,
                destructive=False,
                idempotent=True,
                action="read_record",
                tool_id="record.search",
            )
        }
    )

    assert contract["tools"][0]["id"] == "record.search"
    assert contract["tools"][0]["action"] == "read_record"


def test_framework_export_uses_governed_wrapper_action_by_default() -> None:
    class GovernedFakeTool(FakeTool):
        action_name = "read_record"

    contract = export_fake(tools=[GovernedFakeTool()])

    assert contract["tools"][0]["action"] == "read_record"


@pytest.mark.parametrize(
    ("tools", "governance", "message"),
    [
        (
            [FakeTool()],
            {},
            "missing governance for: search",
        ),
        (
            [],
            {
                "removed": ToolGovernance(
                    read_only=True,
                    destructive=False,
                    idempotent=True,
                )
            },
            "governance references absent tools: removed",
        ),
        (
            [FakeTool(), FakeTool()],
            {
                "search": ToolGovernance(
                    read_only=True,
                    destructive=False,
                    idempotent=True,
                )
            },
            "tool names must be unique: search",
        ),
        (
            [FakeTool()],
            {"search": object()},
            "must be ToolGovernance",
        ),
    ],
)
def test_framework_export_refuses_ambiguous_configuration(
    tools: list[object],
    governance: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ToolContractExportError, match=message):
        export_fake(tools=tools, governance=governance)


@pytest.mark.parametrize(
    ("schema", "message"),
    [
        (None, "does not expose a supported"),
        ({"type": "string"}, "must have type 'object'"),
        ({"type": "object", "properties": []}, "properties must be an object"),
        (
            {"type": "object", "properties": {}, "required": "query"},
            "required must be an array",
        ),
        (
            {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": {},
            },
            "must use a boolean additionalProperties",
        ),
    ],
)
def test_framework_export_refuses_unusable_input_schemas(
    schema: object,
    message: str,
) -> None:
    class InvalidTool(FakeTool):
        args_schema = schema

    with pytest.raises(ToolContractExportError, match=message):
        export_fake(tools=[InvalidTool()])


def test_framework_export_validates_final_governance_claims() -> None:
    with pytest.raises(ToolContractValidationError, match="mutating effects"):
        export_fake(
            governance={
                "search": ToolGovernance(
                    read_only=True,
                    destructive=False,
                    idempotent=True,
                    effects=("database_write",),
                )
            }
        )


@pytest.mark.parametrize("suffix", [".yaml", ".yml", ".json"])
def test_writer_creates_valid_deterministic_contract(
    tmp_path: Path,
    suffix: str,
) -> None:
    path = write_tool_contract(valid_contract(), tmp_path / f"contract{suffix}")

    assert path.exists()
    assert load_tool_contract(path) == valid_contract()
    if suffix == ".json":
        assert json.loads(path.read_text(encoding="utf-8")) == valid_contract()
    else:
        assert yaml.safe_load(path.read_text(encoding="utf-8")) == valid_contract()


def test_writer_refuses_invalid_contract_before_replacing_output(
    tmp_path: Path,
) -> None:
    path = tmp_path / "contract.yaml"
    path.write_text("existing: content\n", encoding="utf-8")
    invalid = valid_contract()
    invalid["tools"][0]["action"] = "read:*"

    with pytest.raises(ToolContractValidationError):
        write_tool_contract(invalid, path)

    assert path.read_text(encoding="utf-8") == "existing: content\n"


def test_writer_requires_a_portable_contract_extension(tmp_path: Path) -> None:
    with pytest.raises(ToolContractExportError, match="output must use"):
        write_tool_contract(valid_contract(), tmp_path / "contract.txt")
