import json
from importlib.resources import files
from pathlib import Path

import pytest
import yaml

from hlinor_registry.cli import main
from hlinor_registry.tool_contract import (
    ToolContractValidationError,
    load_tool_contract,
    tool_contract_errors,
    tool_contract_schema,
    validate_tool_contract,
)

EXAMPLE = Path("examples/tool-contracts/customer-support-tools.yaml")


def valid_contract() -> dict:
    return {
        "schema_version": "1.0",
        "type": "tool_contract",
        "id": "test-tools",
        "name": "Test Tools",
        "description": "Synthetic tools for validation tests.",
        "version": "1.0.0",
        "tools": [
            {
                "id": "record.read",
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
        "metadata": {"owner": "Test Team", "source": "manual"},
    }


def write_yaml(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "tool-contract.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_repository_example_is_valid() -> None:
    assert validate_tool_contract(EXAMPLE) == []


def test_cli_validates_tool_contract(capsys: pytest.CaptureFixture) -> None:
    assert main(["validate-tool-contract", str(EXAMPLE)]) == 0
    assert capsys.readouterr().out == "Tool contract is valid.\n"


def test_loader_accepts_json_and_returns_the_complete_contract(tmp_path: Path) -> None:
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(valid_contract()), encoding="utf-8")

    loaded = load_tool_contract(path)

    assert loaded["id"] == "test-tools"
    assert loaded["tools"][0]["input_schema"]["required"] == ["record_id"]


def test_schema_is_bundled_with_the_installable_package() -> None:
    schema_resource = files("hlinor_registry.schemas").joinpath(
        "tool-contract.schema.json"
    )
    assert schema_resource.is_file()
    assert tool_contract_schema()["$schema"].endswith("draft/2020-12/schema")


def test_schema_callers_cannot_mutate_future_validation() -> None:
    schema = tool_contract_schema()
    schema["properties"]["type"]["const"] = "agent"

    assert tool_contract_errors(valid_contract()) == []


def test_empty_tool_set_is_a_valid_complete_contract() -> None:
    contract = valid_contract()
    contract["tools"] = []

    assert tool_contract_errors(contract) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "2.0"),
        ("type", "agent"),
        ("version", "latest"),
    ],
)
def test_root_contract_identity_is_strict(
    field: str, value: object, tmp_path: Path
) -> None:
    contract = valid_contract()
    contract[field] = value

    errors = validate_tool_contract(write_yaml(tmp_path, contract))

    assert any(field in error for error in errors)


def test_unknown_fields_are_rejected(tmp_path: Path) -> None:
    contract = valid_contract()
    contract["runtime_secret"] = "must-not-be-ignored"

    errors = validate_tool_contract(write_yaml(tmp_path, contract))

    assert any("Additional properties are not allowed" in error for error in errors)


def test_metadata_repository_must_be_a_uri() -> None:
    contract = valid_contract()
    contract["metadata"]["repository"] = "not a uri"

    errors = tool_contract_errors(contract)

    assert any("metadata.repository" in error for error in errors)


def test_duplicate_tool_ids_are_rejected_case_insensitively() -> None:
    contract = valid_contract()
    duplicate = dict(contract["tools"][0])
    duplicate["id"] = "Record.Read"
    duplicate["action"] = "read_another_record"
    contract["tools"].append(duplicate)

    errors = tool_contract_errors(contract)

    assert any("collides with tools[0].id" in error for error in errors)


def test_actions_that_differ_only_by_case_are_rejected() -> None:
    contract = valid_contract()
    second = dict(contract["tools"][0])
    second["id"] = "record.read-secondary"
    second["action"] = "READ_RECORD"
    contract["tools"].append(second)

    errors = tool_contract_errors(contract)

    assert any("collides with tools[0].action" in error for error in errors)


def test_multiple_tools_may_intentionally_share_one_action() -> None:
    contract = valid_contract()
    second = dict(contract["tools"][0])
    second["id"] = "record.read-secondary"
    contract["tools"].append(second)

    assert tool_contract_errors(contract) == []


def test_action_names_are_concrete_not_patterns() -> None:
    contract = valid_contract()
    contract["tools"][0]["action"] = "read_*"

    errors = tool_contract_errors(contract)

    assert any("tools[0].action" in error for error in errors)


def test_resource_patterns_use_the_registry_pattern_vocabulary() -> None:
    contract = valid_contract()
    contract["tools"][0]["resource_patterns"] = ["record/**"]

    errors = tool_contract_errors(contract)

    assert any("unsupported recursive wildcards" in error for error in errors)


def test_required_arguments_must_exist_in_properties() -> None:
    contract = valid_contract()
    contract["tools"][0]["input_schema"]["required"] = ["missing"]

    errors = tool_contract_errors(contract)

    assert any("'missing' is not declared in properties" in error for error in errors)


def test_nested_input_must_be_a_valid_json_schema() -> None:
    contract = valid_contract()
    contract["tools"][0]["input_schema"]["properties"]["record_id"] = {
        "type": "not-a-json-schema-type"
    }

    errors = tool_contract_errors(contract)

    assert any("not-a-json-schema-type" in error for error in errors)


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_non_finite_yaml_numbers_are_rejected(value: float) -> None:
    contract = valid_contract()
    contract["tools"][0]["input_schema"]["properties"]["score"] = {
        "type": "number",
        "default": value,
    }

    errors = tool_contract_errors(contract)

    assert any("non-finite numbers are not valid JSON" in error for error in errors)


def test_yaml_dates_are_rejected_instead_of_becoming_runtime_objects(
    tmp_path: Path,
) -> None:
    content = yaml.safe_dump(valid_contract(), sort_keys=False)
    path = tmp_path / "dated.yaml"
    path.write_text(content + "unexpected_date: 2026-07-30\n", encoding="utf-8")

    errors = validate_tool_contract(path)

    assert any("unsupported JSON value type: date" in error for error in errors)


def test_read_only_cannot_hide_a_mutating_effect() -> None:
    contract = valid_contract()
    contract["tools"][0]["effects"] = ["database_write"]

    errors = tool_contract_errors(contract)

    assert any("cannot be true with mutating effects" in error for error in errors)


def test_destructive_requires_a_mutating_effect() -> None:
    contract = valid_contract()
    contract["tools"][0]["annotations"] = {
        "read_only": False,
        "destructive": True,
        "idempotent": False,
    }

    errors = tool_contract_errors(contract)

    assert any("requires at least one mutating effect" in error for error in errors)


def test_fail_closed_loader_raises_with_all_validation_errors(
    tmp_path: Path,
) -> None:
    contract = valid_contract()
    contract["tools"][0]["action"] = "read:*"
    path = write_yaml(tmp_path, contract)

    with pytest.raises(ToolContractValidationError) as captured:
        load_tool_contract(path)

    assert captured.value.errors
    assert "tools[0].action" in str(captured.value)
