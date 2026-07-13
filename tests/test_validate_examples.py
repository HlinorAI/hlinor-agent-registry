from pathlib import Path
import sys

from hlinor_registry.cli import main
from hlinor_registry.validator import (
    validate_agent,
    validate_department,
    validate_policy,
    validate_production_action_boundary_example,
    validate_registry_file,
    validate_runtime_example,
    validate_skill,
    validate_validator,
    validate_lifecycle_map,
    validate_lifecycle_receipt,
    validate_lifecycle_schema,
)

def test_search_agent_example_is_valid():
    errors = validate_agent("examples/search-agent.yaml")
    assert errors == []

def test_validate_command_remains_backward_compatible(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "hlinor-registry",
        "validate",
        "examples/search-agent.yaml",
    ])

    exit_code = main()

    assert exit_code == 0
    assert capsys.readouterr().out == "Registry file is valid.\n"

def test_department_schema_example_is_valid():
    errors = validate_department("registry/schema/department.yaml")
    assert errors == []

def test_policy_schema_example_is_valid():
    errors = validate_policy("registry/schema/policy.yaml")
    assert errors == []

def test_skill_schema_example_is_valid():
    errors = validate_skill("registry/schema/skill.yaml")
    assert errors == []

def test_validator_schema_example_is_valid():
    errors = validate_validator("registry/schema/validator.yaml")
    assert errors == []

def test_wrong_type_for_list_field_produces_error(tmp_path):
    path = tmp_path / "skill.yaml"
    path.write_text(
        "\n".join([
            "id: web-search",
            "name: Web Search",
            "description: Searches for businesses.",
            "inputs: query",
            "outputs:",
            "  - candidates",
            "required_permissions:",
            "  - internet-access",
            "",
        ]),
        encoding="utf-8",
    )

    errors = validate_skill(path)

    assert "skill: Field must be a list: inputs" in errors

def test_validate_registry_file_dispatches_correctly():
    errors = validate_registry_file("department", "registry/schema/department.yaml")
    assert errors == []

def test_validate_registry_file_unsupported_entity_type():
    errors = validate_registry_file("unknown", "registry/schema/department.yaml")
    assert errors == ["Unsupported entity type: unknown"]

def test_inspect_output_is_deterministic(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "hlinor-registry",
        "inspect",
        "registry/schema/agent.yaml",
    ])

    exit_code = main()

    assert exit_code == 0
    assert capsys.readouterr().out == (
        "Path: registry/schema/agent.yaml\n"
        "id: search-agent\n"
        "name: Search Agent\n"
        "keys: allowed_actions, blocked_actions, department, description, id, "
        "name, policies, skills, validators\n"
    )

def test_runtime_receipt_examples_are_valid():
    paths = list(Path("examples/runtime").glob("*.yaml"))
    assert paths

    for path in paths:
        errors = validate_runtime_example(path)
        assert errors == []


def test_production_action_boundary_example_is_valid():
    errors = validate_production_action_boundary_example(
        "examples/control-loops/production-action-boundary.yaml"
    )
    assert errors == []



def test_lifecycle_map_example_is_valid():
    errors = validate_lifecycle_map("examples/lifecycle/generic-agent-lifecycle-map.yaml")
    assert errors == []


def test_lifecycle_receipt_example_is_valid():
    errors = validate_lifecycle_receipt("examples/lifecycle/generic-lifecycle-receipt.yaml")
    assert errors == []


def test_lifecycle_schema_files_are_valid():
    paths = sorted(Path("registry/schema").glob("lifecycle-*.schema.yaml"))
    assert paths

    for path in paths:
        errors = validate_lifecycle_schema(path)
        assert errors == []


def test_lifecycle_receipt_invalid_mode_produces_error(tmp_path):
    path = tmp_path / "receipt.yaml"
    path.write_text(
        "\n".join([
            "task_id: test-task",
            "lifecycle_mode: wrong",
            "input_refs: []",
            "output_refs: []",
            "changed_files: []",
            "checks_run: []",
            "risks_detected: []",
            "next_recommended_mode: sweeper",
            "stop_reason: completed",
            "secrets_touched: false",
            "production_behavior_changed: false",
            "external_messages_sent: false",
            "services_restarted: false",
            "",
        ]),
        encoding="utf-8",
    )

    errors = validate_lifecycle_receipt(path)

    assert "lifecycle_receipt: Invalid lifecycle_mode: wrong" in errors


def test_validate_lifecycle_map_cli_command(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "hlinor-registry",
        "validate-lifecycle-map",
        "examples/lifecycle/generic-agent-lifecycle-map.yaml",
    ])

    exit_code = main()

    assert exit_code == 0
    assert capsys.readouterr().out == "Lifecycle map is valid.\n"
