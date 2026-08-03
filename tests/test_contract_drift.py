import copy
import json
from pathlib import Path

import pytest
import yaml

from hlinor_registry.cli import main
from hlinor_registry.contract_drift import (
    check_contract_drift_files,
    compare_agent_contract,
    compare_tool_contracts,
)

AGENT_EXAMPLE = Path("examples/tool-contracts/customer-support-agent.yaml")
CONTRACT_EXAMPLE = Path("examples/tool-contracts/customer-support-tools.yaml")


def agent() -> dict:
    return {
        "id": "test-agent",
        "allowed_actions": ["read_record:record/*"],
        "blocked_actions": [],
    }


def tool(
    *,
    tool_id: str = "record.read",
    action: str = "read_record",
    resources: list[str] | None = None,
) -> dict:
    return {
        "id": tool_id,
        "action": action,
        "description": "Read one synthetic record.",
        "input_schema": {
            "type": "object",
            "properties": {
                "record_id": {"type": "string"},
                "fields": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["record_id"],
            "additionalProperties": False,
        },
        "resource_patterns": resources if resources is not None else ["record/*"],
        "effects": ["database_read"],
        "annotations": {
            "read_only": True,
            "destructive": False,
            "idempotent": True,
        },
    }


def contract(*tools: dict) -> dict:
    return {
        "schema_version": "1.0",
        "type": "tool_contract",
        "id": "test-tools",
        "name": "Test Tools",
        "description": "Synthetic contract for drift tests.",
        "version": "1.0.0",
        "tools": list(tools) if tools else [tool()],
        "metadata": {"owner": "Test Team", "source": "manual"},
    }


def write_yaml(path: Path, data: object) -> Path:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def finding_codes(report) -> list[str]:
    return [finding.code for finding in report.findings]


def test_matching_agent_and_contract_are_aligned() -> None:
    report = compare_agent_contract(agent(), contract())

    assert report.status == "aligned"
    assert report.findings == ()


def test_narrower_agent_permission_is_not_drift() -> None:
    declaration = agent()
    declaration["allowed_actions"] = ["read_record:record/customer-*"]

    assert compare_agent_contract(declaration, contract()).status == "aligned"


def test_blocked_only_tool_scope_is_intentionally_declared() -> None:
    declaration = agent()
    declaration["allowed_actions"] = []
    declaration["blocked_actions"] = ["read_record:record/private/*"]

    report = compare_agent_contract(
        declaration,
        contract(tool(resources=["record/private/*"])),
    )

    assert report.status == "aligned"


def test_bare_action_block_covers_all_scoped_capabilities_case_insensitively() -> None:
    declaration = agent()
    declaration["allowed_actions"] = []
    declaration["blocked_actions"] = ["READ_RECORD"]

    assert compare_agent_contract(declaration, contract()).status == "aligned"


def test_undeclared_tool_scope_is_reported() -> None:
    declaration = agent()
    declaration["allowed_actions"] = []

    report = compare_agent_contract(declaration, contract())

    assert finding_codes(report) == ["UNDECLARED_TOOL_SCOPE"]
    assert report.findings[0].symbol == "+"


def test_each_exported_resource_scope_must_be_declared() -> None:
    report = compare_agent_contract(
        agent(),
        contract(tool(resources=["record/*", "archive/*"])),
    )

    assert finding_codes(report) == ["UNDECLARED_TOOL_SCOPE"]
    assert "read_record:archive/*" in report.findings[0].message


def test_an_action_allowed_without_its_scope_is_named_as_one_mistake() -> None:
    """The two halves of this used to be reported as unrelated findings.

    A bare `read_record` covers no call the tool makes, and the tool is covered
    by no permission. Both are true, both were printed, and neither said they
    were the same sentence read from opposite ends. On a real agent that turned
    thirteen mistakes into twenty-six lines in two separate sections.
    """
    declaration = agent()
    declaration["allowed_actions"] = ["read_record"]

    report = compare_agent_contract(declaration, contract())

    assert finding_codes(report) == ["UNSCOPED_ALLOW_PERMISSION"]
    assert report.findings[0].symbol == "~"
    assert "read_record:record/*" in report.findings[0].message


def test_the_suggested_pattern_actually_resolves_the_finding() -> None:
    """The report tells the reader what to write. It has to be right.

    Advice that does not fix the problem is worse than no advice, so the
    suggestion is taken out of the message text and applied rather than
    assumed.
    """
    import re

    declaration = agent()
    declaration["allowed_actions"] = ["read_record"]
    contract_data = contract(tool(resources=["record/*", "archive/*"]))

    report = compare_agent_contract(declaration, contract_data)
    suggested = re.findall(r"'([^']+)'", report.findings[0].message.split("Write")[1])
    assert suggested, "the message carries no pattern to apply"

    declaration["allowed_actions"] = suggested
    assert compare_agent_contract(declaration, contract_data).status == "aligned", (
        f"applying {suggested} left the contract in drift"
    )


def test_a_scoped_permission_that_covers_nothing_is_still_stale() -> None:
    """The new code must not swallow the case it was carved out of."""
    declaration = agent()
    declaration["allowed_actions"] = ["read_record:nowhere/*"]

    assert "STALE_ALLOW_PERMISSION" in finding_codes(
        compare_agent_contract(declaration, contract())
    )


def test_stale_allow_and_block_permissions_are_reported() -> None:
    declaration = agent()
    declaration["allowed_actions"].append("send_email")
    declaration["blocked_actions"].append("delete_invoice")

    report = compare_agent_contract(declaration, contract())

    assert finding_codes(report) == [
        "STALE_ALLOW_PERMISSION",
        "STALE_BLOCK_PERMISSION",
    ]


def test_empty_contract_marks_every_permission_as_stale() -> None:
    declaration = agent()
    declaration["blocked_actions"] = ["delete_record"]
    empty_contract = contract()
    empty_contract["tools"] = []

    report = compare_agent_contract(declaration, empty_contract)

    assert finding_codes(report) == [
        "STALE_ALLOW_PERMISSION",
        "STALE_BLOCK_PERMISSION",
    ]


def test_agent_contract_report_is_stable_machine_readable_data() -> None:
    declaration = agent()
    declaration["allowed_actions"] = []

    data = compare_agent_contract(declaration, contract()).to_dict()

    assert data["schema_version"] == "1.0"
    assert data["mode"] == "agent-contract"
    assert data["status"] == "drift"
    assert data["summary"] == {
        "total_findings": 1,
        "by_code": {"UNDECLARED_TOOL_SCOPE": 1},
    }
    assert data["findings"][0]["severity"] == "error"


def test_equivalent_contract_order_is_not_drift() -> None:
    first = tool(tool_id="first")
    second = tool(tool_id="second", action="list_records")
    expected = contract(first, second)
    observed = copy.deepcopy(expected)
    observed["tools"].reverse()
    observed["tools"][1]["resource_patterns"] = ["record/b/*", "record/a/*"]
    expected["tools"][0]["resource_patterns"] = ["record/a/*", "record/b/*"]
    observed["tools"][1]["effects"] = ["personal_data_access", "database_read"]
    expected["tools"][0]["effects"] = ["database_read", "personal_data_access"]
    observed["tools"][1]["input_schema"]["required"] = ["fields", "record_id"]
    expected["tools"][0]["input_schema"]["required"] = ["record_id", "fields"]

    assert compare_tool_contracts(expected, observed).status == "aligned"


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (lambda data: data.update(id="other-tools"), "CONTRACT_ID_CHANGED"),
        (lambda data: data.update(version="2.0.0"), "CONTRACT_VERSION_CHANGED"),
        (
            lambda data: data["tools"][0].update(action="fetch_record"),
            "ACTION_CHANGED",
        ),
        (
            lambda data: data["tools"][0]["input_schema"]["properties"].update(
                record_id={"type": "integer"}
            ),
            "INPUT_SCHEMA_CHANGED",
        ),
        (
            lambda data: data["tools"][0].update(resource_patterns=["archive/*"]),
            "RESOURCE_SCOPE_CHANGED",
        ),
        (
            lambda data: data["tools"][0].update(effects=["cache_read"]),
            "EFFECTS_CHANGED",
        ),
        (
            lambda data: data["tools"][0]["annotations"].update(idempotent=False),
            "ANNOTATIONS_CHANGED",
        ),
    ],
)
def test_governance_shape_changes_are_reported(mutation, expected_code) -> None:
    expected = contract()
    observed = copy.deepcopy(expected)
    mutation(observed)

    assert expected_code in finding_codes(compare_tool_contracts(expected, observed))


def test_added_and_removed_tools_are_reported_by_stable_id() -> None:
    expected = contract(tool(tool_id="old"))
    observed = contract(tool(tool_id="new"))

    report = compare_tool_contracts(expected, observed)

    assert finding_codes(report) == ["TOOL_ADDED", "TOOL_REMOVED"]


def test_descriptions_and_metadata_do_not_create_governance_drift() -> None:
    expected = contract()
    observed = copy.deepcopy(expected)
    observed["description"] = "Updated documentation."
    observed["tools"][0]["description"] = "Updated tool documentation."
    observed["metadata"] = {"owner": "Another Team", "source": "exporter"}

    assert compare_tool_contracts(expected, observed).status == "aligned"


def test_repository_examples_pass_file_level_check() -> None:
    assert check_contract_drift_files(AGENT_EXAMPLE, CONTRACT_EXAMPLE).status == (
        "aligned"
    )


def test_cli_contract_check_returns_zero_for_aligned_inputs(
    capsys: pytest.CaptureFixture,
) -> None:
    exit_code = main(
        [
            "contract",
            "check",
            "--agent",
            str(AGENT_EXAMPLE),
            "--tools",
            str(CONTRACT_EXAMPLE),
        ]
    )

    assert exit_code == 0
    assert "are aligned" in capsys.readouterr().out


def test_cli_contract_check_returns_one_and_json_for_drift(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    declaration = yaml.safe_load(AGENT_EXAMPLE.read_text(encoding="utf-8"))
    declaration["allowed_actions"] = []
    declaration["blocked_actions"] = []
    agent_path = write_yaml(tmp_path / "agent.yaml", declaration)

    exit_code = main(
        [
            "contract",
            "check",
            "--agent",
            str(agent_path),
            "--tools",
            str(CONTRACT_EXAMPLE),
            "--format",
            "json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert output["status"] == "drift"
    assert output["summary"]["total_findings"] == 2


def test_cli_contract_diff_returns_zero_for_identical_contracts(
    capsys: pytest.CaptureFixture,
) -> None:
    exit_code = main(
        [
            "contract",
            "diff",
            "--expected",
            str(CONTRACT_EXAMPLE),
            "--observed",
            str(CONTRACT_EXAMPLE),
        ]
    )

    assert exit_code == 0
    assert "are aligned" in capsys.readouterr().out


def test_cli_contract_diff_returns_one_for_changed_contract(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    observed = yaml.safe_load(CONTRACT_EXAMPLE.read_text(encoding="utf-8"))
    observed["version"] = "1.1.0"
    observed_path = write_yaml(tmp_path / "observed.yaml", observed)

    exit_code = main(
        [
            "contract",
            "diff",
            "--expected",
            str(CONTRACT_EXAMPLE),
            "--observed",
            str(observed_path),
        ]
    )

    assert exit_code == 1
    assert "CONTRACT_VERSION_CHANGED" in capsys.readouterr().out


@pytest.mark.parametrize(
    "arguments",
    [
        [
            "contract",
            "check",
            "--agent",
            "missing-agent.yaml",
            "--tools",
            str(CONTRACT_EXAMPLE),
        ],
        [
            "contract",
            "diff",
            "--expected",
            str(CONTRACT_EXAMPLE),
            "--observed",
            "missing-contract.yaml",
        ],
    ],
)
def test_cli_contract_commands_return_two_for_invalid_input(
    arguments: list[str],
    capsys: pytest.CaptureFixture,
) -> None:
    assert main(arguments) == 2
    assert capsys.readouterr().err.startswith("Error:")
