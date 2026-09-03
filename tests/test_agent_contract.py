from pathlib import Path

import yaml

from hlinor_registry.agent_contract import (
    check_agent_contract_files,
    compare_agent_contract_compatibility,
    load_agent_contract,
    validate_agent_contract,
    validate_agent_contract_data,
)
from hlinor_registry.cli import EXIT_DENIED, main

CONTRACT_EXAMPLE = Path("examples/agent-contract.yaml")


def _agent() -> dict:
    return {
        "id": "search-agent",
        "policies": ["no-stale-data", "no-hardcoded-locations"],
        "allowed_actions": ["search", "classify", "score"],
        "blocked_actions": ["send_email", "modify_external_records"],
    }


def _tool_contract() -> dict:
    def declared_tool(tool_id: str, action: str, *, destructive: bool = False) -> dict:
        return {
            "id": tool_id,
            "action": action,
            "description": f"Synthetic {action} tool.",
            "input_schema": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            "resource_patterns": [],
            "effects": ["external_system_change"] if destructive else ["database_read"],
            "annotations": {
                "read_only": not destructive,
                "destructive": destructive,
                "idempotent": not destructive,
            },
        }

    return {
        "schema_version": "1.0",
        "type": "tool_contract",
        "id": "search-tools",
        "name": "Search Tools",
        "description": "Synthetic tools for Agent Contract tests.",
        "version": "1.0.0",
        "tools": [
            declared_tool("search.web", "search"),
            declared_tool("classify.local", "classify"),
            declared_tool("score.local", "score"),
            declared_tool("email.send", "send_email", destructive=True),
            declared_tool(
                "records.modify", "modify_external_records", destructive=True
            ),
        ],
        "metadata": {"owner": "Synthetic Test Team", "source": "test"},
    }


def test_public_example_has_a_complete_contract() -> None:
    assert validate_agent_contract(CONTRACT_EXAMPLE) == []


def test_missing_required_field_fails_closed() -> None:
    data = load_agent_contract(CONTRACT_EXAMPLE)
    del data["failure_mode"]

    errors = validate_agent_contract_data(data)

    assert "agent_contract: Missing required field: failure_mode" in errors


def test_approval_requires_action_and_approver() -> None:
    data = load_agent_contract(CONTRACT_EXAMPLE)
    data["approval_required"] = [{"action": "publish", "approver": ""}]

    errors = validate_agent_contract_data(data)

    assert (
        "agent_contract: Field must be a non-empty string: approval_required[0].approver"
        in errors
    )


def test_compatibility_is_aligned_without_creating_authority_state() -> None:
    contract = load_agent_contract(CONTRACT_EXAMPLE)
    permissions = contract["tool_permissions"]
    permissions["allowed_tools"] = ["search.web", "classify.local", "score.local"]
    permissions["disallowed_tools"] = ["email.send", "records.modify"]

    report = compare_agent_contract_compatibility(contract, _agent(), _tool_contract())

    assert report.status == "aligned"
    assert report.findings == ()


def test_policy_and_agent_authority_drift_is_reported() -> None:
    contract = load_agent_contract(CONTRACT_EXAMPLE)
    declaration = _agent()
    declaration["policies"] = ["different-policy"]
    declaration["allowed_actions"] = ["search"]

    report = compare_agent_contract_compatibility(contract, declaration)
    codes = {finding.code for finding in report.findings}

    assert "POLICY_LINK_MISMATCH" in codes
    assert "AUTONOMOUS_ACTION_NOT_ALLOWED" in codes


def test_unmodeled_action_level_is_reported() -> None:
    contract = load_agent_contract(CONTRACT_EXAMPLE)
    contract["action_levels"].append(
        {
            "action": "publish",
            "level": "APPROVAL_REQUIRED",
            "scope": "external-site",
        }
    )

    report = compare_agent_contract_compatibility(contract, _agent())
    codes = {finding.code for finding in report.findings}

    assert "UNMODELED_ACTION_LEVEL" in codes
    assert "APPROVAL_LEVEL_NOT_DECLARED" in codes


def test_file_check_loads_and_validates_all_three_contracts(tmp_path: Path) -> None:
    contract_path = tmp_path / "agent-contract.yaml"
    tools_path = tmp_path / "tools.yaml"
    contract_path.write_text(
        CONTRACT_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8"
    )
    tools_path.write_text(yaml.safe_dump(_tool_contract()), encoding="utf-8")

    report = check_agent_contract_files(
        contract_path,
        Path("examples/search-agent.yaml"),
        tools_path,
    )

    assert report.status == "aligned"


def test_cli_validates_contract_and_reports_compatibility_drift(capsys) -> None:
    assert main(["validate-agent-contract", str(CONTRACT_EXAMPLE)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "contract",
                "verify-agent",
                "--contract",
                str(CONTRACT_EXAMPLE),
                "--agent",
                "examples/search-agent.yaml",
                "--tools",
                "examples/tool-contracts/customer-support-tools.yaml",
                "--format",
                "json",
            ]
        )
        == EXIT_DENIED
    )
    parsed = yaml.safe_load(capsys.readouterr().out)
    assert parsed["mode"] == "agent-contract-compatibility"
    assert parsed["status"] == "drift"
