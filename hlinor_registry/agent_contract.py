"""Portable, fail-closed Agent Contract validation and compatibility checks.

An Agent Contract is the human- and machine-readable boundary around one
agent declaration.  It is intentionally stateless: this module validates
files and compares declarations, but it does not store authority, approvals,
identities, or runtime state.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ._limits import MAX_SOURCE_BYTES, read_text_capped
from ._matching import pattern_errors, patterns_can_overlap

AGENT_CONTRACT_SCHEMA_VERSION = "1.0"
AGENT_CONTRACT_TYPE = "agent_contract"
ACTION_LEVELS = {"READ", "DRAFT", "EXECUTE", "APPROVAL_REQUIRED"}

REQUIRED_AGENT_CONTRACT_FIELDS = [
    "id",
    "version",
    "agent_id",
    "owner",
    "purpose",
    "allowed_goals",
    "out_of_scope",
    "action_levels",
    "autonomous_actions",
    "approval_required",
    "forbidden_actions",
    "stop_conditions",
    "data_access",
    "tool_permissions",
    "policy_ids",
    "audit_requirements",
    "versioning",
    "failure_mode",
]

_REQUIRED_DATA_ACCESS_FIELDS = [
    "readable",
    "writable",
    "retention",
    "sensitive_data_handling",
]
_REQUIRED_TOOL_PERMISSION_FIELDS = ["allowed_tools", "disallowed_tools"]
_REQUIRED_FAILURE_MODE_FIELDS = [
    "on_policy_failure",
    "on_approval_failure",
    "on_audit_failure",
    "on_external_uncertainty",
    "draft_approval_execution",
]


class AgentContractInputError(ValueError):
    """Raised when compatibility cannot be evaluated from invalid inputs."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("Invalid Agent Contract input: " + "; ".join(self.errors))


@dataclass(frozen=True)
class AgentContractFinding:
    """One mismatch between the first-class contract and its dependencies."""

    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": "error",
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True)
class AgentContractCompatibilityReport:
    """Deterministic result of a contract/declaration/tool comparison."""

    agent_contract_id: str
    agent_id: str
    tool_contract_id: str | None
    findings: tuple[AgentContractFinding, ...] = ()

    @property
    def status(self) -> str:
        return "drift" if self.findings else "aligned"

    def to_dict(self) -> dict[str, object]:
        by_code: dict[str, int] = {}
        for finding in self.findings:
            by_code[finding.code] = by_code.get(finding.code, 0) + 1
        return {
            "schema_version": AGENT_CONTRACT_SCHEMA_VERSION,
            "mode": "agent-contract-compatibility",
            "status": self.status,
            "subjects": {
                "agent_contract_id": self.agent_contract_id,
                "agent_id": self.agent_id,
                "tool_contract_id": self.tool_contract_id,
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_code": dict(sorted(by_code.items())),
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _path_text(path: Sequence[object]) -> str:
    rendered = ""
    for part in path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += ("." if rendered else "") + str(part)
    return rendered or "<root>"


def _non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _required_errors(
    data: Mapping[str, Any], fields: Sequence[str], prefix: str
) -> list[str]:
    return [
        f"{prefix}: Missing required field: {field}"
        for field in fields
        if field not in data
    ]


def _string_errors(value: object, path: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, str):
        return [f"agent_contract: Field must be a string: {path}"]
    if not allow_empty and not value.strip():
        return [f"agent_contract: Field must be a non-empty string: {path}"]
    return []


def _string_list_errors(
    value: object, path: str, *, non_empty: bool = False
) -> list[str]:
    if not isinstance(value, list):
        return [f"agent_contract: Field must be a list: {path}"]
    errors: list[str] = []
    if non_empty and not value:
        errors.append(f"agent_contract: List must not be empty: {path}")
    for index, item in enumerate(value):
        errors.extend(_string_errors(item, f"{path}[{index}]"))
    return errors


def _pattern_list_errors(value: object, path: str) -> list[str]:
    errors = _string_list_errors(value, path)
    if not isinstance(value, list):
        return errors
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            continue
        for problem in pattern_errors(item):
            errors.append(
                f"agent_contract: Invalid action in {path}[{index}]: {problem}"
            )
    return errors


def validate_agent_contract_data(data: object) -> list[str]:
    """Validate one Agent Contract mapping without consulting external state."""
    if not isinstance(data, Mapping):
        return ["agent_contract: YAML root must be an object"]

    errors = _required_errors(data, REQUIRED_AGENT_CONTRACT_FIELDS, "agent_contract")

    for field in ["id", "version", "agent_id", "owner", "purpose"]:
        if field in data:
            errors.extend(_string_errors(data[field], field))

    if "type" in data and data["type"] != AGENT_CONTRACT_TYPE:
        errors.append(f"agent_contract: Field must equal {AGENT_CONTRACT_TYPE}: type")
    if (
        "schema_version" in data
        and data["schema_version"] != AGENT_CONTRACT_SCHEMA_VERSION
    ):
        errors.append(
            "agent_contract: Unsupported schema_version: "
            f"{data['schema_version']!r}; expected {AGENT_CONTRACT_SCHEMA_VERSION!r}"
        )

    for field in [
        "allowed_goals",
        "out_of_scope",
        "stop_conditions",
        "audit_requirements",
        "versioning",
    ]:
        if field in data:
            errors.extend(_string_list_errors(data[field], field, non_empty=True))
    errors.extend(
        _pattern_list_errors(data.get("autonomous_actions"), "autonomous_actions")
    )
    errors.extend(
        _pattern_list_errors(data.get("forbidden_actions"), "forbidden_actions")
    )

    approval_required = data.get("approval_required")
    if not isinstance(approval_required, list):
        errors.append("agent_contract: Field must be a list: approval_required")
    else:
        for index, item in enumerate(approval_required):
            path = f"approval_required[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"agent_contract: Approval must be an object: {path}")
                continue
            for field in ["action", "approver"]:
                if field not in item:
                    errors.append(
                        f"agent_contract: {path}: Missing required field: {field}"
                    )
                else:
                    errors.extend(_string_errors(item[field], f"{path}.{field}"))
            action = item.get("action")
            if isinstance(action, str) and action.strip():
                for problem in pattern_errors(action):
                    errors.append(
                        f"agent_contract: Invalid action in {path}.action: {problem}"
                    )

    action_levels = data.get("action_levels")
    if not isinstance(action_levels, list):
        errors.append("agent_contract: Field must be a list: action_levels")
    elif not action_levels:
        errors.append("agent_contract: List must not be empty: action_levels")
    else:
        seen_actions: set[tuple[str, str]] = set()
        for index, item in enumerate(action_levels):
            path = f"action_levels[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"agent_contract: Action level must be an object: {path}")
                continue
            for field in ["action", "level", "scope"]:
                if field not in item:
                    errors.append(
                        f"agent_contract: {path}: Missing required field: {field}"
                    )
            if "action" in item:
                errors.extend(_string_errors(item["action"], f"{path}.action"))
                if isinstance(item["action"], str) and item["action"].strip():
                    for problem in pattern_errors(item["action"]):
                        errors.append(
                            f"agent_contract: Invalid action in {path}.action: {problem}"
                        )
            if "level" in item and item["level"] not in ACTION_LEVELS:
                errors.append(f"agent_contract: Invalid level: {path}.level")
            if "scope" in item:
                errors.extend(_string_errors(item["scope"], f"{path}.scope"))
            if "notes" in item:
                errors.extend(_string_errors(item["notes"], f"{path}.notes"))
            action = item.get("action")
            scope = item.get("scope")
            if (
                isinstance(action, str)
                and isinstance(scope, str)
                and action.strip()
                and scope.strip()
            ):
                key = (action.casefold(), scope.casefold())
                if key in seen_actions:
                    errors.append(
                        f"agent_contract: Duplicate action level: {path}.action"
                    )
                seen_actions.add(key)

    data_access = data.get("data_access")
    if not isinstance(data_access, Mapping):
        errors.append("agent_contract: Field must be an object: data_access")
    else:
        errors.extend(
            _required_errors(
                data_access, _REQUIRED_DATA_ACCESS_FIELDS, "agent_contract.data_access"
            )
        )
        for field in ["readable", "writable"]:
            if field in data_access:
                errors.extend(
                    _string_list_errors(data_access[field], f"data_access.{field}")
                )
        for field in ["retention", "sensitive_data_handling"]:
            if field in data_access:
                errors.extend(
                    _string_errors(data_access[field], f"data_access.{field}")
                )

    tool_permissions = data.get("tool_permissions")
    if not isinstance(tool_permissions, Mapping):
        errors.append("agent_contract: Field must be an object: tool_permissions")
    else:
        errors.extend(
            _required_errors(
                tool_permissions,
                _REQUIRED_TOOL_PERMISSION_FIELDS,
                "agent_contract.tool_permissions",
            )
        )
        for field in _REQUIRED_TOOL_PERMISSION_FIELDS:
            if field in tool_permissions:
                errors.extend(
                    _string_list_errors(
                        tool_permissions[field], f"tool_permissions.{field}"
                    )
                )

    if "policy_ids" in data:
        errors.extend(
            _string_list_errors(data["policy_ids"], "policy_ids", non_empty=True)
        )

    failure_mode = data.get("failure_mode")
    if not isinstance(failure_mode, Mapping):
        errors.append("agent_contract: Field must be an object: failure_mode")
    else:
        errors.extend(
            _required_errors(
                failure_mode,
                _REQUIRED_FAILURE_MODE_FIELDS,
                "agent_contract.failure_mode",
            )
        )
        for field in _REQUIRED_FAILURE_MODE_FIELDS:
            if field in failure_mode:
                errors.extend(
                    _string_errors(failure_mode[field], f"failure_mode.{field}")
                )

    return errors


def load_agent_contract(path: str | Path) -> dict[str, Any]:
    """Load an Agent Contract YAML document with the repository size limit."""
    source_path = Path(path)
    if not source_path.exists():
        raise FileNotFoundError(f"File not found: {source_path}")
    data = yaml.safe_load(
        read_text_capped(source_path, MAX_SOURCE_BYTES, "Agent Contract")
    )
    if not isinstance(data, dict):
        raise TypeError("YAML root must be an object")
    return data


def validate_agent_contract(path: str | Path) -> list[str]:
    """Validate one Agent Contract YAML file."""
    return validate_agent_contract_data(load_agent_contract(path))


def _finding(code: str, path: str, message: str) -> AgentContractFinding:
    return AgentContractFinding(code=code, path=path, message=message)


def _actions(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _approval_actions(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        item["action"]
        for item in value
        if isinstance(item, Mapping) and isinstance(item.get("action"), str)
    )


def _overlaps_any(pattern: str, patterns: Sequence[str]) -> bool:
    return any(
        patterns_can_overlap(pattern.casefold(), candidate.casefold())
        for candidate in patterns
    )


def compare_agent_contract_compatibility(
    agent_contract: Mapping[str, Any],
    agent: Mapping[str, Any],
    tool_contract: Mapping[str, Any] | None = None,
) -> AgentContractCompatibilityReport:
    """Cross-check an Agent Contract against an agent and optional Tool Contract.

    This is a comparison only.  The existing agent declaration and Tool
    Contract remain the inputs supplied by the caller; no source becomes an
    authority store by being passed here.
    """
    contract_errors = validate_agent_contract_data(agent_contract)
    if contract_errors:
        raise AgentContractInputError(contract_errors)

    agent_id = agent.get("id")
    contract_agent_id = agent_contract["agent_id"]
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise AgentContractInputError(["agent: missing non-empty id"])

    findings: list[AgentContractFinding] = []
    if contract_agent_id != agent_id:
        findings.append(
            _finding(
                "AGENT_ID_MISMATCH",
                "agent_id",
                f"Agent Contract names '{contract_agent_id}', but the agent declaration is '{agent_id}'.",
            )
        )

    declared_policies = _actions(agent.get("policies"))
    contract_policies = _actions(agent_contract.get("policy_ids"))
    if set(declared_policies) != set(contract_policies):
        findings.append(
            _finding(
                "POLICY_LINK_MISMATCH",
                "policy_ids",
                f"Agent Contract policies {sorted(contract_policies)!r} do not equal agent declaration policies {sorted(declared_policies)!r}.",
            )
        )

    allowed = _actions(agent.get("allowed_actions"))
    blocked = _actions(agent.get("blocked_actions"))
    autonomous = _actions(agent_contract.get("autonomous_actions"))
    approvals = _approval_actions(agent_contract.get("approval_required"))
    forbidden = _actions(agent_contract.get("forbidden_actions"))

    for index, action in enumerate(autonomous):
        if not _overlaps_any(action, allowed) or _overlaps_any(action, blocked):
            findings.append(
                _finding(
                    "AUTONOMOUS_ACTION_NOT_ALLOWED",
                    f"autonomous_actions[{index}]",
                    f"Autonomous action '{action}' is not allowed by the agent declaration or overlaps a blocked action.",
                )
            )
    for index, action in enumerate(approvals):
        if not _overlaps_any(action, allowed) or _overlaps_any(action, blocked):
            findings.append(
                _finding(
                    "APPROVAL_ACTION_NOT_ALLOWED",
                    f"approval_required[{index}].action",
                    f"Approval-required action '{action}' is not allowed by the agent declaration or overlaps a blocked action.",
                )
            )
    for index, action in enumerate(forbidden):
        if not _overlaps_any(action, blocked) or _overlaps_any(action, allowed):
            findings.append(
                _finding(
                    "FORBIDDEN_ACTION_NOT_BLOCKED",
                    f"forbidden_actions[{index}]",
                    f"Forbidden action '{action}' is not blocked by the agent declaration or overlaps an allowed action.",
                )
            )

    if {action.casefold() for action in autonomous} & {
        action.casefold() for action in approvals
    }:
        findings.append(
            _finding(
                "ACTION_AUTHORITY_COLLISION",
                "approval_required",
                "An action cannot be both autonomous and approval-required.",
            )
        )
    if any(_overlaps_any(action, autonomous + approvals) for action in forbidden):
        findings.append(
            _finding(
                "FORBIDDEN_AUTHORITY_COLLISION",
                "forbidden_actions",
                "A forbidden action overlaps autonomous or approval-required authority.",
            )
        )

    action_levels = agent_contract.get("action_levels", [])
    for index, action in enumerate(autonomous):
        matching_levels = [
            item
            for item in action_levels
            if isinstance(item, Mapping)
            and isinstance(item.get("action"), str)
            and patterns_can_overlap(action.casefold(), item["action"].casefold())
        ]
        if not matching_levels or any(
            item.get("level") == "APPROVAL_REQUIRED" for item in matching_levels
        ):
            findings.append(
                _finding(
                    "AUTONOMOUS_LEVEL_MISMATCH",
                    f"autonomous_actions[{index}]",
                    f"Autonomous action '{action}' has no non-approval action level.",
                )
            )
    for index, action in enumerate(approvals):
        matching_levels = [
            item
            for item in action_levels
            if isinstance(item, Mapping)
            and isinstance(item.get("action"), str)
            and patterns_can_overlap(action.casefold(), item["action"].casefold())
        ]
        if not matching_levels or not any(
            item.get("level") == "APPROVAL_REQUIRED" for item in matching_levels
        ):
            findings.append(
                _finding(
                    "APPROVAL_LEVEL_MISMATCH",
                    f"approval_required[{index}].action",
                    f"Approval-required action '{action}' has no APPROVAL_REQUIRED action level.",
                )
            )

    modeled_authority = autonomous + approvals
    for index, item in enumerate(action_levels):
        if not isinstance(item, Mapping) or not isinstance(item.get("action"), str):
            continue
        action = item["action"]
        if not _overlaps_any(action, modeled_authority):
            findings.append(
                _finding(
                    "UNMODELED_ACTION_LEVEL",
                    f"action_levels[{index}].action",
                    f"Action level '{action}' is not present in autonomous_actions or approval_required.",
                )
            )
        if item.get("level") == "APPROVAL_REQUIRED" and not _overlaps_any(
            action, approvals
        ):
            findings.append(
                _finding(
                    "APPROVAL_LEVEL_NOT_DECLARED",
                    f"action_levels[{index}].level",
                    f"Action level '{action}' requires approval but has no approval_required entry.",
                )
            )

    for index, action in enumerate(allowed):
        if not _overlaps_any(action, autonomous + approvals):
            findings.append(
                _finding(
                    "UNMODELED_ALLOWED_ACTION",
                    f"agent.allowed_actions[{index}]",
                    f"Agent allow pattern '{action}' is absent from autonomous_actions and approval_required.",
                )
            )
    for index, action in enumerate(blocked):
        if not _overlaps_any(action, forbidden):
            findings.append(
                _finding(
                    "UNMODELED_BLOCKED_ACTION",
                    f"agent.blocked_actions[{index}]",
                    f"Agent block pattern '{action}' is absent from forbidden_actions.",
                )
            )

    tool_contract_id: str | None = None
    if tool_contract is not None:
        tool_contract_id_value = tool_contract.get("id")
        tool_contract_id = (
            tool_contract_id_value if isinstance(tool_contract_id_value, str) else None
        )
        tools = {
            item.get("id")
            for item in tool_contract.get("tools", [])
            if isinstance(item, Mapping) and isinstance(item.get("id"), str)
        }
        permissions = agent_contract.get("tool_permissions", {})
        if isinstance(permissions, Mapping):
            for field in ["allowed_tools", "disallowed_tools"]:
                for index, tool_id in enumerate(_actions(permissions.get(field))):
                    if tool_id not in tools:
                        findings.append(
                            _finding(
                                "UNKNOWN_TOOL_PERMISSION",
                                f"tool_permissions.{field}[{index}]",
                                f"Tool '{tool_id}' is not present in Tool Contract '{tool_contract_id}'.",
                            )
                        )
        from .contract_drift import compare_agent_contract

        drift = compare_agent_contract(agent, tool_contract)
        findings.extend(
            _finding(f"TOOL_{item.code}", item.path, item.message)
            for item in drift.findings
        )

    findings.sort(key=lambda item: (item.code, item.path, item.message))
    return AgentContractCompatibilityReport(
        agent_contract_id=str(agent_contract["id"]),
        agent_id=agent_id,
        tool_contract_id=tool_contract_id,
        findings=tuple(findings),
    )


def check_agent_contract_files(
    agent_contract_path: str | Path,
    agent_path: str | Path,
    tool_contract_path: str | Path | None = None,
) -> AgentContractCompatibilityReport:
    """Load, validate, and compare Agent Contract dependency files."""
    contract = load_agent_contract(agent_contract_path)
    contract_errors = validate_agent_contract_data(contract)
    if contract_errors:
        raise AgentContractInputError(contract_errors)

    from .validator import validate_agent

    agent = _load_validated_mapping(agent_path, validate_agent, "agent")
    tool_contract = None
    if tool_contract_path is not None:
        from .tool_contract import load_tool_contract

        tool_contract = load_tool_contract(tool_contract_path)
    return compare_agent_contract_compatibility(contract, agent, tool_contract)


def _load_validated_mapping(
    path: str | Path,
    validator: Any,
    label: str,
) -> dict[str, Any]:
    source_path = Path(path)
    errors = validator(source_path)
    if errors:
        raise AgentContractInputError([f"{label}: {error}" for error in errors])
    data = yaml.safe_load(read_text_capped(source_path, MAX_SOURCE_BYTES, label))
    if not isinstance(data, dict):
        raise AgentContractInputError([f"{label}: YAML root must be an object"])
    return data


def format_agent_contract_text(report: AgentContractCompatibilityReport) -> str:
    """Render a short deterministic human-readable compatibility report."""
    lines = [
        "AGENT CONTRACT COMPATIBILITY",
        f"Status: {report.status.upper()}",
        f"Agent Contract: {report.agent_contract_id}",
        f"Agent: {report.agent_id}",
    ]
    if report.tool_contract_id is not None:
        lines.append(f"Tool Contract: {report.tool_contract_id}")
    if not report.findings:
        lines.append("No compatibility findings.")
        return "\n".join(lines)
    lines.append("Findings:")
    lines.extend(
        f"- [{finding.code}] {finding.path}: {finding.message}"
        for finding in report.findings
    )
    return "\n".join(lines)
