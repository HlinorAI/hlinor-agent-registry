"""Deterministic drift checks between agents and Tool Contracts."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._matching import patterns_can_overlap
from .tool_contract import load_tool_contract
from .validator import load_yaml, validate_agent

DRIFT_REPORT_SCHEMA_VERSION = "1.0"


class ContractDriftInputError(ValueError):
    """Raised when drift cannot be evaluated from invalid input contracts."""

    def __init__(self, source: str, errors: Sequence[str]) -> None:
        self.source = source
        self.errors = tuple(errors)
        super().__init__(f"Invalid {source}: " + "; ".join(self.errors))


@dataclass(frozen=True)
class DriftFinding:
    """One deterministic mismatch in a contract comparison."""

    code: str
    symbol: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": "error",
            "symbol": self.symbol,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True)
class ContractDriftReport:
    """Machine-readable result shared by the Python API and CLI."""

    mode: str
    subjects: Mapping[str, str]
    findings: tuple[DriftFinding, ...] = ()

    @property
    def status(self) -> str:
        return "drift" if self.findings else "aligned"

    def to_dict(self) -> dict[str, object]:
        counts = Counter(finding.code for finding in self.findings)
        return {
            "schema_version": DRIFT_REPORT_SCHEMA_VERSION,
            "mode": self.mode,
            "status": self.status,
            "subjects": dict(sorted(self.subjects.items())),
            "summary": {
                "total_findings": len(self.findings),
                "by_code": dict(sorted(counts.items())),
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class _ToolCapability:
    tool_id: str
    action: str
    pattern: str


def _sorted_findings(findings: list[DriftFinding]) -> tuple[DriftFinding, ...]:
    symbol_order = {"+": 0, "-": 1, "~": 2}
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                symbol_order[finding.symbol],
                finding.code,
                finding.path,
                finding.message,
            ),
        )
    )


def _contract_capabilities(contract: Mapping[str, Any]) -> tuple[_ToolCapability, ...]:
    capabilities: list[_ToolCapability] = []
    for tool in contract["tools"]:
        tool_id = tool["id"]
        action = tool["action"]
        resource_patterns = tool["resource_patterns"]
        if resource_patterns:
            for resource_pattern in resource_patterns:
                capabilities.append(
                    _ToolCapability(
                        tool_id=tool_id,
                        action=action,
                        pattern=f"{action}:{resource_pattern}",
                    )
                )
        else:
            capabilities.append(
                _ToolCapability(tool_id=tool_id, action=action, pattern=action)
            )
    return tuple(
        sorted(
            capabilities,
            key=lambda capability: (
                capability.tool_id,
                capability.action,
                capability.pattern,
            ),
        )
    )


def _allow_overlaps(permission: str, capability: _ToolCapability) -> bool:
    return patterns_can_overlap(permission, capability.pattern)


def _block_overlaps(permission: str, capability: _ToolCapability) -> bool:
    """Mirror runtime block semantics, including bare action blocks."""
    normalized_permission = permission.casefold()
    return patterns_can_overlap(
        normalized_permission, capability.pattern.casefold()
    ) or patterns_can_overlap(normalized_permission, capability.action.casefold())


def compare_agent_contract(
    agent: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> ContractDriftReport:
    """Compare one validated agent declaration with one validated Tool Contract."""
    capabilities = _contract_capabilities(contract)
    allowed_actions = tuple(agent["allowed_actions"])
    blocked_actions = tuple(agent["blocked_actions"])
    findings: list[DriftFinding] = []

    for capability in capabilities:
        allowed = any(
            _allow_overlaps(permission, capability) for permission in allowed_actions
        )
        blocked = any(
            _block_overlaps(permission, capability) for permission in blocked_actions
        )
        if not allowed and not blocked:
            findings.append(
                DriftFinding(
                    code="UNDECLARED_TOOL_SCOPE",
                    symbol="+",
                    path=f"tools.{capability.tool_id}",
                    message=(
                        f"Tool '{capability.tool_id}' exposes "
                        f"'{capability.pattern}', but the agent neither allows "
                        "nor blocks that runtime scope."
                    ),
                )
            )

    for index, permission in enumerate(allowed_actions):
        if not any(
            _allow_overlaps(permission, capability) for capability in capabilities
        ):
            findings.append(
                DriftFinding(
                    code="STALE_ALLOW_PERMISSION",
                    symbol="-",
                    path=f"allowed_actions[{index}]",
                    message=(
                        f"Allowed action pattern '{permission}' does not overlap "
                        "any tool in the contract."
                    ),
                )
            )

    for index, permission in enumerate(blocked_actions):
        if not any(
            _block_overlaps(permission, capability) for capability in capabilities
        ):
            findings.append(
                DriftFinding(
                    code="STALE_BLOCK_PERMISSION",
                    symbol="-",
                    path=f"blocked_actions[{index}]",
                    message=(
                        f"Blocked action pattern '{permission}' does not overlap "
                        "any tool in the contract."
                    ),
                )
            )

    return ContractDriftReport(
        mode="agent-contract",
        subjects={
            "agent_id": agent["id"],
            "tool_contract_id": contract["id"],
            "tool_contract_version": contract["version"],
        },
        findings=_sorted_findings(findings),
    )


_UNORDERED_SCHEMA_ARRAYS = {"enum", "required", "type"}


def _normalize_schema(value: object, parent_key: str | None = None) -> object:
    """Normalize order-insensitive JSON Schema sets before comparison."""
    if isinstance(value, dict):
        return {
            key: _normalize_schema(nested, key) for key, nested in sorted(value.items())
        }
    if isinstance(value, list):
        normalized = [_normalize_schema(item) for item in value]
        if parent_key in _UNORDERED_SCHEMA_ARRAYS:
            return sorted(
                normalized,
                key=lambda item: json.dumps(
                    item,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ),
            )
        return normalized
    return value


def _tool_map(contract: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {tool["id"]: tool for tool in contract["tools"]}


def _changed_finding(
    tool_id: str,
    field: str,
    code: str,
    expected: object,
    observed: object,
) -> DriftFinding:
    return DriftFinding(
        code=code,
        symbol="~",
        path=f"tools.{tool_id}.{field}",
        message=(
            f"Tool '{tool_id}' changed {field}: "
            f"expected {expected!r}, observed {observed!r}."
        ),
    )


def compare_tool_contracts(
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
) -> ContractDriftReport:
    """Compare committed and observed Tool Contracts by stable tool ID."""
    findings: list[DriftFinding] = []

    if expected["id"] != observed["id"]:
        findings.append(
            DriftFinding(
                code="CONTRACT_ID_CHANGED",
                symbol="~",
                path="id",
                message=(
                    f"Contract ID changed from '{expected['id']}' "
                    f"to '{observed['id']}'."
                ),
            )
        )
    if expected["version"] != observed["version"]:
        findings.append(
            DriftFinding(
                code="CONTRACT_VERSION_CHANGED",
                symbol="~",
                path="version",
                message=(
                    f"Contract version changed from '{expected['version']}' "
                    f"to '{observed['version']}'."
                ),
            )
        )

    expected_tools = _tool_map(expected)
    observed_tools = _tool_map(observed)

    for tool_id in sorted(expected_tools.keys() - observed_tools.keys()):
        findings.append(
            DriftFinding(
                code="TOOL_REMOVED",
                symbol="-",
                path=f"tools.{tool_id}",
                message=f"Expected tool '{tool_id}' is absent from the observed contract.",
            )
        )
    for tool_id in sorted(observed_tools.keys() - expected_tools.keys()):
        findings.append(
            DriftFinding(
                code="TOOL_ADDED",
                symbol="+",
                path=f"tools.{tool_id}",
                message=f"Observed contract contains new tool '{tool_id}'.",
            )
        )

    for tool_id in sorted(expected_tools.keys() & observed_tools.keys()):
        expected_tool = expected_tools[tool_id]
        observed_tool = observed_tools[tool_id]

        if expected_tool["action"] != observed_tool["action"]:
            findings.append(
                _changed_finding(
                    tool_id,
                    "action",
                    "ACTION_CHANGED",
                    expected_tool["action"],
                    observed_tool["action"],
                )
            )

        expected_schema = _normalize_schema(expected_tool["input_schema"])
        observed_schema = _normalize_schema(observed_tool["input_schema"])
        if expected_schema != observed_schema:
            findings.append(
                _changed_finding(
                    tool_id,
                    "input_schema",
                    "INPUT_SCHEMA_CHANGED",
                    expected_schema,
                    observed_schema,
                )
            )

        for field, code in (
            ("resource_patterns", "RESOURCE_SCOPE_CHANGED"),
            ("effects", "EFFECTS_CHANGED"),
        ):
            expected_values = sorted(expected_tool[field])
            observed_values = sorted(observed_tool[field])
            if expected_values != observed_values:
                findings.append(
                    _changed_finding(
                        tool_id,
                        field,
                        code,
                        expected_values,
                        observed_values,
                    )
                )

        if expected_tool["annotations"] != observed_tool["annotations"]:
            findings.append(
                _changed_finding(
                    tool_id,
                    "annotations",
                    "ANNOTATIONS_CHANGED",
                    expected_tool["annotations"],
                    observed_tool["annotations"],
                )
            )

    return ContractDriftReport(
        mode="contract-contract",
        subjects={
            "expected_contract_id": expected["id"],
            "expected_contract_version": expected["version"],
            "observed_contract_id": observed["id"],
            "observed_contract_version": observed["version"],
        },
        findings=_sorted_findings(findings),
    )


def _load_agent(path: str | Path) -> dict[str, Any]:
    errors = validate_agent(path)
    if errors:
        raise ContractDriftInputError("agent", errors)
    return load_yaml(path)


def check_contract_drift_files(
    agent_path: str | Path,
    tool_contract_path: str | Path,
) -> ContractDriftReport:
    """Validate and compare an agent file with a Tool Contract file."""
    agent = _load_agent(agent_path)
    contract = load_tool_contract(tool_contract_path)
    return compare_agent_contract(agent, contract)


def diff_tool_contract_files(
    expected_path: str | Path,
    observed_path: str | Path,
) -> ContractDriftReport:
    """Validate and compare expected and observed Tool Contract files."""
    expected = load_tool_contract(expected_path)
    observed = load_tool_contract(observed_path)
    return compare_tool_contracts(expected, observed)


def format_contract_drift_text(report: ContractDriftReport) -> str:
    """Render a concise deterministic report for humans and CI logs."""
    if not report.findings:
        if report.mode == "agent-contract":
            return (
                f"Agent '{report.subjects['agent_id']}' and Tool Contract "
                f"'{report.subjects['tool_contract_id']}' are aligned."
            )
        return (
            f"Expected and observed Tool Contract "
            f"'{report.subjects['expected_contract_id']}' are aligned."
        )

    lines = [f"Contract drift detected ({len(report.findings)} findings):"]
    lines.extend(
        f"{finding.symbol} [{finding.code}] {finding.message}"
        for finding in report.findings
    )
    return "\n".join(lines)
