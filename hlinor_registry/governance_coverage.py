"""Static coverage checks for known sensitive tool paths.

The checker verifies an explicit inventory of sensitive symbols against the
source syntax that protects them.  It is intentionally conservative and
bounded: it does not pretend to prove whole-program coverage or infer dynamic
registration.  Unknown symbols, unreadable sources, malformed syntax, and
unsupported boundary shapes fail closed.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ._limits import MAX_SOURCE_BYTES, read_text_capped

GOVERNANCE_COVERAGE_SCHEMA_VERSION = "1.0"
GOVERNANCE_COVERAGE_TYPE = "governance_coverage"
COVERAGE_BOUNDARIES = {
    "governed_decorator",
    "governance_gate",
    "bound_tool_target",
}
SENSITIVE_EFFECTS = {
    "code_execution",
    "credential_access",
    "database_write",
    "external_system_change",
    "financial_transaction",
    "filesystem_write",
    "message_send",
    "network_read",
    "network_write",
    "personal_data_access",
}

REQUIRED_GOVERNANCE_COVERAGE_FIELDS = [
    "schema_version",
    "type",
    "id",
    "entries",
]
REQUIRED_COVERAGE_ENTRY_FIELDS = ["id", "source", "symbol", "effects", "boundary"]


class GovernanceCoverageInputError(ValueError):
    """Raised when a coverage manifest cannot be trusted as input."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("Invalid governance coverage: " + "; ".join(self.errors))


@dataclass(frozen=True)
class CoverageFinding:
    """One missing, invalid, or bypassed known sensitive path."""

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
class GovernanceCoverageReport:
    """Deterministic result of one source inventory check."""

    manifest_id: str
    entries_checked: int
    findings: tuple[CoverageFinding, ...] = ()

    @property
    def status(self) -> str:
        return "covered" if not self.findings else "bypass"

    def to_dict(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.code] = counts.get(finding.code, 0) + 1
        return {
            "schema_version": GOVERNANCE_COVERAGE_SCHEMA_VERSION,
            "mode": "governance-coverage",
            "status": self.status,
            "manifest_id": self.manifest_id,
            "summary": {
                "entries_checked": self.entries_checked,
                "total_findings": len(self.findings),
                "by_code": dict(sorted(counts.items())),
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _string_errors(value: object, path: str) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return [f"governance_coverage: Field must be a non-empty string: {path}"]
    return []


def _string_list_errors(value: object, path: str, *, non_empty: bool) -> list[str]:
    if not isinstance(value, list):
        return [f"governance_coverage: Field must be a list: {path}"]
    errors: list[str] = []
    if non_empty and not value:
        errors.append(f"governance_coverage: List must not be empty: {path}")
    for index, item in enumerate(value):
        errors.extend(_string_errors(item, f"{path}[{index}]"))
    return errors


def _relative_source_errors(value: object, path: str) -> list[str]:
    errors = _string_errors(value, path)
    if errors or not isinstance(value, str):
        return errors
    source = Path(value)
    if source.is_absolute():
        errors.append(f"governance_coverage: Source must be relative: {path}")
    if "\\" in value:
        errors.append(f"governance_coverage: Source must use '/' separators: {path}")
    if any(part == ".." for part in source.parts):
        errors.append(f"governance_coverage: Source must stay within root: {path}")
    return errors


def validate_governance_coverage_data(data: object) -> list[str]:
    """Validate a coverage manifest without reading any source files."""
    if not isinstance(data, Mapping):
        return ["governance_coverage: YAML root must be an object"]

    errors = [
        f"governance_coverage: Missing required field: {field}"
        for field in REQUIRED_GOVERNANCE_COVERAGE_FIELDS
        if field not in data
    ]
    for field in ["schema_version", "type", "id"]:
        if field in data:
            errors.extend(_string_errors(data[field], field))
    if data.get("schema_version") != GOVERNANCE_COVERAGE_SCHEMA_VERSION:
        errors.append(
            "governance_coverage: Unsupported schema_version: "
            f"{data.get('schema_version')!r}"
        )
    if data.get("type") != GOVERNANCE_COVERAGE_TYPE:
        errors.append(
            f"governance_coverage: Field must equal {GOVERNANCE_COVERAGE_TYPE}: type"
        )

    entries = data.get("entries")
    if not isinstance(entries, list):
        errors.append("governance_coverage: Field must be a list: entries")
        return errors
    if not entries:
        errors.append("governance_coverage: List must not be empty: entries")
    seen_ids: set[str] = set()
    seen_paths: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        path = f"entries[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"governance_coverage: Entry must be an object: {path}")
            continue
        for field in REQUIRED_COVERAGE_ENTRY_FIELDS:
            if field not in entry:
                errors.append(
                    f"governance_coverage: {path}: Missing required field: {field}"
                )
        for field in ["id", "symbol"]:
            if field in entry:
                errors.extend(_string_errors(entry[field], f"{path}.{field}"))
        if "source" in entry:
            errors.extend(_relative_source_errors(entry["source"], f"{path}.source"))
        if "effects" in entry:
            errors.extend(
                _string_list_errors(entry["effects"], f"{path}.effects", non_empty=True)
            )
            if isinstance(entry["effects"], list):
                for effect_index, effect in enumerate(entry["effects"]):
                    if isinstance(effect, str) and effect not in SENSITIVE_EFFECTS:
                        errors.append(
                            f"governance_coverage: Unsupported sensitive effect: {path}.effects[{effect_index}]"
                        )
        if "boundary" in entry and entry["boundary"] not in COVERAGE_BOUNDARIES:
            errors.append(f"governance_coverage: Invalid boundary: {path}.boundary")
        entry_id = entry.get("id")
        if isinstance(entry_id, str) and entry_id.strip():
            normalized_id = entry_id.casefold()
            if normalized_id in seen_ids:
                errors.append(f"governance_coverage: Duplicate entry id: {path}.id")
            seen_ids.add(normalized_id)
        source = entry.get("source")
        symbol = entry.get("symbol")
        if isinstance(source, str) and isinstance(symbol, str):
            key = (source.casefold(), symbol.casefold())
            if key in seen_paths:
                errors.append(f"governance_coverage: Duplicate source symbol: {path}")
            seen_paths.add(key)
    return errors


def load_governance_coverage(path: str | Path) -> dict[str, Any]:
    """Load one coverage manifest using the repository input-size limit."""
    source_path = Path(path)
    if not source_path.exists():
        raise FileNotFoundError(f"File not found: {source_path}")
    data = yaml.safe_load(
        read_text_capped(source_path, MAX_SOURCE_BYTES, "Governance coverage")
    )
    if not isinstance(data, dict):
        raise TypeError("YAML root must be an object")
    return data


def validate_governance_coverage(path: str | Path) -> list[str]:
    """Validate one coverage manifest file."""
    return validate_governance_coverage_data(load_governance_coverage(path))


def _call_name(node: ast.Call) -> str | None:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return None


def _decorator_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


def _function_nodes(
    tree: ast.AST, symbol: str
) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == symbol
    ]


def _has_governed_decorator(node: ast.AsyncFunctionDef | ast.FunctionDef) -> bool:
    return any(
        _decorator_name(decorator) == "governed" for decorator in node.decorator_list
    )


def _has_governance_gate(node: ast.AsyncFunctionDef | ast.FunctionDef) -> bool:
    gate_created = False
    authorized = False
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _call_name(child) == "GovernanceGate":
            gate_created = True
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "authorize"
        ):
            authorized = True
    return gate_created and authorized


def _has_bound_tool_target(tree: ast.AST, symbol: str) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node) != "bind_tool":
            continue
        for keyword in node.keywords:
            if (
                keyword.arg == "target"
                and isinstance(keyword.value, ast.Name)
                and keyword.value.id == symbol
            ):
                return True
    return False


def _boundary_present(
    tree: ast.AST, node: ast.AsyncFunctionDef | ast.FunctionDef, boundary: str
) -> bool:
    if boundary == "governed_decorator":
        return _has_governed_decorator(node)
    if boundary == "governance_gate":
        return _has_governance_gate(node)
    if boundary == "bound_tool_target":
        return _has_bound_tool_target(tree, node.name)
    return False


def _entry_findings(
    root: Path, entry: Mapping[str, Any], entry_index: int
) -> list[CoverageFinding]:
    source = entry.get("source")
    symbol = entry.get("symbol")
    boundary = entry.get("boundary")
    entry_path = f"entries[{entry_index}]"
    if (
        not isinstance(source, str)
        or not isinstance(symbol, str)
        or not isinstance(boundary, str)
    ):
        return []
    source_path = (root / source).resolve()
    try:
        source_path.relative_to(root)
    except ValueError:
        return [
            _finding(
                "SOURCE_OUTSIDE_ROOT",
                f"{entry_path}.source",
                f"Source '{source}' resolves outside the configured root.",
            )
        ]
    if not source_path.is_file():
        return [
            _finding(
                "SOURCE_NOT_FOUND",
                f"{entry_path}.source",
                f"Source file '{source}' was not found.",
            )
        ]
    try:
        tree = ast.parse(
            read_text_capped(
                source_path, MAX_SOURCE_BYTES, "Governance coverage source"
            ),
            filename=str(source_path),
        )
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError) as error:
        return [
            _finding(
                "SOURCE_UNREADABLE",
                f"{entry_path}.source",
                f"Source '{source}' could not be parsed safely: {error}",
            )
        ]

    nodes = _function_nodes(tree, symbol)
    if not nodes:
        return [
            _finding(
                "SYMBOL_NOT_FOUND",
                f"{entry_path}.symbol",
                f"Function '{symbol}' was not found in '{source}'.",
            )
        ]
    if len(nodes) > 1:
        return [
            _finding(
                "SYMBOL_AMBIGUOUS",
                f"{entry_path}.symbol",
                f"Function '{symbol}' occurs multiple times in '{source}'; use a unique symbol before relying on coverage.",
            )
        ]
    if not any(_boundary_present(tree, node, boundary) for node in nodes):
        return [
            _finding(
                "BOUNDARY_BYPASS",
                entry_path,
                f"Sensitive function '{symbol}' in '{source}' has no '{boundary}' boundary.",
            )
        ]
    return []


def _finding(code: str, path: str, message: str) -> CoverageFinding:
    return CoverageFinding(code=code, path=path, message=message)


def check_governance_coverage(
    manifest: Mapping[str, Any],
    *,
    root: str | Path = ".",
) -> GovernanceCoverageReport:
    """Check all manifest entries against source-level governance boundaries."""
    errors = validate_governance_coverage_data(manifest)
    if errors:
        raise GovernanceCoverageInputError(errors)
    root_path = Path(root).resolve()
    entries = manifest["entries"]
    findings: list[CoverageFinding] = []
    for index, entry in enumerate(entries):
        if isinstance(entry, Mapping):
            findings.extend(_entry_findings(root_path, entry, index))
    findings.sort(key=lambda item: (item.code, item.path, item.message))
    return GovernanceCoverageReport(
        manifest_id=str(manifest["id"]),
        entries_checked=len(entries),
        findings=tuple(findings),
    )


def check_governance_coverage_file(
    manifest_path: str | Path,
    *,
    root: str | Path = ".",
) -> GovernanceCoverageReport:
    """Load and check one coverage manifest."""
    manifest = load_governance_coverage(manifest_path)
    return check_governance_coverage(manifest, root=root)


def format_governance_coverage_text(report: GovernanceCoverageReport) -> str:
    """Render a stable human-readable coverage report."""
    lines = [
        "GOVERNANCE COVERAGE",
        f"Status: {report.status.upper()}",
        f"Manifest: {report.manifest_id}",
        f"Entries checked: {report.entries_checked}",
    ]
    if not report.findings:
        lines.append("No coverage findings.")
        return "\n".join(lines)
    lines.append("Findings:")
    lines.extend(
        f"- [{finding.code}] {finding.path}: {finding.message}"
        for finding in report.findings
    )
    return "\n".join(lines)
