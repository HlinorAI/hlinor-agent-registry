"""Strict loading and validation for framework-neutral tool contracts."""

from __future__ import annotations

import copy
import json
import math
from collections.abc import Mapping, Sequence
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from ._limits import MAX_SOURCE_BYTES, read_text_capped
from ._matching import pattern_errors

TOOL_CONTRACT_SCHEMA_VERSION = "1.0"

MUTATING_EFFECTS = {
    "code_execution",
    "database_write",
    "external_system_change",
    "filesystem_write",
    "financial_transaction",
    "message_send",
    "network_write",
}


class ToolContractValidationError(ValueError):
    """Raised when a tool contract cannot be trusted as a valid descriptor."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("Invalid tool contract: " + "; ".join(self.errors))


@lru_cache(maxsize=1)
def _loaded_tool_contract_schema() -> dict[str, Any]:
    schema_path = files("hlinor_registry.schemas").joinpath("tool-contract.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def tool_contract_schema() -> dict[str, Any]:
    """Return an isolated copy of the bundled Tool Contract JSON Schema."""
    return copy.deepcopy(_loaded_tool_contract_schema())


def _load_source(path: str | Path) -> object:
    source_path = Path(path)
    if not source_path.exists():
        raise FileNotFoundError(f"File not found: {source_path}")
    return yaml.safe_load(
        read_text_capped(source_path, MAX_SOURCE_BYTES, "Tool contract")
    )


def _path_text(path: Sequence[object]) -> str:
    if not path:
        return "<root>"
    rendered = ""
    for part in path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += ("." if rendered else "") + str(part)
    return rendered


def _json_value_errors(value: object, path: tuple[object, ...] = ()) -> list[str]:
    """Reject YAML-only values before JSON Schema sees them."""
    if value is None or isinstance(value, (str, bool, int)):
        return []
    if isinstance(value, float):
        if math.isfinite(value):
            return []
        return [
            f"tool_contract: {_path_text(path)}: non-finite numbers are not valid JSON"
        ]
    if isinstance(value, Mapping):
        errors: list[str] = []
        for key, nested in value.items():
            if not isinstance(key, str):
                errors.append(
                    f"tool_contract: {_path_text(path)}: object keys must be strings"
                )
                continue
            errors.extend(_json_value_errors(nested, (*path, key)))
        return errors
    if isinstance(value, list):
        errors = []
        for index, nested in enumerate(value):
            errors.extend(_json_value_errors(nested, (*path, index)))
        return errors
    return [
        (
            f"tool_contract: {_path_text(path)}: "
            f"unsupported JSON value type: {type(value).__name__}"
        )
    ]


def _schema_errors(data: object) -> list[str]:
    validator = Draft202012Validator(
        _loaded_tool_contract_schema(),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    discovered = sorted(
        validator.iter_errors(data),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            error.validator or "",
            error.message,
        ),
    )
    return [
        f"tool_contract: {_path_text(tuple(error.absolute_path))}: {error.message}"
        for error in discovered
    ]


def _schema_version_errors(data: object) -> list[str]:
    """Reject versions this reader does not implement with one stable error.

    Tool Contract readers are exact-version readers. ``additionalProperties:
    false`` is a security boundary, so pretending an older reader understands a
    future additive field would either ignore governance data or weaken that
    boundary. Newer 1.x readers remain backward compatible with 1.0; older
    readers fail closed on a future minor version.
    """
    if not isinstance(data, dict) or "schema_version" not in data:
        return []
    version = data["schema_version"]
    if version == TOOL_CONTRACT_SCHEMA_VERSION:
        return []
    return [
        (
            "tool_contract: schema_version: unsupported Tool Contract schema "
            f"{version!r}; this reader supports exactly "
            f"{TOOL_CONTRACT_SCHEMA_VERSION!r}"
        )
    ]


def _duplicate_errors(tools: list[object]) -> list[str]:
    errors: list[str] = []
    seen_ids: dict[str, tuple[int, str]] = {}
    seen_actions: dict[str, tuple[int, str]] = {}

    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        for field, seen in (("id", seen_ids), ("action", seen_actions)):
            value = tool.get(field)
            if not isinstance(value, str):
                continue
            normalized = value.casefold()
            previous = seen.get(normalized)
            if previous is None:
                seen[normalized] = (index, value)
                continue
            previous_index, previous_value = previous
            if field == "id" or previous_value != value:
                errors.append(
                    f"tool_contract: tools[{index}].{field}: "
                    f"collides with tools[{previous_index}].{field} "
                    f"('{previous_value}')"
                )
    return errors


def _input_schema_errors(tools: list[object]) -> list[str]:
    errors: list[str] = []
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        input_schema = tool.get("input_schema")
        if not isinstance(input_schema, dict):
            continue
        try:
            Draft202012Validator.check_schema(input_schema)
        except SchemaError as error:
            schema_path = _path_text(tuple(error.absolute_path))
            errors.append(
                f"tool_contract: tools[{index}].input_schema.{schema_path}: "
                f"{error.message}"
            )
            continue

        properties = input_schema.get("properties")
        required = input_schema.get("required")
        if isinstance(properties, dict) and isinstance(required, list):
            for required_name in required:
                if isinstance(required_name, str) and required_name not in properties:
                    errors.append(
                        f"tool_contract: tools[{index}].input_schema.required: "
                        f"'{required_name}' is not declared in properties"
                    )
    return errors


def _resource_pattern_errors(tools: list[object]) -> list[str]:
    errors: list[str] = []
    for tool_index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        patterns = tool.get("resource_patterns")
        if not isinstance(patterns, list):
            continue
        for pattern_index, pattern in enumerate(patterns):
            if not isinstance(pattern, str):
                continue
            for problem in pattern_errors(pattern):
                errors.append(
                    f"tool_contract: tools[{tool_index}]."
                    f"resource_patterns[{pattern_index}]: {problem}"
                )
    return errors


def _annotation_errors(tools: list[object]) -> list[str]:
    errors: list[str] = []
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        annotations = tool.get("annotations")
        effects = tool.get("effects")
        if not isinstance(annotations, dict) or not isinstance(effects, list):
            continue

        read_only = annotations.get("read_only")
        destructive = annotations.get("destructive")
        mutating = sorted(
            effect
            for effect in effects
            if isinstance(effect, str) and effect in MUTATING_EFFECTS
        )
        if read_only is True and mutating:
            errors.append(
                f"tool_contract: tools[{index}].annotations.read_only: "
                f"cannot be true with mutating effects: {', '.join(mutating)}"
            )
        if read_only is True and destructive is True:
            errors.append(
                f"tool_contract: tools[{index}].annotations: "
                "read_only and destructive cannot both be true"
            )
        if destructive is True and not mutating:
            errors.append(
                f"tool_contract: tools[{index}].annotations.destructive: "
                "requires at least one mutating effect"
            )
    return errors


def tool_contract_errors(data: object) -> list[str]:
    """Return deterministic validation errors for parsed YAML or JSON data."""
    json_errors = _json_value_errors(data)
    if json_errors:
        return json_errors

    version_errors = _schema_version_errors(data)
    if version_errors:
        return version_errors

    errors = _schema_errors(data)
    if not isinstance(data, dict):
        return errors
    tools = data.get("tools")
    if not isinstance(tools, list):
        return errors

    errors.extend(_duplicate_errors(tools))
    errors.extend(_input_schema_errors(tools))
    errors.extend(_resource_pattern_errors(tools))
    errors.extend(_annotation_errors(tools))
    return errors


def validate_tool_contract(path: str | Path) -> list[str]:
    """Validate a YAML or JSON Tool Contract without loading it for use."""
    return tool_contract_errors(_load_source(path))


def load_tool_contract(path: str | Path) -> dict[str, Any]:
    """Load a Tool Contract, refusing malformed or ambiguous descriptors."""
    data = _load_source(path)
    errors = tool_contract_errors(data)
    if errors:
        raise ToolContractValidationError(errors)
    if not isinstance(data, dict):  # Schema enforces this; narrows the type.
        raise ToolContractValidationError(
            ["tool_contract: <root>: contract must be an object"]
        )
    return data
