"""Safe helpers for exporting framework tools as Hlinor Tool Contracts."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .tool_contract import ToolContractValidationError, tool_contract_errors


class ToolContractExportError(ValueError):
    """Raised when framework metadata cannot produce a trustworthy contract."""


@dataclass(frozen=True)
class ToolGovernance:
    """Explicit governance metadata that frameworks cannot infer safely."""

    read_only: bool
    destructive: bool
    idempotent: bool
    resource_patterns: tuple[str, ...] = ()
    effects: tuple[str, ...] = ()
    action: str | None = None
    tool_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "resource_patterns", tuple(self.resource_patterns))
        object.__setattr__(self, "effects", tuple(self.effects))


@dataclass(frozen=True)
class _FrameworkTool:
    name: str
    description: str
    schema_source: object
    default_action: str


def _schema_from_source(
    source: object,
    *,
    framework: str,
    tool_name: str,
) -> dict[str, Any]:
    if isinstance(source, Mapping):
        schema: object = copy.deepcopy(dict(source))
    elif callable(getattr(source, "model_json_schema", None)):
        schema = source.model_json_schema()  # type: ignore[attr-defined]
    elif callable(getattr(source, "schema", None)):
        schema = source.schema()  # type: ignore[attr-defined]
    else:
        raise ToolContractExportError(
            f"{framework} tool '{tool_name}' does not expose a supported "
            "Pydantic or JSON Schema input contract"
        )

    if not isinstance(schema, dict):
        raise ToolContractExportError(
            f"{framework} tool '{tool_name}' produced a non-object input schema"
        )
    if schema.get("type") != "object":
        raise ToolContractExportError(
            f"{framework} tool '{tool_name}' input schema must have type 'object'"
        )

    properties = schema.get("properties")
    if properties is None:
        schema["properties"] = {}
    elif not isinstance(properties, dict):
        raise ToolContractExportError(
            f"{framework} tool '{tool_name}' input schema properties must be an object"
        )

    required = schema.get("required")
    if required is None:
        schema["required"] = []
    elif not isinstance(required, list):
        raise ToolContractExportError(
            f"{framework} tool '{tool_name}' input schema required must be an array"
        )

    additional_properties = schema.get("additionalProperties")
    if additional_properties is None:
        # JSON Schema defaults to accepting additional properties. Preserve that
        # behavior instead of silently claiming a stricter runtime contract.
        schema["additionalProperties"] = True
    elif not isinstance(additional_properties, bool):
        raise ToolContractExportError(
            f"{framework} tool '{tool_name}' input schema must use a boolean "
            "additionalProperties value"
        )

    return schema


def _required_text(value: object, *, field: str, framework: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolContractExportError(
            f"{framework} tool has no usable {field}; set it on the framework tool"
        )
    return value


def _framework_tool(
    tool: object,
    *,
    framework: str,
    schema_source: object,
) -> _FrameworkTool:
    name = _required_text(
        getattr(tool, "name", None), field="name", framework=framework
    )
    description = _required_text(
        getattr(tool, "description", None),
        field=f"description for '{name}'",
        framework=framework,
    )
    action_candidate = getattr(tool, "action_name", name)
    action = _required_text(
        action_candidate,
        field=f"action name for '{name}'",
        framework=framework,
    )
    return _FrameworkTool(
        name=name,
        description=description,
        schema_source=schema_source,
        default_action=action,
    )


def _export_framework_tool_contract(
    tools: Sequence[object],
    *,
    framework: str,
    contract_id: str,
    name: str,
    description: str,
    version: str,
    owner: str,
    governance: Mapping[str, ToolGovernance],
    descriptor: Callable[[object], _FrameworkTool],
    repository: str | None = None,
    revision: str | None = None,
) -> dict[str, Any]:
    records = [descriptor(tool) for tool in tools]
    names = [record.name for record in records]
    duplicate_names = sorted(
        {tool_name for tool_name in names if names.count(tool_name) > 1}
    )
    if duplicate_names:
        raise ToolContractExportError(
            f"{framework} tool names must be unique: {', '.join(duplicate_names)}"
        )

    actual_names = set(names)
    configured_names = set(governance)
    missing = sorted(actual_names - configured_names)
    stale = sorted(configured_names - actual_names)
    problems: list[str] = []
    if missing:
        problems.append(f"missing governance for: {', '.join(missing)}")
    if stale:
        problems.append(f"governance references absent tools: {', '.join(stale)}")
    if problems:
        raise ToolContractExportError(
            f"{framework} export configuration is incomplete: " + "; ".join(problems)
        )

    exported_tools: list[dict[str, Any]] = []
    for record in records:
        config = governance[record.name]
        if not isinstance(config, ToolGovernance):
            raise ToolContractExportError(
                f"{framework} governance for '{record.name}' must be ToolGovernance"
            )
        exported_tools.append(
            {
                "id": config.tool_id or record.name,
                "action": config.action or record.default_action,
                "description": record.description,
                "input_schema": _schema_from_source(
                    record.schema_source,
                    framework=framework,
                    tool_name=record.name,
                ),
                "resource_patterns": sorted(set(config.resource_patterns)),
                "effects": sorted(set(config.effects)),
                "annotations": {
                    "read_only": config.read_only,
                    "destructive": config.destructive,
                    "idempotent": config.idempotent,
                },
            }
        )

    metadata: dict[str, str] = {
        "owner": owner,
        "source": framework,
    }
    if repository is not None:
        metadata["repository"] = repository
    if revision is not None:
        metadata["revision"] = revision

    contract: dict[str, Any] = {
        "schema_version": "1.0",
        "type": "tool_contract",
        "id": contract_id,
        "name": name,
        "description": description,
        "version": version,
        "tools": sorted(exported_tools, key=lambda item: item["id"]),
        "metadata": metadata,
    }
    errors = tool_contract_errors(contract)
    if errors:
        raise ToolContractValidationError(errors)
    return contract


def write_tool_contract(
    contract: Mapping[str, Any],
    path: str | Path,
) -> Path:
    """Validate and atomically write one deterministic YAML or JSON contract."""
    data = copy.deepcopy(dict(contract))
    errors = tool_contract_errors(data)
    if errors:
        raise ToolContractValidationError(errors)

    output_path = Path(path)
    suffix = output_path.suffix.casefold()
    if suffix not in {".json", ".yaml", ".yml"}:
        raise ToolContractExportError(
            "Tool Contract output must use .json, .yaml, or .yml"
        )

    if suffix == ".json":
        serialized = json.dumps(data, indent=2, sort_keys=True) + "\n"
    else:
        serialized = yaml.safe_dump(
            data,
            sort_keys=False,
            allow_unicode=False,
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return output_path
