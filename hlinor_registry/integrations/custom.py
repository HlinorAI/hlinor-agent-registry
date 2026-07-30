"""Framework-neutral Tool Contract export for custom Python tools."""

from __future__ import annotations

import inspect
from collections.abc import Mapping, Sequence
from typing import Any

from ..tool_export import (
    CustomToolDescriptor,
    ToolContractExportError,
    ToolGovernance,
    _export_framework_tool_contract,
    _FrameworkTool,
    _required_text,
)


def _custom_tool_descriptor(tool: object) -> _FrameworkTool:
    if not isinstance(tool, CustomToolDescriptor):
        raise ToolContractExportError(
            "custom-python tools must be CustomToolDescriptor instances"
        )
    if not callable(tool.callable):
        raise ToolContractExportError("custom-python tool callable must be callable")

    callable_name = getattr(tool.callable, "__name__", None)
    name = _required_text(
        tool.name or callable_name,
        field="name",
        framework="custom-python",
    )
    description = _required_text(
        tool.description or inspect.getdoc(tool.callable),
        field=f"description for '{name}'",
        framework="custom-python",
    )
    action = _required_text(
        tool.action_name or name,
        field=f"action name for '{name}'",
        framework="custom-python",
    )
    return _FrameworkTool(
        name=name,
        description=description,
        schema_source=tool.input_schema,
        default_action=action,
    )


def export_custom_tool_contract(
    tools: Sequence[CustomToolDescriptor],
    *,
    contract_id: str,
    name: str,
    description: str,
    version: str,
    owner: str,
    governance: Mapping[str, ToolGovernance],
    repository: str | None = None,
    revision: str | None = None,
) -> dict[str, Any]:
    """Export explicit custom Python tool schemas without invoking callables."""
    return _export_framework_tool_contract(
        list(tools),
        framework="custom-python",
        contract_id=contract_id,
        name=name,
        description=description,
        version=version,
        owner=owner,
        governance=governance,
        descriptor=_custom_tool_descriptor,
        repository=repository,
        revision=revision,
    )
