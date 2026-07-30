"""Microsoft AutoGen Tool Contract export.

The module intentionally uses AutoGen's public tool protocol rather than
importing its concrete classes. This keeps the dependency optional while the
dedicated compatibility job tests the implementation against ``autogen-core``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..tool_export import (
    ToolContractExportError,
    ToolGovernance,
    _export_framework_tool_contract,
    _framework_tool,
)


def _autogen_tool_descriptor(tool: object):
    schema = getattr(tool, "schema", None)
    if not isinstance(schema, Mapping):
        raise ToolContractExportError(
            "autogen tool does not expose a usable schema mapping"
        )
    parameters = schema.get("parameters")
    return _framework_tool(
        tool,
        framework="autogen",
        schema_source=parameters,
    )


def export_autogen_tool_contract(
    tools: Sequence[object],
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
    """Export AutoGen ``BaseTool`` schemas without invoking the tools."""
    return _export_framework_tool_contract(
        list(tools),
        framework="autogen",
        contract_id=contract_id,
        name=name,
        description=description,
        version=version,
        owner=owner,
        governance=governance,
        descriptor=_autogen_tool_descriptor,
        repository=repository,
        revision=revision,
    )
