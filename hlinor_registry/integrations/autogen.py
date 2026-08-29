"""Microsoft AutoGen Tool Contract export and governed execution.

The dependency remains optional. When installed, the integration uses only
AutoGen Core's public ``BaseTool`` API; the dedicated compatibility job tests
the implementation against the pinned ``autogen-core`` version.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

try:
    from autogen_core.tools import BaseTool as AutoGenBaseTool
    from pydantic import PrivateAttr
except ImportError:  # pragma: no cover - exercised by the optional CI job
    AutoGenBaseTool = None  # type: ignore[assignment,misc]
    PrivateAttr = None  # type: ignore[assignment,misc]

from ..policy_checker import PolicyChecker
from ..tool_export import (
    ToolContractExportError,
    ToolGovernance,
    _export_framework_tool_contract,
    _framework_tool,
)
from ._gate import (
    DecisionSink,
    ExecutionScopeSpec,
    GovernanceGate,
    RequestFactory,
    ResourceSpec,
    SignalsSpec,
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


if AutoGenBaseTool is not None:

    class GovernedAutoGenTool(AutoGenBaseTool):
        """Authorize an AutoGen ``BaseTool`` before its public run path."""

        _wrapped_tool: Any = PrivateAttr()
        _gate: GovernanceGate = PrivateAttr()

        def __init__(
            self,
            tool: Any,
            agent_id: str,
            bundle_path: str = "./dist/policy-bundle.json",
            action_name: str | None = None,
            *,
            registry_dir: str | None = None,
            checker: PolicyChecker | None = None,
            decision_sink: DecisionSink | None = None,
            request_factory: RequestFactory | None = None,
            resource: ResourceSpec = None,
            signals: SignalsSpec = None,
            execution_scope: ExecutionScopeSpec = None,
            require_execution_scope: bool = False,
        ) -> None:
            if not isinstance(tool, AutoGenBaseTool):
                raise ToolContractExportError(
                    "GovernedAutoGenTool requires an AutoGen BaseTool"
                )
            resolved_bundle_path = registry_dir or bundle_path
            action_candidate = (
                action_name if action_name is not None else getattr(tool, "name", None)
            )
            if not isinstance(action_candidate, str) or not action_candidate:
                raise ToolContractExportError(
                    "AutoGen tool must expose a non-empty name or action_name"
                )
            super().__init__(
                args_type=tool.args_type(),
                return_type=tool.return_type(),
                name=tool.name,
                description=tool.description,
                strict=getattr(tool, "strict", False),
            )
            self._wrapped_tool = tool
            self._gate = GovernanceGate(
                agent_id=agent_id,
                action=action_candidate,
                bundle_path=resolved_bundle_path,
                tool_id=tool.name,
                checker=checker,
                decision_sink=decision_sink,
                request_factory=request_factory,
                resource=resource,
                signals=signals,
                execution_scope=execution_scope,
                require_execution_scope=require_execution_scope,
            )

        async def run(self, args: Any, cancellation_token: Any) -> Any:
            """Authorize once, then delegate to AutoGen's validated tool args."""
            if hasattr(args, "model_dump"):
                normalized_args = args.model_dump()
            elif hasattr(args, "dict"):
                normalized_args = args.dict()
            else:  # pragma: no cover - BaseTool validates this before calling
                raise TypeError("AutoGen tool arguments must be a Pydantic model")
            self._gate.authorize(kwargs=normalized_args)
            return await self._wrapped_tool.run(args, cancellation_token)

else:

    class GovernedAutoGenTool:  # type: ignore[no-redef]
        """Placeholder that fails clearly when AutoGen is not installed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ToolContractExportError(
                "autogen-core is required for GovernedAutoGenTool"
            )
