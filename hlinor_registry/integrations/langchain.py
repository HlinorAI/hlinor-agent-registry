"""LangChain integration for governed tool execution."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import patch_config
from langchain_core.tools import BaseTool
from pydantic import PrivateAttr

from ..policy_checker import PolicyChecker
from ._gate import DecisionSink, GovernanceGate, RequestFactory


def _tool_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | dict[str, Any]:
    if kwargs and not args:
        return kwargs
    if len(args) == 1 and not kwargs:
        value = args[0]
        if isinstance(value, (str, dict)):
            return value
    raise TypeError("LangChain tools require one string input or one input object")


class GovernedTool(BaseTool):
    """A real LangChain BaseTool that authorizes before delegation."""

    _wrapped_tool: Any = PrivateAttr()
    _gate: GovernanceGate = PrivateAttr()
    _agent_id: str = PrivateAttr()
    _action_name: str = PrivateAttr()
    _bundle_path: str = PrivateAttr()

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
    ) -> None:
        resolved_bundle_path = registry_dir or bundle_path
        action_candidate = (
            action_name if action_name is not None else getattr(tool, "name", None)
        )
        resolved_action = (
            action_candidate
            if isinstance(action_candidate, str) and action_candidate
            else "unknown"
        )
        name_candidate = getattr(tool, "name", None)
        name = (
            name_candidate
            if isinstance(name_candidate, str) and name_candidate
            else resolved_action
        )
        description_candidate = getattr(tool, "description", None)
        description = (
            description_candidate
            if isinstance(description_candidate, str) and description_candidate
            else f"Governed tool: {name}"
        )

        inherited_fields: dict[str, Any] = {}
        for field_name in (
            "args_schema",
            "return_direct",
            "verbose",
            "callbacks",
            "tags",
            "metadata",
            "handle_tool_error",
            "handle_validation_error",
            "response_format",
        ):
            if hasattr(tool, field_name):
                inherited_fields[field_name] = getattr(tool, field_name)

        super().__init__(
            name=name,
            description=description,
            **inherited_fields,
        )
        self._wrapped_tool = tool
        self._agent_id = agent_id
        self._action_name = resolved_action
        self._bundle_path = resolved_bundle_path
        self._gate = GovernanceGate(
            agent_id=agent_id,
            action=resolved_action,
            bundle_path=resolved_bundle_path,
            tool_id=name,
            checker=checker,
            decision_sink=decision_sink,
            request_factory=request_factory,
        )

    @property
    def tool(self) -> Any:
        """Return the wrapped tool for compatibility and inspection."""
        return self._wrapped_tool

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def action_name(self) -> str:
        return self._action_name

    @property
    def bundle_path(self) -> str:
        return self._bundle_path

    def _child_config(
        self,
        config: RunnableConfig | None,
        run_manager: Any,
    ) -> RunnableConfig | None:
        if run_manager is None:
            return config
        return patch_config(config, callbacks=run_manager.get_child())

    def _run(
        self,
        *args: Any,
        run_manager: Any = None,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        self._gate.authorize(args, kwargs)

        if isinstance(self._wrapped_tool, BaseTool):
            return self._wrapped_tool.invoke(
                _tool_input(args, kwargs),
                config=self._child_config(config, run_manager),
            )
        if hasattr(self._wrapped_tool, "run"):
            return self._wrapped_tool.run(*args, **kwargs)
        if callable(self._wrapped_tool):
            return self._wrapped_tool(*args, **kwargs)
        raise TypeError(f"Tool {self._wrapped_tool} does not support execution")

    async def _arun(
        self,
        *args: Any,
        run_manager: Any = None,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Any:
        self._gate.authorize(args, kwargs)

        if isinstance(self._wrapped_tool, BaseTool):
            return await self._wrapped_tool.ainvoke(
                _tool_input(args, kwargs),
                config=self._child_config(config, run_manager),
            )
        if hasattr(self._wrapped_tool, "arun"):
            result = self._wrapped_tool.arun(*args, **kwargs)
            return await result if inspect.isawaitable(result) else result
        if hasattr(self._wrapped_tool, "run"):
            return await asyncio.to_thread(self._wrapped_tool.run, *args, **kwargs)
        if callable(self._wrapped_tool):
            if inspect.iscoroutinefunction(self._wrapped_tool):
                return await self._wrapped_tool(*args, **kwargs)
            return await asyncio.to_thread(self._wrapped_tool, *args, **kwargs)
        raise TypeError(f"Tool {self._wrapped_tool} does not support execution")


class GovernedAgent:
    """Compatibility wrapper that replaces discoverable executor tools."""

    def __init__(
        self,
        agent_executor: Any,
        agent_id: str,
        bundle_path: str = "./dist/policy-bundle.json",
        *,
        registry_dir: str | None = None,
        checker: PolicyChecker | None = None,
        decision_sink: DecisionSink | None = None,
        request_factory: RequestFactory | None = None,
    ) -> None:
        self.agent_executor = agent_executor
        self.agent_id = agent_id
        self.bundle_path = registry_dir or bundle_path
        self._checker = checker
        self._decision_sink = decision_sink
        self._request_factory = request_factory
        self._wrap_tools()

    def _wrap_tools(self) -> None:
        tools = getattr(self.agent_executor, "tools", [])
        if not tools:
            agent = getattr(self.agent_executor, "agent", None)
            if agent:
                tools = getattr(agent, "tools", [])

        wrapped_tools = [
            GovernedTool(
                tool=tool,
                agent_id=self.agent_id,
                bundle_path=self.bundle_path,
                action_name=getattr(tool, "name", None),
                checker=self._checker,
                decision_sink=self._decision_sink,
                request_factory=self._request_factory,
            )
            for tool in tools
        ]

        if tools:
            self.agent_executor.tools = wrapped_tools
