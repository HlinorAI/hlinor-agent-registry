"""CrewAI integration for governed tool execution."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from typing import Any

from crewai.tools import BaseTool
from pydantic import Field, PrivateAttr

from ..policy_checker import PolicyChecker
from ._gate import (
    DecisionSink,
    GovernanceGate,
    RequestFactory,
    ResourceSpec,
    SignalsSpec,
)


class GovernedCrewTool(BaseTool):
    """A CrewAI BaseTool that authorizes exactly once before delegation."""

    name: str = Field(..., description="Name of the tool")
    description: str = Field(..., description="Description of the tool")
    agent_id: str = Field(..., description="ID of the agent using this tool")
    action_name: str = Field(
        ..., description="The action name to check against policies"
    )
    bundle_path: str = Field(..., description="Path to the compiled policy bundle JSON")

    _executor: Callable[..., Any] | BaseTool | None = PrivateAttr(default=None)
    _gate: GovernanceGate | None = PrivateAttr(default=None)

    def __init__(
        self,
        executor: Callable[..., Any] | BaseTool,
        *,
        checker: PolicyChecker | None = None,
        decision_sink: DecisionSink | None = None,
        request_factory: RequestFactory | None = None,
        resource: ResourceSpec = None,
        signals: SignalsSpec = None,
        **kwargs: Any,
    ) -> None:
        if isinstance(executor, BaseTool):
            for field_name in (
                "name",
                "description",
                "args_schema",
                "result_schema",
                "result_as_answer",
                "cache_function",
            ):
                if hasattr(executor, field_name):
                    kwargs.setdefault(field_name, getattr(executor, field_name))

        super().__init__(**kwargs)
        self._executor = executor
        self._gate = GovernanceGate(
            agent_id=self.agent_id,
            action=self.action_name,
            bundle_path=self.bundle_path,
            tool_id=self.name,
            checker=checker,
            decision_sink=decision_sink,
            request_factory=request_factory,
            resource=resource,
            signals=signals,
        )

    def _authorize(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        if self._gate is None:  # pragma: no cover - Pydantic lifecycle invariant
            raise RuntimeError("GovernedCrewTool gate is not configured")
        self._gate.authorize(args, kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Authorize once and execute the synchronous tool path."""
        self._authorize(args, kwargs)
        if self._executor is None:
            raise RuntimeError("GovernedCrewTool executor is not configured")
        if isinstance(self._executor, BaseTool):
            return self._executor.run(*args, **kwargs)
        return self._executor(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Authorize once and execute the asynchronous tool path."""
        self._authorize(args, kwargs)
        if self._executor is None:
            raise RuntimeError("GovernedCrewTool executor is not configured")
        if isinstance(self._executor, BaseTool):
            return await self._executor.arun(*args, **kwargs)
        if inspect.iscoroutinefunction(self._executor):
            return await self._executor(*args, **kwargs)

        result = await asyncio.to_thread(self._executor, *args, **kwargs)
        return await result if inspect.isawaitable(result) else result
