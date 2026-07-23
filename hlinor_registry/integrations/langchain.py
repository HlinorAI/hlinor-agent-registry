"""LangChain integration for governed tool execution."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from ..decision import GovernanceDeniedError, PolicyDecision
from ..policy_checker import PolicyChecker

logger = logging.getLogger(__name__)


class GovernedTool:
    """Wrapper around a LangChain tool that enforces governance policies.
    
    Before delegating to the underlying tool, this wrapper checks whether
    the action is allowed by the PolicyChecker. If denied, it raises
    GovernanceDeniedError instead of returning a string.
    """

    def __init__(
        self,
        tool: Any,
        agent_id: str,
        bundle_path: str = "./dist/policy-bundle.json",
        action_name: Optional[str] = None,
        *,
        registry_dir: Optional[str] = None,
    ) -> None:
        self.tool = tool
        self.agent_id = agent_id
        self.bundle_path = registry_dir or bundle_path
        self.action_name = action_name or getattr(tool, "name", "unknown")
        self._checker: Optional[PolicyChecker] = None

    def _get_checker(self) -> PolicyChecker:
        """Lazily initialize the PolicyChecker."""
        if self._checker is None:
            self._checker = PolicyChecker(self.bundle_path)
        return self._checker

    def _check_action(self) -> PolicyDecision:
        """Check if the action is allowed. Returns PolicyDecision."""
        return self._get_checker().check_action(self.agent_id, self.action_name)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the tool if allowed, otherwise raise GovernanceDeniedError."""
        decision = self._check_action()
        
        if decision.denied:
            raise GovernanceDeniedError(decision)
        
        # Delegate to the underlying tool
        if hasattr(self.tool, "run"):
            return self.tool.run(*args, **kwargs)
        if callable(self.tool):
            return self.tool(*args, **kwargs)
        raise TypeError(f"Tool {self.tool} does not support execution")

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        """Async version of run."""
        decision = self._check_action()
        
        if decision.denied:
            raise GovernanceDeniedError(decision)
        
        if hasattr(self.tool, "arun"):
            return await self.tool.arun(*args, **kwargs)
        if hasattr(self.tool, "run"):
            return self.tool.run(*args, **kwargs)
        if callable(self.tool):
            return self.tool(*args, **kwargs)
        raise TypeError(f"Tool {self.tool} does not support execution")


class GovernedAgent:
    """Wrapper that applies governance to all tools in a LangChain agent."""

    def __init__(
        self,
        agent_executor: Any,
        agent_id: str,
        bundle_path: str = "./dist/policy-bundle.json",
        *,
        registry_dir: Optional[str] = None,
    ) -> None:
        self.agent_executor = agent_executor
        self.agent_id = agent_id
        self.bundle_path = registry_dir or bundle_path
        self._wrap_tools()

    def _wrap_tools(self) -> None:
        """Wrap all tools in the agent with GovernedTool."""
        tools = getattr(self.agent_executor, "tools", [])
        if not tools:
            # Try nested agent
            agent = getattr(self.agent_executor, "agent", None)
            if agent:
                tools = getattr(agent, "tools", [])
        
        wrapped_tools = []
        for tool in tools:
            wrapped = GovernedTool(
                tool=tool,
                agent_id=self.agent_id,
                bundle_path=self.bundle_path,
                action_name=getattr(tool, "name", None),
            )
            wrapped_tools.append(wrapped)
        
        if tools:
            self.agent_executor.tools = wrapped_tools
