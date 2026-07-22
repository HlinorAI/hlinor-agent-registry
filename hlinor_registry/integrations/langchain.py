"""Optional LangChain integration for Hlinor Agent Registry.

The module deliberately does not import LangChain at module import time. It
wraps LangChain-compatible tool objects through their public ``run`` or
``invoke`` methods, so the core package remains usable without LangChain.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class GovernedTool:
    """Proxy a LangChain-compatible tool behind a Hlinor policy check.

    The wrapped object must expose either ``run`` or ``invoke``. Calls are
    denied before the underlying tool is touched when the agent's registry
    policy does not permit the configured action.
    """

    def __init__(
        self,
        tool: Any,
        agent_id: str,
        registry_dir: str = "./",
        action_name: Optional[str] = None,
    ) -> None:
        self.tool = tool
        self.agent_id = agent_id
        self.registry_dir = registry_dir
        self.action_name = action_name or getattr(tool, "name", "unknown_action")
        self._checker = None
        self._hlinor_governed = True

    def _get_checker(self):
        """Load PolicyChecker only when the wrapped tool is invoked."""
        if self._checker is None:
            from hlinor_registry.policy_checker import PolicyChecker

            self._checker = PolicyChecker(registry_dir=self.registry_dir)
        return self._checker

    def _check_action(self) -> Optional[str]:
        is_allowed, reason = self._get_checker().check_action(
            self.agent_id, self.action_name
        )
        if is_allowed:
            logger.info(
                "Action %r permitted for agent %r", self.action_name, self.agent_id
            )
            return None

        logger.warning(
            "Blocked action %r for agent %r: %s",
            self.action_name,
            self.agent_id,
            reason,
        )
        return f"Action blocked by governance policy: {reason}"

    def run(self, tool_input: Any, **kwargs: Any) -> Any:
        """Run the wrapped tool after checking its policy."""
        blocked = self._check_action()
        if blocked:
            return blocked

        run = getattr(self.tool, "run", None)
        if callable(run):
            return run(tool_input, **kwargs)

        invoke = getattr(self.tool, "invoke", None)
        if callable(invoke):
            return invoke(tool_input, **kwargs)
        raise TypeError("Wrapped tool must expose a callable run or invoke method")

    def invoke(self, tool_input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Invoke the wrapped tool using LangChain's modern tool protocol."""
        blocked = self._check_action()
        if blocked:
            return blocked

        invoke = getattr(self.tool, "invoke", None)
        if callable(invoke):
            if config is None:
                return invoke(tool_input, **kwargs)
            return invoke(tool_input, config=config, **kwargs)

        run = getattr(self.tool, "run", None)
        if callable(run):
            return run(tool_input, **kwargs)
        raise TypeError("Wrapped tool must expose a callable run or invoke method")

    async def arun(self, tool_input: Any, **kwargs: Any) -> Any:
        """Asynchronously run the wrapped tool when supported."""
        blocked = self._check_action()
        if blocked:
            return blocked

        arun = getattr(self.tool, "arun", None)
        if callable(arun):
            return await arun(tool_input, **kwargs)

        ainvoke = getattr(self.tool, "ainvoke", None)
        if callable(ainvoke):
            return await ainvoke(tool_input, **kwargs)
        return self.run(tool_input, **kwargs)

    async def ainvoke(self, tool_input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Asynchronously invoke the wrapped tool when supported."""
        blocked = self._check_action()
        if blocked:
            return blocked

        ainvoke = getattr(self.tool, "ainvoke", None)
        if callable(ainvoke):
            if config is None:
                return await ainvoke(tool_input, **kwargs)
            return await ainvoke(tool_input, config=config, **kwargs)

        arun = getattr(self.tool, "arun", None)
        if callable(arun):
            return await arun(tool_input, **kwargs)
        return self.run(tool_input, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Proxy metadata and other attributes to the underlying tool."""
        return getattr(self.tool, name)


class GovernedAgent:
    """Wrap an agent executor and replace its tools with governed proxies."""

    def __init__(
        self,
        agent_executor: Any,
        agent_id: str,
        registry_dir: str = "./",
    ) -> None:
        self.agent_executor = agent_executor
        self.agent_id = agent_id
        self.registry_dir = registry_dir
        self.wrapped_tool_count = self._wrap_tools()

    def _wrap_tools(self) -> int:
        """Wrap tools exposed by common LangChain executor layouts."""
        tool_owners = []

        agent = getattr(self.agent_executor, "agent", None)
        if hasattr(self.agent_executor, "tools"):
            tool_owners.append(self.agent_executor)
        if agent is not None and hasattr(agent, "tools"):
            tool_owners.append(agent)

        if not tool_owners:
            logger.info("No tools found on agent executor %r", self.agent_id)
            return 0

        tools = next((owner.tools for owner in tool_owners if owner.tools is not None), None)
        if tools is None:
            return 0

        wrapped_tools = [
            tool
            if getattr(tool, "_hlinor_governed", False)
            else GovernedTool(
                tool=tool,
                agent_id=self.agent_id,
                registry_dir=self.registry_dir,
            )
            for tool in tools
        ]
        for owner in tool_owners:
            try:
                owner.tools = wrapped_tools
            except AttributeError:
                logger.debug("Could not replace tools on %r", owner, exc_info=True)
        logger.info(
            "Wrapped %d tools with Hlinor governance for agent %r",
            len(wrapped_tools),
            self.agent_id,
        )
        return len(wrapped_tools)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        """Invoke the underlying agent executor."""
        return self.agent_executor.invoke(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Proxy executor methods and metadata."""
        return getattr(self.agent_executor, name)
