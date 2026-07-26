"""Python decorators for automatic policy enforcement."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any

from ..decision import GovernanceDeniedError
from ..policy_checker import PolicyChecker
from ._gate import DecisionSink, GovernanceGate, RequestFactory

# Compatibility alias retained for callers importing the former subclass.
PolicyViolationError = GovernanceDeniedError


def governed(
    agent_id: str,
    action: str,
    bundle_path: str,
    *,
    checker: PolicyChecker | None = None,
    decision_sink: DecisionSink | None = None,
    request_factory: RequestFactory | None = None,
    tool_id: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a sync or async function with one governance evaluation."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        gate = GovernanceGate(
            agent_id=agent_id,
            action=action,
            bundle_path=bundle_path,
            tool_id=tool_id or f"{func.__module__}.{func.__qualname__}",
            checker=checker,
            decision_sink=decision_sink,
            request_factory=request_factory,
        )

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                gate.authorize(args, kwargs)
                return await func(*args, **kwargs)

            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            gate.authorize(args, kwargs)
            return func(*args, **kwargs)

        return wrapper

    return decorator
