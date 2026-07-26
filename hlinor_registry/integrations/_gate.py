"""Shared governance contract for framework integrations."""

from __future__ import annotations

import threading
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from ..action_request import ActionRequest
from ..decision import GovernanceDeniedError, PolicyDecision
from ..policy_checker import PolicyChecker

DecisionSink = Callable[[PolicyDecision], None]


@dataclass(frozen=True)
class InvocationContext:
    """Immutable adapter context passed to an optional request factory."""

    agent_id: str
    action: str
    tool_id: str | None
    environment: str
    args: tuple[Any, ...]
    kwargs: Mapping[str, Any]


RequestFactory = Callable[[InvocationContext], ActionRequest]

_checker_locks: weakref.WeakKeyDictionary[PolicyChecker, threading.RLock] = (
    weakref.WeakKeyDictionary()
)
_checker_locks_guard = threading.Lock()


def _lock_for_checker(checker: PolicyChecker) -> threading.RLock:
    with _checker_locks_guard:
        lock = _checker_locks.get(checker)
        if lock is None:
            lock = threading.RLock()
            _checker_locks[checker] = lock
        return lock


class GovernanceGate:
    """Evaluate exactly one request before one governed invocation."""

    def __init__(
        self,
        *,
        agent_id: str,
        action: str,
        bundle_path: str,
        tool_id: str | None = None,
        checker: PolicyChecker | None = None,
        decision_sink: DecisionSink | None = None,
        request_factory: RequestFactory | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.action = action
        self.tool_id = tool_id
        self.bundle_path = bundle_path
        self._checker = checker
        self._decision_sink = decision_sink
        self._request_factory = request_factory
        self._lock = threading.RLock()

    @property
    def checker(self) -> PolicyChecker:
        """Return the active checker, loading it lazily when necessary."""
        with self._lock:
            if self._checker is None:
                self._checker = PolicyChecker(self.bundle_path)
            return self._checker

    def authorize(
        self,
        args: tuple[Any, ...] = (),
        kwargs: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate and emit one decision, raising on denial."""
        frozen_kwargs = MappingProxyType(dict(kwargs or {}))

        with self._lock:
            checker = self.checker
            with _lock_for_checker(checker):
                checker.reload_if_changed()
                context = InvocationContext(
                    agent_id=self.agent_id,
                    action=self.action,
                    tool_id=self.tool_id,
                    environment=checker.environment,
                    args=tuple(args),
                    kwargs=frozen_kwargs,
                )
                request = (
                    self._request_factory(context)
                    if self._request_factory is not None
                    else ActionRequest(
                        agent_id=self.agent_id,
                        action=self.action,
                        tool_id=self.tool_id,
                        environment=checker.environment,
                    )
                )
                self._validate_request(request)
                decision = checker.evaluate(request)
                if self._decision_sink is not None:
                    self._decision_sink(decision)

        if decision.denied:
            raise GovernanceDeniedError(decision)
        return decision

    def _validate_request(self, request: ActionRequest) -> None:
        """Prevent a custom request factory from changing the governed target."""
        if request.agent_id != self.agent_id:
            raise ValueError("Request factory changed the governed agent_id")
        if request.action != self.action:
            raise ValueError("Request factory changed the governed action")
        if self.tool_id is not None and request.tool_id != self.tool_id:
            raise ValueError("Request factory changed the governed tool_id")
