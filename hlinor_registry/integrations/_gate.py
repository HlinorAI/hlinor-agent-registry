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
from ..execution_scope import ExecutionScope, ExecutionScopeError
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

#: A resource or a signal set may be fixed for the governed target, or derived
#: from the arguments of the call being authorized.
ResourceSpec = str | Callable[[InvocationContext], str | None] | None
SignalsSpec = (
    Mapping[str, Any] | Callable[[InvocationContext], Mapping[str, Any]] | None
)
ExecutionScopeSpec = (
    ExecutionScope | Callable[[InvocationContext], ExecutionScope | None] | None
)


def _resolve(spec: Any, context: InvocationContext) -> Any:
    """Return a static spec unchanged, or call it with the invocation context."""
    return spec(context) if callable(spec) else spec


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
        resource: ResourceSpec = None,
        signals: SignalsSpec = None,
        execution_scope: ExecutionScopeSpec = None,
        require_execution_scope: bool = False,
    ) -> None:
        # A request factory owns the whole request. Accepting resource or
        # signals alongside one would mean silently dropping them, which is
        # the failure mode this project keeps having to fix: a setting that
        # looks configured and does nothing.
        if request_factory is not None and (
            resource is not None or signals is not None
        ):
            raise ValueError(
                "Pass either request_factory or resource/signals, not both: "
                "a request factory builds the whole request itself."
            )

        self.agent_id = agent_id
        self.action = action
        self.tool_id = tool_id
        self.bundle_path = bundle_path
        self._checker = checker
        self._decision_sink = decision_sink
        self._request_factory = request_factory
        self._resource = resource
        self._signals = signals
        self._execution_scope = execution_scope
        self._require_execution_scope = require_execution_scope
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
                execution_scope = _resolve(self._execution_scope, context)
                if execution_scope is not None and not isinstance(
                    execution_scope, ExecutionScope
                ):
                    raise ExecutionScopeError(
                        "EXECUTION_SCOPE_INVALID",
                        "execution_scope must be an ExecutionScope instance",
                    )
                if self._require_execution_scope and execution_scope is None:
                    raise ExecutionScopeError(
                        "EXECUTION_SCOPE_REQUIRED",
                        "an explicit project/workspace execution scope is required",
                    )
                if self._request_factory is not None:
                    request = self._request_factory(context)
                else:
                    resolved_signals = _resolve(self._signals, context) or {}
                    if "execution_scope" in resolved_signals:
                        raise ValueError(
                            "execution scope must be supplied through "
                            'execution_scope, not signals["execution_scope"]'
                        )
                    if execution_scope is not None:
                        resolved_signals = dict(resolved_signals)
                        resolved_signals["execution_scope"] = (
                            execution_scope.as_policy_signal()
                        )
                    request = ActionRequest(
                        agent_id=self.agent_id,
                        action=self.action,
                        tool_id=self.tool_id,
                        environment=checker.environment,
                        resource=_resolve(self._resource, context),
                        signals=resolved_signals,
                        project_id=(
                            execution_scope.project_id if execution_scope else None
                        ),
                        workspace_id=(
                            execution_scope.workspace_id if execution_scope else None
                        ),
                    )
                self._validate_request(request, execution_scope)
                decision = checker.evaluate(request)
                if self._decision_sink is not None:
                    self._decision_sink(decision)

        if decision.denied:
            raise GovernanceDeniedError(decision)
        return decision

    def _validate_request(
        self,
        request: ActionRequest,
        execution_scope: ExecutionScope | None,
    ) -> None:
        """Prevent a custom request factory from changing the governed target."""
        if request.agent_id != self.agent_id:
            raise ValueError("Request factory changed the governed agent_id")
        if request.action != self.action:
            raise ValueError("Request factory changed the governed action")
        if self.tool_id is not None and request.tool_id != self.tool_id:
            raise ValueError("Request factory changed the governed tool_id")
        if self._require_execution_scope and execution_scope is None:
            raise ExecutionScopeError(
                "EXECUTION_SCOPE_REQUIRED",
                "an explicit project/workspace execution scope is required",
            )
        if execution_scope is not None and (
            request.project_id != execution_scope.project_id
            or request.workspace_id != execution_scope.workspace_id
        ):
            raise ValueError("Request does not match the explicit execution scope")
