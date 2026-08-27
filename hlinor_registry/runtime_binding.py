"""Trusted in-process binding from reviewed Tool Contracts to dispatch targets."""

from __future__ import annotations

import copy
import hashlib
import hmac
import inspect
import math
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, cast

import rfc8785
from jsonschema import Draft202012Validator

from ._matching import matches
from .action_request import ActionRequest
from .circuit_breaker import (
    BreakerSnapshot,
    CircuitBreaker,
    CircuitBreakerError,
)
from .decision import GovernanceDeniedError
from .delegation import (
    DelegationTrustedKey,
    DelegationVerificationError,
    FanOutError,
    FanOutGuard,
    VerifiedDelegation,
    verify_delegation_chain,
)
from .execution_receipts import (
    ApprovalVerificationError,
    ReceiptSink,
    ReplayGuard,
    VerifiedApproval,
    verify_approval_token,
)
from .integrations._gate import DecisionSink, GovernanceGate
from .policy_checker import PolicyChecker
from .runtime_limits import (
    RuntimeBudgetGuard,
    RuntimeLimitError,
    RuntimeLimitSnapshot,
)
from .signing import TrustedKey
from .tool_contract import tool_contract_errors


class RuntimeBindingError(ValueError):
    """Raised when a trusted runtime binding cannot be established or used."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class ContractBindingError(RuntimeBindingError):
    """Raised when reviewed and observed Tool Contracts do not agree."""


class ArgumentValidationError(RuntimeBindingError):
    """Raised when normalized arguments do not satisfy a Tool Contract schema."""

    def __init__(self, errors: tuple[str, ...]) -> None:
        self.errors = errors
        super().__init__("ARGUMENTS_INVALID", "; ".join(errors))


def _json_value(value: object, path: str = "<root>") -> object:
    """Convert supported Python values to the strict JSON data model."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RuntimeBindingError(
                "ARGUMENTS_NOT_JSON",
                f"{path}: non-finite numbers are not valid JSON",
            )
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise RuntimeBindingError(
                    "ARGUMENTS_NOT_JSON",
                    f"{path}: object keys must be strings",
                )
            result[key] = _json_value(nested, f"{path}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [
            _json_value(nested, f"{path}[{index}]")
            for index, nested in enumerate(value)
        ]
    raise RuntimeBindingError(
        "ARGUMENTS_NOT_JSON",
        f"{path}: unsupported value type {type(value).__name__}",
    )


def canonical_json_bytes(value: object) -> bytes:
    """Return RFC 8785 JCS bytes for one JSON-compatible value."""
    try:
        return rfc8785.dumps(cast(Any, _json_value(value)))
    except RuntimeBindingError:
        raise
    except Exception as exc:
        raise RuntimeBindingError(
            "CANONICALIZATION_FAILED",
            f"RFC 8785 canonicalization failed: {exc}",
        ) from exc


def compute_tool_contract_digest(contract: Mapping[str, Any]) -> str:
    """Return the RFC 8785 SHA-256 digest of a validated Tool Contract."""
    errors = tool_contract_errors(contract)
    if errors:
        raise ContractBindingError("CONTRACT_INVALID", "; ".join(errors))
    payload = canonical_json_bytes(contract)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def compute_arguments_digest(arguments: Mapping[str, Any]) -> str:
    """Return the RFC 8785 SHA-256 digest of normalized tool arguments."""
    payload = canonical_json_bytes(arguments)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(nested) for key, nested in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(nested) for key, nested in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _path_text(path: tuple[object, ...]) -> str:
    if not path:
        return "<root>"
    rendered = ""
    for part in path:
        rendered += f"[{part}]" if isinstance(part, int) else f".{part}"
    return rendered.lstrip(".")


def _contract_tool(
    contract: Mapping[str, Any],
    tool_id: str,
) -> Mapping[str, Any]:
    errors = tool_contract_errors(contract)
    if errors:
        raise ContractBindingError("CONTRACT_INVALID", "; ".join(errors))
    for tool in contract["tools"]:
        if tool["id"] == tool_id:
            return tool
    raise ContractBindingError(
        "TOOL_NOT_DECLARED",
        f"Tool Contract does not declare runtime tool '{tool_id}'",
    )


@dataclass(frozen=True, slots=True)
class BoundTool:
    """Immutable association between one contract digest and one exact callable."""

    contract_digest: str
    tool_id: str
    action: str
    input_schema: Mapping[str, Any]
    resource_patterns: tuple[str, ...]
    target: Callable[..., Any] = field(repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        if not callable(self.target):
            raise RuntimeBindingError(
                "TOOL_NOT_CALLABLE",
                f"Runtime target for '{self.tool_id}' is not callable",
            )
        object.__setattr__(
            self, "input_schema", _freeze(copy.deepcopy(dict(self.input_schema)))
        )
        object.__setattr__(self, "resource_patterns", tuple(self.resource_patterns))

    def normalize_arguments(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Bind Python call syntax into one JSON object before validation."""
        try:
            signature = inspect.signature(self.target, follow_wrapped=False)
        except (TypeError, ValueError) as exc:
            raise RuntimeBindingError(
                "TOOL_SIGNATURE_UNAVAILABLE",
                f"Cannot inspect bound tool '{self.tool_id}'",
            ) from exc

        unsupported = [
            parameter.name
            for parameter in signature.parameters.values()
            if parameter.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            )
        ]
        if unsupported:
            raise RuntimeBindingError(
                "TOOL_SIGNATURE_UNSUPPORTED",
                f"Tool '{self.tool_id}' uses unsupported parameters: "
                + ", ".join(unsupported),
            )

        try:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            normalized = _json_value(dict(bound.arguments))
        except TypeError as exc:
            raise ArgumentValidationError((str(exc),)) from exc
        if not isinstance(normalized, dict):
            raise RuntimeBindingError(
                "ARGUMENTS_NOT_OBJECT",
                "Normalized tool arguments must be a JSON object",
            )

        validator = Draft202012Validator(
            cast(Mapping[str, Any], _thaw(self.input_schema))
        )
        try:
            discovered = sorted(
                validator.iter_errors(normalized),
                key=lambda error: (
                    tuple(str(part) for part in error.absolute_path),
                    error.message,
                ),
            )
        except Exception as exc:
            raise ArgumentValidationError(
                (f"schema evaluation failed: {exc}",)
            ) from exc
        if discovered:
            raise ArgumentValidationError(
                tuple(
                    f"{_path_text(tuple(error.absolute_path))}: {error.message}"
                    for error in discovered
                )
            )
        return normalized

    def _validate_resource(self, resource: str | None) -> None:
        if not self.resource_patterns:
            return
        if resource is None or not resource.strip():
            raise RuntimeBindingError(
                "RESOURCE_REQUIRED",
                f"Tool '{self.tool_id}' requires a resource scope",
            )
        if not any(matches(pattern, resource) for pattern in self.resource_patterns):
            raise RuntimeBindingError(
                "RESOURCE_OUT_OF_SCOPE",
                f"Resource '{resource}' is outside Tool Contract scope for "
                f"'{self.tool_id}'",
            )

    def invoke(
        self,
        checker: PolicyChecker,
        *,
        agent_id: str,
        bundle_path: str = "",
        actor_id: str | None = None,
        resource: str | None = None,
        signals: Mapping[str, Any] | None = None,
        decision_sink: DecisionSink | None = None,
        receipt_sink: ReceiptSink | None = None,
        approval_token: Mapping[str, Any] | None = None,
        approval_trusted_keys: Mapping[str, TrustedKey] | None = None,
        replay_guard: ReplayGuard | None = None,
        binding_id: str | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
        tenant_id: str | None = None,
        delegation_chain: Sequence[Mapping[str, Any]] | None = None,
        delegation_trusted_keys: Mapping[str, DelegationTrustedKey] | None = None,
        delegation_audience: str | None = None,
        delegation_fan_out_guard: FanOutGuard | None = None,
        runtime_budget: RuntimeBudgetGuard | None = None,
        budget_scope: str | None = None,
        max_concurrency: int | None = None,
        rate_limit: int | None = None,
        rate_window_seconds: int | None = None,
        lease_ttl_seconds: int = 300,
        circuit_breaker: CircuitBreaker | None = None,
        failure_fingerprint: str | None = None,
        failure_threshold: int | None = None,
        args: tuple[Any, ...] = (),
        kwargs: Mapping[str, Any] | None = None,
    ) -> Any:
        """Authorize and invoke the exact bound callable with validated args."""
        invocation_id = request_id or str(uuid.uuid4())
        effective_binding_id = binding_id or (
            f"in-process:{self.contract_digest}:{self.tool_id}"
        )
        normalized: dict[str, Any] | None = None
        arguments_digest: str | None = None
        request: ActionRequest | None = None
        verified_approval: VerifiedApproval | None = None
        verified_delegation: VerifiedDelegation | None = None
        breaker_snapshot: BreakerSnapshot | None = None
        budget_snapshot: RuntimeLimitSnapshot | None = None
        budget_lease_id: str | None = None
        receipt_attempted = False
        effective_failure_fingerprint = failure_fingerprint or (
            f"{agent_id}:{self.tool_id}:{resource or '<none>'}"
        )

        def emit_receipt(
            *,
            authorization_result: str,
            side_effect_state: str,
            phase: str,
            reason: str = "",
            decision: Any = None,
            output_digest: str | None = None,
            error_code: str | None = None,
            breaker: BreakerSnapshot | None = None,
        ) -> None:
            nonlocal receipt_attempted
            if receipt_sink is None:
                return
            receipt_attempted = True
            receipt_sink.append(
                {
                    "schema_version": "1.0",
                    "receipt_id": str(uuid.uuid4()),
                    "check_id": f"check:{invocation_id}",
                    "phase": phase,
                    "session_id": session_id or "unspecified",
                    "binding_id": effective_binding_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": actor_id or agent_id,
                    "agent_id": agent_id,
                    "requested_tool_name": self.tool_id,
                    "tool_id": self.tool_id,
                    "authorization_result": authorization_result,
                    "side_effect_state": side_effect_state,
                    "matched_approved_binding": verified_approval is not None,
                    "registry_version": getattr(checker, "bundle_revision", 0),
                    "policy_bundle_digest": getattr(checker, "bundle_digest", ""),
                    "tool_descriptor_digest": self.contract_digest,
                    "normalized_argument_digest": arguments_digest or "",
                    "target_resource_scope": (
                        {"resource": resource} if resource is not None else {}
                    ),
                    "approval_id_or_lease_id": (
                        verified_approval.token_id if verified_approval else ""
                    ),
                    "request_id": request.request_id if request else invocation_id,
                    "decision_id": getattr(decision, "decision_id", ""),
                    "reason": reason,
                    "output_digest": output_digest,
                    "error_code": error_code,
                    "failure_fingerprint": (
                        effective_failure_fingerprint if circuit_breaker else None
                    ),
                    "breaker_state": breaker.state if breaker else None,
                    "breaker_count": breaker.current_count if breaker else None,
                    "delegation_id": (
                        verified_delegation.delegation_id
                        if verified_delegation
                        else None
                    ),
                    "delegation_depth": (
                        verified_delegation.delegation_depth
                        if verified_delegation
                        else None
                    ),
                    "budget_scope": budget_snapshot.scope if budget_snapshot else None,
                    "budget_lease_id": budget_snapshot.lease_id if budget_snapshot else None,
                    "budget_active_leases": (
                        budget_snapshot.active_leases if budget_snapshot else None
                    ),
                    "budget_rate_events": (
                        budget_snapshot.rate_events if budget_snapshot else None
                    ),
                }
            )

        def release_budget() -> None:
            nonlocal budget_lease_id
            if runtime_budget is None or budget_lease_id is None:
                return
            lease_id = budget_lease_id
            budget_lease_id = None
            runtime_budget.release(lease_id)

        try:
            normalized = self.normalize_arguments(*args, **dict(kwargs or {}))
            self._validate_resource(resource)
            arguments_digest = compute_arguments_digest(normalized)

            effective_signals = dict(signals or {})
            if delegation_chain is not None:
                if not delegation_trusted_keys:
                    raise DelegationVerificationError(
                        "DELEGATION_TRUST_ROOT_REQUIRED",
                        "delegation_trusted_keys are required for a delegation chain",
                    )
                if delegation_audience is None:
                    raise DelegationVerificationError(
                        "DELEGATION_AUDIENCE_REQUIRED",
                        "delegation_audience is required for a delegation chain",
                    )
                verified_chain = verify_delegation_chain(
                    delegation_chain,
                    trusted_keys=delegation_trusted_keys,
                    expected_audience=delegation_audience,
                    expected_subject_agent_id=agent_id,
                    expected_action=self.action,
                    expected_resource_scope=resource,
                    expected_session_id=session_id,
                    expected_tenant_id=tenant_id,
                    fan_out_guard=delegation_fan_out_guard,
                )
                verified_delegation = verified_chain[-1]
                if "delegation" in effective_signals:
                    raise DelegationVerificationError(
                        "DELEGATION_INPUT_AMBIGUOUS",
                        "pass either delegation_chain or signals['delegation'], not both",
                    )
                effective_signals["delegation"] = (
                    verified_delegation.as_policy_signal()
                )
            if approval_token is not None:
                if "approval" in effective_signals:
                    raise ApprovalVerificationError(
                        "APPROVAL_INPUT_AMBIGUOUS",
                        "pass either approval_token or signals['approval'], not both",
                    )
                if not approval_trusted_keys:
                    raise ApprovalVerificationError(
                        "APPROVAL_TRUST_ROOT_REQUIRED",
                        "approval_trusted_keys are required for a signed approval",
                    )
                verified_approval = verify_approval_token(
                    approval_token,
                    trusted_keys=approval_trusted_keys,
                    expected_agent_id=agent_id,
                    expected_action=self.action,
                    expected_tool_id=self.tool_id,
                    expected_resource=resource,
                    expected_arguments_digest=arguments_digest,
                    expected_session_id=session_id,
                    expected_tenant_id=tenant_id,
                    replay_guard=replay_guard,
                )
                effective_signals["approval"] = verified_approval.as_policy_signal()

            def request_factory(context: Any) -> ActionRequest:
                nonlocal request
                request = ActionRequest(
                    request_id=invocation_id,
                    agent_id=agent_id,
                    action=self.action,
                    tool_id=self.tool_id,
                    actor_id=actor_id,
                    resource=resource,
                    arguments_digest=arguments_digest,
                    signals=effective_signals,
                    approval_id=(
                        verified_approval.token_id if verified_approval else None
                    ),
                    session_id=session_id,
                    tenant_id=tenant_id,
                    environment=context.environment,
                )
                if (
                    verified_approval is not None
                    and verified_approval.request_digest is not None
                    and verified_approval.request_digest != request.request_digest
                ):
                    raise ApprovalVerificationError(
                        "APPROVAL_REQUEST_MISMATCH",
                        "request digest does not match",
                    )
                return request

            gate = GovernanceGate(
                agent_id=agent_id,
                action=self.action,
                tool_id=self.tool_id,
                bundle_path=bundle_path,
                checker=checker,
                decision_sink=decision_sink,
                request_factory=request_factory,
            )
            decision = gate.authorize((), normalized)
            if circuit_breaker is not None:
                if failure_threshold is None:
                    raise RuntimeBindingError(
                        "BREAKER_CONFIG_REQUIRED",
                        "failure_threshold is required when circuit_breaker is set",
                    )
                breaker_snapshot = circuit_breaker.before_dispatch(
                    effective_failure_fingerprint,
                    failure_threshold,
                )
            if runtime_budget is not None:
                if budget_scope is None:
                    raise RuntimeBindingError(
                        "BUDGET_SCOPE_REQUIRED",
                        "budget_scope is required when runtime_budget is set",
                    )
                budget_lease_id = f"lease:{invocation_id}"
                budget_snapshot = runtime_budget.acquire(
                    budget_scope,
                    budget_lease_id,
                    max_concurrency=max_concurrency,
                    rate_limit=rate_limit,
                    rate_window_seconds=rate_window_seconds,
                    lease_ttl_seconds=lease_ttl_seconds,
                )
            emit_receipt(
                authorization_result="allowed",
                side_effect_state="side_effect_attempted",
                phase="pre_dispatch",
                decision=decision,
                breaker=breaker_snapshot,
            )
            try:
                result = self.target(**normalized)
            except Exception as exc:
                breaker_error: CircuitBreakerError | None = None
                if circuit_breaker is not None and failure_threshold is not None:
                    try:
                        breaker_snapshot = circuit_breaker.record_failure(
                            effective_failure_fingerprint,
                            failure_threshold,
                        )
                    except CircuitBreakerError as update_error:
                        breaker_error = update_error
                emit_receipt(
                    authorization_result="allowed",
                    side_effect_state="side_effect_attempted",
                    phase="completed",
                    reason="tool raised after authorized dispatch",
                    decision=decision,
                    error_code=type(exc).__name__,
                    breaker=breaker_snapshot,
                )
                if breaker_error is not None:
                    raise breaker_error from exc
                raise
            if circuit_breaker is not None:
                try:
                    breaker_snapshot = circuit_breaker.record_success(
                        effective_failure_fingerprint
                    )
                except CircuitBreakerError as update_error:
                    emit_receipt(
                        authorization_result="allowed",
                        side_effect_state="side_effect_attempted",
                        phase="completed",
                        reason="tool succeeded but breaker state was not persisted",
                        decision=decision,
                        error_code=update_error.code,
                        breaker=breaker_snapshot,
                    )
                    raise
            output_digest: str | None = None
            try:
                output_digest = compute_arguments_digest({"output": result})
            except RuntimeBindingError:
                pass
            emit_receipt(
                authorization_result="allowed",
                side_effect_state="side_effect_attempted",
                phase="completed",
                decision=decision,
                output_digest=output_digest,
                breaker=breaker_snapshot,
            )
            return result
        except GovernanceDeniedError as exc:
            if not receipt_attempted:
                emit_receipt(
                    authorization_result="denied",
                    side_effect_state="blocked_before_side_effect",
                    phase="pre_dispatch",
                    reason=str(exc.decision.reason_code),
                    decision=exc.decision,
                    error_code=str(exc.decision.reason_code),
                )
            raise
        except (
            ApprovalVerificationError,
            DelegationVerificationError,
            FanOutError,
            RuntimeLimitError,
            RuntimeBindingError,
        ) as exc:
            if not receipt_attempted:
                reapproval_codes = {
                    "APPROVAL_EXPIRED",
                    "APPROVAL_NOT_YET_VALID",
                    "APPROVAL_TARGET_MISMATCH",
                    "APPROVAL_REQUEST_MISMATCH",
                    "APPROVAL_REPLAYED",
                    "APPROVAL_REPLAY_GUARD_REQUIRED",
                }
                if getattr(exc, "code", "") in {
                    "APPROVAL_EXPIRED",
                    "DELEGATION_EXPIRED",
                }:
                    result = "expired"
                elif getattr(exc, "code", "") in reapproval_codes or getattr(
                    exc, "code", ""
                ) in {
                    "DELEGATION_EXPIRED",
                    "DELEGATION_NOT_YET_VALID",
                    "DELEGATION_CONTEXT_MISMATCH",
                    "DELEGATION_REVOKED",
                    "DELEGATION_FANOUT_UNREGISTERED",
                    "DELEGATION_FANOUT_GUARD_REQUIRED",
                }:
                    result = "reapproval_required"
                else:
                    result = "denied"
                emit_receipt(
                    authorization_result=result,
                    side_effect_state="blocked_before_side_effect",
                    phase="pre_dispatch",
                    reason=str(exc),
                    error_code=exc.code,
                )
            raise
        except CircuitBreakerError as exc:
            if not receipt_attempted:
                emit_receipt(
                    authorization_result="denied",
                    side_effect_state="blocked_before_side_effect",
                    phase="pre_dispatch",
                    reason=str(exc),
                    error_code=exc.code,
                    breaker=getattr(exc, "snapshot", None),
                )
            raise
        finally:
            release_budget()


def bind_tool(
    reviewed_contract: Mapping[str, Any],
    observed_contract: Mapping[str, Any],
    *,
    tool_id: str,
    target: Callable[..., Any],
) -> BoundTool:
    """Bind one exact target after comparing reviewed and observed contracts."""
    reviewed_digest = compute_tool_contract_digest(reviewed_contract)
    observed_digest = compute_tool_contract_digest(observed_contract)
    if not hmac.compare_digest(reviewed_digest, observed_digest):
        raise ContractBindingError(
            "CONTRACT_DRIFT",
            f"Reviewed and observed Tool Contract digests differ for '{tool_id}'",
        )
    tool = _contract_tool(reviewed_contract, tool_id)
    return BoundTool(
        contract_digest=reviewed_digest,
        tool_id=tool_id,
        action=tool["action"],
        input_schema=tool["input_schema"],
        resource_patterns=tuple(tool["resource_patterns"]),
        target=target,
    )


@dataclass(frozen=True, slots=True)
class BoundToolRegistry:
    """Immutable map from reviewed tool IDs to exact runtime callables."""

    contract_digest: str
    tools: Mapping[str, BoundTool]

    @classmethod
    def bind(
        cls,
        reviewed_contract: Mapping[str, Any],
        observed_contract: Mapping[str, Any],
        runtime_tools: Mapping[str, Callable[..., Any]],
    ) -> BoundToolRegistry:
        reviewed_digest = compute_tool_contract_digest(reviewed_contract)
        observed_digest = compute_tool_contract_digest(observed_contract)
        if not hmac.compare_digest(reviewed_digest, observed_digest):
            raise ContractBindingError(
                "CONTRACT_DRIFT",
                "Reviewed and observed Tool Contract digests differ",
            )
        declared = {tool["id"] for tool in reviewed_contract["tools"]}
        supplied = set(runtime_tools)
        if declared != supplied:
            missing = sorted(declared - supplied)
            unexpected = sorted(supplied - declared)
            detail = []
            if missing:
                detail.append("missing: " + ", ".join(missing))
            if unexpected:
                detail.append("unexpected: " + ", ".join(unexpected))
            raise ContractBindingError("RUNTIME_TOOL_SET_CHANGED", "; ".join(detail))
        bound = {
            tool_id: bind_tool(
                reviewed_contract,
                observed_contract,
                tool_id=tool_id,
                target=runtime_tools[tool_id],
            )
            for tool_id in sorted(declared)
        }
        return cls(reviewed_digest, MappingProxyType(bound))

    def get(self, tool_id: str) -> BoundTool:
        try:
            return self.tools[tool_id]
        except KeyError as exc:
            raise RuntimeBindingError(
                "TOOL_NOT_BOUND",
                f"Tool '{tool_id}' is not in the immutable bound registry",
            ) from exc

    def invoke(self, tool_id: str, checker: PolicyChecker, **kwargs: Any) -> Any:
        """Resolve only from the immutable bound map, then dispatch."""
        return self.get(tool_id).invoke(checker, **kwargs)


__all__ = [
    "ArgumentValidationError",
    "BoundTool",
    "BoundToolRegistry",
    "ContractBindingError",
    "RuntimeBindingError",
    "bind_tool",
    "canonical_json_bytes",
    "compute_arguments_digest",
    "compute_tool_contract_digest",
]
