"""Policy decision types and exceptions."""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# Re-exported for callers that historically imported these from this module.
# The definitions live in .enums so that a decision built by PolicyChecker and a
# decision built here can never disagree about which reason codes exist.
from .enums import DecisionResult, ReasonCode

__all__ = [
    "DecisionResult",
    "GovernanceDeniedError",
    "PolicyDecision",
    "ReasonCode",
]


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable record of a policy evaluation.

    Attributes:
        decision_id: Unique identifier for this decision
        agent_id: The agent requesting the action
        action: The action being evaluated
        result: Either 'allowed' or 'denied'
        reason_code: Machine-readable reason for the decision
        checked_at: ISO 8601 timestamp of when the check occurred
    """

    decision_id: str
    agent_id: str
    action: str
    result: DecisionResult
    reason_code: ReasonCode
    checked_at: str
    request_id: str = ""
    bundle_digest: str = ""
    request_digest: str = ""
    matched_policy_ids: tuple[str, ...] = ()
    enforcement_mode: str = "strict"
    environment: str | None = None
    actor_id: str | None = None
    bundle_schema_version: str = ""
    compiler_version: str = ""
    bundle_revision: int = 0
    policy_revision: str = ""
    signature_key_id: str | None = None
    signature_key_fingerprint: str | None = None
    signature_issuer: str | None = None
    signature_issued_at: str | None = None
    signature_expires_at: str | None = None

    @classmethod
    def deny(
        cls,
        agent_id: str,
        action: str,
        reason_code: ReasonCode | str,
        **provenance: Any,
    ) -> "PolicyDecision":
        """Create a denial decision."""
        return cls(
            decision_id=str(uuid.uuid4()),
            agent_id=agent_id,
            action=action,
            result=DecisionResult.DENIED,
            reason_code=ReasonCode(reason_code),
            checked_at=datetime.now(timezone.utc).isoformat(),
            **provenance,
        )

    @classmethod
    def allow(cls, agent_id: str, action: str, **provenance: Any) -> "PolicyDecision":
        """Create an allowance decision."""
        return cls(
            decision_id=str(uuid.uuid4()),
            agent_id=agent_id,
            action=action,
            result=DecisionResult.ALLOWED,
            reason_code=ReasonCode.EXPLICITLY_ALLOWED,
            checked_at=datetime.now(timezone.utc).isoformat(),
            **provenance,
        )

    @property
    def allowed(self) -> bool:
        """Check if the action was allowed."""
        return self.result is DecisionResult.ALLOWED

    @property
    def denied(self) -> bool:
        """Check if the action was denied."""
        return self.result is DecisionResult.DENIED

    @property
    def evaluated_at(self) -> str:
        """Compatibility-neutral name for the policy evaluation timestamp."""
        return self.checked_at


class GovernanceDeniedError(PermissionError):
    """Raised when a governance policy denies an action.

    Attributes:
        decision: The PolicyDecision that denied the action
    """

    def __init__(self, decision: PolicyDecision):
        self.decision = decision
        super().__init__(
            f"Action '{decision.action}' denied for agent '{decision.agent_id}': "
            f"{decision.reason_code} (decision_id={decision.decision_id})"
        )
