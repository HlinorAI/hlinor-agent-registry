"""Policy decision types and exceptions."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
import uuid


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
    result: Literal["allowed", "denied"]
    reason_code: str
    checked_at: str
    
    @classmethod
    def deny(cls, agent_id: str, action: str, reason_code: str) -> "PolicyDecision":
        """Create a denial decision."""
        return cls(
            decision_id=str(uuid.uuid4()),
            agent_id=agent_id,
            action=action,
            result="denied",
            reason_code=reason_code,
            checked_at=datetime.now(timezone.utc).isoformat(),
        )
    
    @classmethod
    def allow(cls, agent_id: str, action: str) -> "PolicyDecision":
        """Create an allowance decision."""
        return cls(
            decision_id=str(uuid.uuid4()),
            agent_id=agent_id,
            action=action,
            result="allowed",
            reason_code="EXPLICITLY_ALLOWED",
            checked_at=datetime.now(timezone.utc).isoformat(),
        )
    
    @property
    def allowed(self) -> bool:
        """Check if the action was allowed."""
        return self.result == "allowed"
    
    @property
    def denied(self) -> bool:
        """Check if the action was denied."""
        return self.result == "denied"


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