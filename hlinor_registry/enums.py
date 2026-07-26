"""Centralized enums for policy decisions."""

from enum import Enum


class DecisionResult(str, Enum):
    """Canonical result of a policy evaluation."""

    ALLOWED = "allowed"
    DENIED = "denied"


class ReasonCode(str, Enum):
    """Standardized reason codes for auditability."""

    EXPLICITLY_ALLOWED = "EXPLICITLY_ALLOWED"
    ACTION_BLOCKLISTED = "ACTION_BLOCKLISTED"
    ACTION_NOT_ALLOWLISTED = "ACTION_NOT_ALLOWLISTED"
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    BUNDLE_INTEGRITY_FAILED = "BUNDLE_INTEGRITY_FAILED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    POLICY_EVALUATION_ERROR = "POLICY_EVALUATION_ERROR"
