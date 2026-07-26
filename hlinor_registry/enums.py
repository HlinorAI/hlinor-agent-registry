"""Canonical enums for policy decisions.

This module is the single source of truth. ``hlinor_registry.decision``
re-exports these names for callers that import them from there; do not add a
second definition. Two copies that drift apart are a fail-closed hazard: a
reason code present in one copy and missing from the other raises ``ValueError``
inside the code path that constructs a denial.
"""

from enum import Enum


class DecisionResult(str, Enum):
    """Canonical result of a policy evaluation."""

    ALLOWED = "allowed"
    DENIED = "denied"

    def __str__(self) -> str:
        return self.value


class ReasonCode(str, Enum):
    """Standardized reason codes for auditability.

    Members are part of the audit-event contract. Add new codes here only, and
    do not remove or rename an existing one: emitted decisions and JSONL audit
    records carry these string values.
    """

    EXPLICITLY_ALLOWED = "EXPLICITLY_ALLOWED"
    ACTION_BLOCKLISTED = "ACTION_BLOCKLISTED"
    ACTION_NOT_ALLOWLISTED = "ACTION_NOT_ALLOWLISTED"
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    BUNDLE_INTEGRITY_FAILED = "BUNDLE_INTEGRITY_FAILED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    POLICY_EVALUATION_ERROR = "POLICY_EVALUATION_ERROR"

    def __str__(self) -> str:
        return self.value
