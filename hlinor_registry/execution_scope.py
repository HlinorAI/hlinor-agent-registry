"""Explicit project/workspace scope for governed runtime actions."""

from __future__ import annotations

from dataclasses import dataclass


class ExecutionScopeError(ValueError):
    """Raised when a project/workspace scope is malformed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class ExecutionScope:
    """Opaque, explicit scope that binds one action to one workspace."""

    project_id: str
    workspace_id: str

    def __post_init__(self) -> None:
        for field, value in (
            ("project_id", self.project_id),
            ("workspace_id", self.workspace_id),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ExecutionScopeError(
                    "EXECUTION_SCOPE_INVALID",
                    f"{field} must be a non-empty string",
                )
            if value != value.strip():
                raise ExecutionScopeError(
                    "EXECUTION_SCOPE_INVALID",
                    f"{field} cannot contain outer whitespace",
                )

    def as_policy_signal(self) -> dict[str, object]:
        """Return the explicit scope facts for the request digest and policy."""
        return {
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "verified": True,
        }


__all__ = ["ExecutionScope", "ExecutionScopeError"]
