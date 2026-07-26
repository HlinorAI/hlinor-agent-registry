"""Immutable request model for exact policy evaluations."""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise TypeError("ActionRequest attribute keys must be strings")
            frozen[key] = _freeze_json(nested_value)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("ActionRequest attributes cannot contain non-finite numbers")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(
        f"Unsupported ActionRequest attribute value: {type(value).__name__}"
    )


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(nested_value) for key, nested_value in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True)
class ActionRequest:
    """An immutable, digestible request evaluated against one policy bundle."""

    agent_id: str
    action: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    actor_id: str | None = None
    tool_id: str | None = None
    resource: str | None = None
    arguments_digest: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)
    approval_id: str | None = None
    session_id: str | None = None
    tenant_id: str | None = None
    environment: str | None = None
    requested_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        for field_name in ("request_id", "agent_id", "action", "requested_at"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"ActionRequest {field_name} must be a non-empty string"
                )
            if value != value.strip():
                raise ValueError(
                    f"ActionRequest {field_name} cannot contain outer whitespace"
                )

        for field_name in (
            "actor_id",
            "tool_id",
            "resource",
            "arguments_digest",
            "approval_id",
            "session_id",
            "tenant_id",
            "environment",
        ):
            value = getattr(self, field_name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(
                    f"ActionRequest {field_name} must be a non-empty string when set"
                )
            if isinstance(value, str) and value != value.strip():
                raise ValueError(
                    f"ActionRequest {field_name} cannot contain outer whitespace"
                )

        object.__setattr__(self, "attributes", _freeze_json(self.attributes))

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON-compatible representation used for hashing."""
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "actor_id": self.actor_id,
            "tool_id": self.tool_id,
            "resource": self.resource,
            "arguments_digest": self.arguments_digest,
            "attributes": _thaw_json(self.attributes),
            "approval_id": self.approval_id,
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "requested_at": self.requested_at,
        }

    @property
    def request_digest(self) -> str:
        """Return the SHA-256 digest of the canonical request representation."""
        payload = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"
