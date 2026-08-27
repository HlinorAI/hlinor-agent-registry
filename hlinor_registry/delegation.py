"""Authenticated agent delegation and bounded child-delegation state.

Delegation is deliberately narrower than agent identity in a host platform. It
proves that a configured signing key for one agent authorized another agent for
an explicit audience, scope, and time window. It does not attest the process,
workload, model, or transport carrying the token.
"""

from __future__ import annotations

import base64
import binascii
import copy
import sqlite3
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, cast

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DELEGATION_SCHEMA_VERSION = "1.0"
DELEGATION_SIGNATURE_ALGORITHM = "Ed25519"
_DOMAIN_DELEGATION = "hlinor/agent-delegation/v1"
_SIGNATURE_FIELDS = {"algorithm", "key_id", "issuer", "value"}


class DelegationVerificationError(ValueError):
    """Raised when a delegation token or chain cannot be trusted."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class FanOutError(RuntimeError):
    """Raised when bounded delegation state cannot be checked safely."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class DelegationTrustedKey:
    """A signing key bound to one configured agent principal."""

    key_id: str
    agent_id: str
    public_key: Ed25519PublicKey
    issuer: str | None = None


@dataclass(frozen=True, slots=True)
class VerifiedDelegation:
    """Verified authority facts safe to use at a runtime boundary."""

    delegation_id: str
    issuer_agent_id: str
    subject_agent_id: str
    audience: str
    allowed_actions: tuple[str, ...]
    allowed_resource_scopes: tuple[str, ...]
    session_id: str | None
    tenant_id: str | None
    project_id: str | None
    workspace_id: str | None
    parent_delegation_id: str | None
    delegation_depth: int
    max_depth: int
    max_fan_out: int
    issued_at: str
    expires_at: str
    nonce: str
    key_id: str
    issuer: str

    def as_policy_signal(self) -> dict[str, Any]:
        """Return only verified identity facts for legacy policy consumers."""
        return {
            "delegation_id": self.delegation_id,
            "issuer_agent_id": self.issuer_agent_id,
            "subject_agent_id": self.subject_agent_id,
            "audience": self.audience,
            "verified": True,
        }


class FanOutGuard(Protocol):
    """Atomic state used to register and verify child delegations."""

    def reserve(
        self,
        parent_delegation_id: str,
        child_delegation_id: str,
        limit: int,
        expires_at: str,
    ) -> bool:
        """Register one child if the parent's limit has not been reached."""

    def is_registered(
        self, parent_delegation_id: str, child_delegation_id: str
    ) -> bool:
        """Return whether this exact child was registered under this parent."""

    def is_revoked(self, delegation_id: str) -> bool:
        """Return whether a delegation has been revoked."""

    def revoke(self, delegation_id: str) -> None:
        """Revoke a delegation ID for future verification."""


def _canonical(value: object) -> bytes:
    try:
        return rfc8785.dumps(value)  # type: ignore[arg-type]
    except Exception as exc:
        raise DelegationVerificationError(
            "DELEGATION_CANONICALIZATION_FAILED",
            "delegation payload is not canonicalizable",
        ) from exc


def _validate_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise DelegationVerificationError(
            "DELEGATION_FIELD_INVALID",
            f"{field} must be a non-empty string",
        )


def _validate_optional_text(value: object, field: str) -> None:
    if value is not None:
        _validate_text(value, field)


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise DelegationVerificationError(
            "DELEGATION_TIMESTAMP_INVALID",
            f"{field} must be a non-empty ISO-8601 string",
        )
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise DelegationVerificationError(
            "DELEGATION_TIMESTAMP_INVALID",
            f"{field} is not valid ISO-8601",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DelegationVerificationError(
            "DELEGATION_TIMESTAMP_INVALID",
            f"{field} must include a timezone",
        )
    return parsed.astimezone(timezone.utc)


def _check_window(
    issued_at: str,
    expires_at: str,
    *,
    current_time: datetime | None,
    clock_skew_seconds: int,
) -> None:
    if clock_skew_seconds < 0:
        raise ValueError("clock_skew_seconds cannot be negative")
    issued = _parse_time(issued_at, "issued_at")
    expires = _parse_time(expires_at, "expires_at")
    if expires <= issued:
        raise DelegationVerificationError(
            "DELEGATION_WINDOW_INVALID",
            "expires_at must be after issued_at",
        )
    now = current_time or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("current_time must include a timezone")
    now = now.astimezone(timezone.utc)
    skew = timedelta(seconds=clock_skew_seconds)
    if issued > now + skew:
        raise DelegationVerificationError(
            "DELEGATION_NOT_YET_VALID",
            "delegation was issued in the future",
        )
    if expires < now - skew:
        raise DelegationVerificationError(
            "DELEGATION_EXPIRED",
            "delegation has expired",
        )


def _scope_list(values: object, field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise DelegationVerificationError(
            "DELEGATION_FIELD_INVALID",
            f"{field} must be a list of strings",
        )
    normalized: list[str] = []
    for value in cast(Sequence[object], values):
        _validate_text(value, field)
        assert isinstance(value, str)
        normalized.append(value)
    if not normalized:
        raise DelegationVerificationError(
            "DELEGATION_FIELD_INVALID",
            f"{field} must not be empty",
        )
    if len(set(normalized)) != len(normalized):
        raise DelegationVerificationError(
            "DELEGATION_FIELD_INVALID",
            f"{field} must not contain duplicates",
        )
    return tuple(sorted(normalized))


def _validate_limits(
    delegation_depth: object,
    max_depth: object,
    max_fan_out: object,
    parent_delegation_id: object,
) -> tuple[int, int, int]:
    values = (
        (delegation_depth, "delegation_depth"),
        (max_depth, "max_depth"),
        (max_fan_out, "max_fan_out"),
    )
    for value, field in values:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise DelegationVerificationError(
                "DELEGATION_LIMIT_INVALID",
                f"{field} must be a non-negative integer",
            )
    assert isinstance(delegation_depth, int)
    assert isinstance(max_depth, int)
    assert isinstance(max_fan_out, int)
    if max_depth < delegation_depth:
        raise DelegationVerificationError(
            "DELEGATION_LIMIT_INVALID",
            "max_depth must be at least delegation_depth",
        )
    if parent_delegation_id is None and delegation_depth != 0:
        raise DelegationVerificationError(
            "DELEGATION_CHAIN_INVALID",
            "root delegation must have depth zero",
        )
    if parent_delegation_id is not None and delegation_depth == 0:
        raise DelegationVerificationError(
            "DELEGATION_CHAIN_INVALID",
            "child delegation must reference a parent",
        )
    return delegation_depth, max_depth, max_fan_out


def _signed_payload(token: Mapping[str, Any]) -> bytes:
    payload = copy.deepcopy(dict(token))
    signature = payload.get("signature")
    if not isinstance(signature, Mapping):
        raise DelegationVerificationError(
            "DELEGATION_SIGNATURE_INVALID",
            "signature must be an object",
        )
    payload["signature"] = dict(signature)
    payload["signature"]["value"] = ""
    return _canonical({"domain": _DOMAIN_DELEGATION, "payload": payload})


def sign_delegation_token(
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
    issuer: str,
    issuer_agent_id: str,
    subject_agent_id: str,
    audience: str,
    allowed_actions: Sequence[str],
    allowed_resource_scopes: Sequence[str],
    issued_at: str,
    expires_at: str,
    nonce: str,
    session_id: str | None = None,
    tenant_id: str | None = None,
    project_id: str | None = None,
    workspace_id: str | None = None,
    parent_delegation_id: str | None = None,
    delegation_depth: int = 0,
    max_depth: int = 0,
    max_fan_out: int = 0,
    delegation_id: str | None = None,
) -> dict[str, Any]:
    """Create a signed delegation token for one bounded child principal."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    for field, required_value in (
        ("key_id", key_id),
        ("issuer", issuer),
        ("issuer_agent_id", issuer_agent_id),
        ("subject_agent_id", subject_agent_id),
        ("audience", audience),
        ("nonce", nonce),
    ):
        _validate_text(required_value, field)
    if issuer_agent_id == subject_agent_id:
        raise DelegationVerificationError(
            "DELEGATION_CHAIN_INVALID",
            "issuer_agent_id and subject_agent_id must differ",
        )
    for field, optional_value in (
        ("session_id", session_id),
        ("tenant_id", tenant_id),
        ("project_id", project_id),
        ("workspace_id", workspace_id),
        ("parent_delegation_id", parent_delegation_id),
    ):
        _validate_optional_text(optional_value, field)
    effective_delegation_id: str | None = delegation_id
    if effective_delegation_id is None:
        effective_delegation_id = str(uuid.uuid4())
    assert isinstance(effective_delegation_id, str)
    _validate_text(effective_delegation_id, "delegation_id")
    actions = _scope_list(allowed_actions, "allowed_actions")
    resources = _scope_list(allowed_resource_scopes, "allowed_resource_scopes")
    _validate_limits(
        delegation_depth,
        max_depth,
        max_fan_out,
        parent_delegation_id,
    )
    _check_window(
        issued_at,
        expires_at,
        current_time=None,
        clock_skew_seconds=0,
    )
    token: dict[str, Any] = {
        "schema_version": DELEGATION_SCHEMA_VERSION,
        "delegation_id": effective_delegation_id,
        "issuer_agent_id": issuer_agent_id,
        "subject_agent_id": subject_agent_id,
        "audience": audience,
        "allowed_actions": list(actions),
        "allowed_resource_scopes": list(resources),
        "session_id": session_id,
        "tenant_id": tenant_id,
        "project_id": project_id,
        "workspace_id": workspace_id,
        "parent_delegation_id": parent_delegation_id,
        "delegation_depth": delegation_depth,
        "max_depth": max_depth,
        "max_fan_out": max_fan_out,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
        "signature": {
            "algorithm": DELEGATION_SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "issuer": issuer,
            "value": "",
        },
    }
    token["signature"]["value"] = base64.b64encode(
        private_key.sign(_signed_payload(token))
    ).decode("ascii")
    return token


def verify_delegation_token(
    token: Mapping[str, Any],
    *,
    trusted_keys: Mapping[str, DelegationTrustedKey],
    expected_audience: str,
    expected_subject_agent_id: str | None = None,
    expected_session_id: str | None = None,
    expected_tenant_id: str | None = None,
    expected_project_id: str | None = None,
    expected_workspace_id: str | None = None,
    current_time: datetime | None = None,
    clock_skew_seconds: int = 60,
) -> VerifiedDelegation:
    """Verify one delegation token and bind it to the expected context."""
    if not isinstance(token, Mapping):
        raise DelegationVerificationError(
            "DELEGATION_INVALID", "token must be an object"
        )
    allowed = {
        "schema_version",
        "delegation_id",
        "issuer_agent_id",
        "subject_agent_id",
        "audience",
        "allowed_actions",
        "allowed_resource_scopes",
        "session_id",
        "tenant_id",
        "project_id",
        "workspace_id",
        "parent_delegation_id",
        "delegation_depth",
        "max_depth",
        "max_fan_out",
        "issued_at",
        "expires_at",
        "nonce",
        "signature",
    }
    unknown = set(token).difference(allowed)
    if unknown:
        raise DelegationVerificationError(
            "DELEGATION_INVALID",
            f"unknown fields: {sorted(unknown)}",
        )
    if token.get("schema_version") != DELEGATION_SCHEMA_VERSION:
        raise DelegationVerificationError(
            "DELEGATION_VERSION_UNSUPPORTED",
            f"expected {DELEGATION_SCHEMA_VERSION}",
        )
    for field in (
        "delegation_id",
        "issuer_agent_id",
        "subject_agent_id",
        "audience",
        "issued_at",
        "expires_at",
        "nonce",
    ):
        _validate_text(token.get(field), field)
    if token["issuer_agent_id"] == token["subject_agent_id"]:
        raise DelegationVerificationError(
            "DELEGATION_CHAIN_INVALID",
            "issuer_agent_id and subject_agent_id must differ",
        )
    actions = _scope_list(token.get("allowed_actions"), "allowed_actions")
    resources = _scope_list(
        token.get("allowed_resource_scopes"),
        "allowed_resource_scopes",
    )
    parent_delegation_id = token.get("parent_delegation_id")
    _validate_optional_text(parent_delegation_id, "parent_delegation_id")
    delegation_depth, max_depth, max_fan_out = _validate_limits(
        token.get("delegation_depth"),
        token.get("max_depth"),
        token.get("max_fan_out"),
        parent_delegation_id,
    )
    for field, expected in (
        ("audience", expected_audience),
        ("subject_agent_id", expected_subject_agent_id),
        ("session_id", expected_session_id),
        ("tenant_id", expected_tenant_id),
        ("project_id", expected_project_id),
        ("workspace_id", expected_workspace_id),
    ):
        if expected is not None and token.get(field) != expected:
            raise DelegationVerificationError(
                "DELEGATION_CONTEXT_MISMATCH",
                f"{field} does not match the requested context",
            )
    signature = token.get("signature")
    if not isinstance(signature, Mapping) or set(signature) != _SIGNATURE_FIELDS:
        raise DelegationVerificationError(
            "DELEGATION_SIGNATURE_INVALID",
            "signature fields are invalid",
        )
    if signature.get("algorithm") != DELEGATION_SIGNATURE_ALGORITHM:
        raise DelegationVerificationError(
            "DELEGATION_SIGNATURE_INVALID",
            "unsupported signature algorithm",
        )
    key_id = signature.get("key_id")
    issuer = signature.get("issuer")
    _validate_text(key_id, "signature.key_id")
    _validate_text(issuer, "signature.issuer")
    assert isinstance(key_id, str)
    assert isinstance(issuer, str)
    trusted = trusted_keys.get(key_id)
    if trusted is None:
        raise DelegationVerificationError(
            "DELEGATION_KEY_UNTRUSTED",
            f"unknown key: {key_id}",
        )
    if trusted.agent_id != token["issuer_agent_id"]:
        raise DelegationVerificationError(
            "DELEGATION_ISSUER_UNBOUND",
            "signing key is not bound to issuer_agent_id",
        )
    if trusted.issuer is not None and trusted.issuer != issuer:
        raise DelegationVerificationError(
            "DELEGATION_ISSUER_INVALID",
            "issuer does not match trusted key",
        )
    encoded = signature.get("value")
    if not isinstance(encoded, str) or not encoded:
        raise DelegationVerificationError(
            "DELEGATION_SIGNATURE_INVALID",
            "signature value is missing",
        )
    try:
        signature_bytes = base64.b64decode(encoded, validate=True)
        trusted.public_key.verify(signature_bytes, _signed_payload(token))
    except (binascii.Error, ValueError, InvalidSignature) as exc:
        raise DelegationVerificationError(
            "DELEGATION_SIGNATURE_INVALID",
            "signature verification failed",
        ) from exc
    _check_window(
        token["issued_at"],
        token["expires_at"],
        current_time=current_time,
        clock_skew_seconds=clock_skew_seconds,
    )
    return VerifiedDelegation(
        delegation_id=token["delegation_id"],
        issuer_agent_id=token["issuer_agent_id"],
        subject_agent_id=token["subject_agent_id"],
        audience=token["audience"],
        allowed_actions=actions,
        allowed_resource_scopes=resources,
        session_id=token.get("session_id"),
        tenant_id=token.get("tenant_id"),
        project_id=token.get("project_id"),
        workspace_id=token.get("workspace_id"),
        parent_delegation_id=parent_delegation_id,
        delegation_depth=delegation_depth,
        max_depth=max_depth,
        max_fan_out=max_fan_out,
        issued_at=token["issued_at"],
        expires_at=token["expires_at"],
        nonce=token["nonce"],
        key_id=key_id,
        issuer=issuer,
    )


def reserve_delegation_child(
    parent: VerifiedDelegation,
    child: VerifiedDelegation,
    *,
    fan_out_guard: FanOutGuard,
) -> None:
    """Atomically register a direct child before distributing its token."""
    _validate_child_link(parent, child)
    if not fan_out_guard.reserve(
        parent.delegation_id,
        child.delegation_id,
        parent.max_fan_out,
        child.expires_at,
    ):
        raise FanOutError(
            "DELEGATION_FANOUT_EXCEEDED",
            "parent delegation child limit was reached",
        )


def _validate_child_link(parent: VerifiedDelegation, child: VerifiedDelegation) -> None:
    if child.parent_delegation_id != parent.delegation_id:
        raise DelegationVerificationError(
            "DELEGATION_CHAIN_INVALID",
            "child does not reference the direct parent",
        )
    if child.issuer_agent_id != parent.subject_agent_id:
        raise DelegationVerificationError(
            "DELEGATION_ISSUER_INVALID",
            "child issuer is not the parent subject",
        )
    if child.delegation_depth != parent.delegation_depth + 1:
        raise DelegationVerificationError(
            "DELEGATION_CHAIN_INVALID",
            "child delegation depth is invalid",
        )
    if child.max_depth > parent.max_depth:
        raise DelegationVerificationError(
            "DELEGATION_SCOPE_ESCALATION",
            "child max_depth exceeds parent authority",
        )
    if child.audience != parent.audience:
        raise DelegationVerificationError(
            "DELEGATION_CONTEXT_MISMATCH",
            "child audience differs from parent",
        )
    for field in ("session_id", "tenant_id", "project_id", "workspace_id"):
        if getattr(child, field) != getattr(parent, field):
            raise DelegationVerificationError(
                "DELEGATION_CONTEXT_MISMATCH",
                f"child {field} differs from parent",
            )
    if not set(child.allowed_actions).issubset(parent.allowed_actions):
        raise DelegationVerificationError(
            "DELEGATION_SCOPE_ESCALATION",
            "child actions exceed parent authority",
        )
    if not set(child.allowed_resource_scopes).issubset(parent.allowed_resource_scopes):
        raise DelegationVerificationError(
            "DELEGATION_SCOPE_ESCALATION",
            "child resource scopes exceed parent authority",
        )


def verify_delegation_chain(
    chain: Sequence[Mapping[str, Any]],
    *,
    trusted_keys: Mapping[str, DelegationTrustedKey],
    expected_audience: str,
    expected_subject_agent_id: str,
    expected_action: str | None = None,
    expected_resource_scope: str | None = None,
    expected_session_id: str | None = None,
    expected_tenant_id: str | None = None,
    expected_project_id: str | None = None,
    expected_workspace_id: str | None = None,
    fan_out_guard: FanOutGuard | None = None,
    current_time: datetime | None = None,
    clock_skew_seconds: int = 60,
    max_chain_length: int = 8,
) -> tuple[VerifiedDelegation, ...]:
    """Verify root-to-leaf identity, scope attenuation, and fan-out records."""
    if isinstance(chain, (str, bytes)) or not isinstance(chain, Sequence) or not chain:
        raise DelegationVerificationError(
            "DELEGATION_CHAIN_INVALID",
            "chain must be a non-empty sequence",
        )
    if max_chain_length < 1:
        raise ValueError("max_chain_length must be positive")
    if len(chain) > max_chain_length:
        raise DelegationVerificationError(
            "DELEGATION_CHAIN_TOO_DEEP",
            "delegation chain exceeds the configured maximum length",
        )
    verified: list[VerifiedDelegation] = []
    seen: set[str] = set()
    for index, token in enumerate(chain):
        current = verify_delegation_token(
            token,
            trusted_keys=trusted_keys,
            expected_audience=expected_audience,
            expected_subject_agent_id=(
                expected_subject_agent_id if index == len(chain) - 1 else None
            ),
            expected_session_id=expected_session_id,
            expected_tenant_id=expected_tenant_id,
            expected_project_id=expected_project_id,
            expected_workspace_id=expected_workspace_id,
            current_time=current_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if current.delegation_id in seen:
            raise DelegationVerificationError(
                "DELEGATION_CHAIN_INVALID",
                "delegation IDs must be unique",
            )
        seen.add(current.delegation_id)
        if fan_out_guard is not None and fan_out_guard.is_revoked(
            current.delegation_id
        ):
            raise DelegationVerificationError(
                "DELEGATION_REVOKED",
                "delegation was revoked",
            )
        if index == 0:
            if (
                current.parent_delegation_id is not None
                or current.delegation_depth != 0
            ):
                raise DelegationVerificationError(
                    "DELEGATION_CHAIN_INVALID",
                    "chain must begin with a root delegation",
                )
        else:
            parent = verified[-1]
            _validate_child_link(parent, current)
            if fan_out_guard is None:
                raise DelegationVerificationError(
                    "DELEGATION_FANOUT_GUARD_REQUIRED",
                    "child delegation verification requires a fan-out guard",
                )
            if not fan_out_guard.is_registered(
                parent.delegation_id,
                current.delegation_id,
            ):
                raise DelegationVerificationError(
                    "DELEGATION_FANOUT_UNREGISTERED",
                    "child delegation was not registered under its parent",
                )
        verified.append(current)
    leaf = verified[-1]
    if expected_action is not None and expected_action not in leaf.allowed_actions:
        raise DelegationVerificationError(
            "DELEGATION_ACTION_NOT_ALLOWED",
            "leaf delegation does not authorize the requested action",
        )
    if (
        expected_resource_scope is not None
        and expected_resource_scope not in leaf.allowed_resource_scopes
    ):
        raise DelegationVerificationError(
            "DELEGATION_RESOURCE_NOT_ALLOWED",
            "leaf delegation does not authorize the requested resource scope",
        )
    return tuple(verified)


class InMemoryFanOutGuard:
    """Thread-safe fan-out guard for tests and one-process development only."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._children: dict[str, tuple[str, datetime]] = {}
        self._revoked: set[str] = set()

    def reserve(
        self,
        parent_delegation_id: str,
        child_delegation_id: str,
        limit: int,
        expires_at: str,
    ) -> bool:
        if limit < 0:
            raise FanOutError("DELEGATION_LIMIT_INVALID", "limit must be non-negative")
        expiry = _parse_time(expires_at, "expires_at")
        now = datetime.now(timezone.utc)
        with self._lock:
            self._children = {
                child: value
                for child, value in self._children.items()
                if value[1] > now
            }
            if child_delegation_id in self._children:
                return self._children[child_delegation_id][0] == parent_delegation_id
            if child_delegation_id in self._revoked:
                return False
            count = sum(
                parent == parent_delegation_id
                for parent, _expiry in self._children.values()
            )
            if count >= limit:
                return False
            self._children[child_delegation_id] = (parent_delegation_id, expiry)
            return True

    def is_registered(
        self, parent_delegation_id: str, child_delegation_id: str
    ) -> bool:
        with self._lock:
            return (
                self._children.get(child_delegation_id, (None, None))[0]
                == parent_delegation_id
            )

    def is_revoked(self, delegation_id: str) -> bool:
        with self._lock:
            return delegation_id in self._revoked

    def revoke(self, delegation_id: str) -> None:
        with self._lock:
            self._revoked.add(delegation_id)


class SQLiteFanOutGuard:
    """Atomic cross-worker fan-out registration and delegation revocation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS delegation_children ("
                    "child_delegation_id TEXT PRIMARY KEY, "
                    "parent_delegation_id TEXT NOT NULL, expires_at REAL NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS revoked_delegations ("
                    "delegation_id TEXT PRIMARY KEY)"
                )
        except sqlite3.Error as exc:
            raise FanOutError(
                "DELEGATION_FANOUT_STORE_UNAVAILABLE",
                "unable to initialize fan-out store",
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def reserve(
        self,
        parent_delegation_id: str,
        child_delegation_id: str,
        limit: int,
        expires_at: str,
    ) -> bool:
        if limit < 0:
            raise FanOutError("DELEGATION_LIMIT_INVALID", "limit must be non-negative")
        expiry = _parse_time(expires_at, "expires_at").timestamp()
        now = datetime.now(timezone.utc).timestamp()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM delegation_children WHERE expires_at <= ?",
                    (now,),
                )
                if connection.execute(
                    "SELECT 1 FROM revoked_delegations WHERE delegation_id = ?",
                    (child_delegation_id,),
                ).fetchone():
                    connection.execute("ROLLBACK")
                    return False
                existing = connection.execute(
                    "SELECT parent_delegation_id FROM delegation_children "
                    "WHERE child_delegation_id = ?",
                    (child_delegation_id,),
                ).fetchone()
                if existing is not None:
                    connection.execute("ROLLBACK")
                    return existing[0] == parent_delegation_id
                count = connection.execute(
                    "SELECT COUNT(*) FROM delegation_children "
                    "WHERE parent_delegation_id = ?",
                    (parent_delegation_id,),
                ).fetchone()
                assert count is not None
                if int(count[0]) >= limit:
                    connection.execute("ROLLBACK")
                    return False
                connection.execute(
                    "INSERT INTO delegation_children "
                    "(child_delegation_id, parent_delegation_id, expires_at) "
                    "VALUES (?, ?, ?)",
                    (child_delegation_id, parent_delegation_id, expiry),
                )
                connection.execute("COMMIT")
                return True
        except sqlite3.Error as exc:
            raise FanOutError(
                "DELEGATION_FANOUT_STORE_UNAVAILABLE",
                "unable to reserve delegation child",
            ) from exc

    def is_registered(
        self, parent_delegation_id: str, child_delegation_id: str
    ) -> bool:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT parent_delegation_id FROM delegation_children "
                    "WHERE child_delegation_id = ?",
                    (child_delegation_id,),
                ).fetchone()
                return row is not None and row[0] == parent_delegation_id
        except sqlite3.Error as exc:
            raise FanOutError(
                "DELEGATION_FANOUT_STORE_UNAVAILABLE",
                "unable to verify delegation child registration",
            ) from exc

    def is_revoked(self, delegation_id: str) -> bool:
        try:
            with self._connect() as connection:
                return (
                    connection.execute(
                        "SELECT 1 FROM revoked_delegations WHERE delegation_id = ?",
                        (delegation_id,),
                    ).fetchone()
                    is not None
                )
        except sqlite3.Error as exc:
            raise FanOutError(
                "DELEGATION_FANOUT_STORE_UNAVAILABLE",
                "unable to verify delegation revocation",
            ) from exc

    def revoke(self, delegation_id: str) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT OR IGNORE INTO revoked_delegations(delegation_id) VALUES (?)",
                    (delegation_id,),
                )
        except sqlite3.Error as exc:
            raise FanOutError(
                "DELEGATION_FANOUT_STORE_UNAVAILABLE",
                "unable to revoke delegation",
            ) from exc


__all__ = [
    "DELEGATION_SCHEMA_VERSION",
    "DELEGATION_SIGNATURE_ALGORITHM",
    "DelegationTrustedKey",
    "DelegationVerificationError",
    "FanOutError",
    "FanOutGuard",
    "InMemoryFanOutGuard",
    "SQLiteFanOutGuard",
    "VerifiedDelegation",
    "reserve_delegation_child",
    "sign_delegation_token",
    "verify_delegation_chain",
    "verify_delegation_token",
]
