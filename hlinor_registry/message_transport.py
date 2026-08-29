"""Signed, scope-bound transport for ordinary agent messages."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .execution_receipts import ReplayGuard
from .execution_scope import ExecutionScope, ExecutionScopeError

MESSAGE_TRANSPORT_SCHEMA_VERSION = "1.0"
MESSAGE_SIGNATURE_ALGORITHM = "Ed25519"
_DOMAIN_MESSAGE = "hlinor/scoped-message/v1"
_SIGNATURE_FIELDS = {"algorithm", "key_id", "issuer", "value"}
_MAX_MESSAGE_BYTES = 1_048_576


class MessageVerificationError(ValueError):
    """Raised when a signed scoped message cannot be trusted or delivered."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class MessageTrustedKey:
    """A configured Ed25519 key bound to one sending agent."""

    key_id: str
    agent_id: str
    public_key: Ed25519PublicKey
    issuer: str | None = None


@dataclass(frozen=True, slots=True)
class VerifiedScopedMessage:
    """Verified sender, target, scope, and message body facts."""

    message_id: str
    scope: ExecutionScope
    sender_agent_id: str
    recipient_agent_id: str
    body: object
    issued_at: str
    expires_at: str
    nonce: str
    key_id: str
    issuer: str

    @property
    def body_digest(self) -> str:
        """Return a stable digest of the signed message body."""
        return f"sha256:{hashlib.sha256(_canonical(self.body)).hexdigest()}"

    def as_policy_signal(self) -> dict[str, Any]:
        """Return only verified transport facts for policy/audit consumers."""
        return {
            "message_id": self.message_id,
            "sender_agent_id": self.sender_agent_id,
            "recipient_agent_id": self.recipient_agent_id,
            "project_id": self.scope.project_id,
            "workspace_id": self.scope.workspace_id,
            "body_digest": self.body_digest,
            "key_id": self.key_id,
            "issuer": self.issuer,
            "verified": True,
        }


def _canonical(value: object) -> bytes:
    try:
        return rfc8785.dumps(value)  # type: ignore[arg-type]
    except Exception as exc:
        raise MessageVerificationError(
            "MESSAGE_PAYLOAD_INVALID", "message payload is not canonicalizable"
        ) from exc


def _text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise MessageVerificationError(
            "MESSAGE_FIELD_INVALID", f"{field} must be a non-empty string"
        )
    if len(value) > 256:
        raise MessageVerificationError(
            "MESSAGE_FIELD_INVALID", f"{field} exceeds the maximum length"
        )


def _window(
    issued_at: object,
    expires_at: object,
    *,
    current_time: datetime | None,
    clock_skew_seconds: int,
) -> None:
    if clock_skew_seconds < 0:
        raise ValueError("clock_skew_seconds cannot be negative")
    if not isinstance(issued_at, str) or not isinstance(expires_at, str):
        raise MessageVerificationError(
            "MESSAGE_TIME_INVALID", "message timestamps must be strings"
        )
    try:
        issued = datetime.fromisoformat(
            issued_at[:-1] + "+00:00" if issued_at.endswith("Z") else issued_at
        )
        expires = datetime.fromisoformat(
            expires_at[:-1] + "+00:00" if expires_at.endswith("Z") else expires_at
        )
    except ValueError as exc:
        raise MessageVerificationError(
            "MESSAGE_TIME_INVALID", "message timestamps must be ISO-8601"
        ) from exc
    if (
        issued.tzinfo is None
        or issued.utcoffset() is None
        or expires.tzinfo is None
        or expires.utcoffset() is None
    ):
        raise MessageVerificationError(
            "MESSAGE_TIME_INVALID", "message timestamps must include a timezone"
        )
    issued = issued.astimezone(timezone.utc)
    expires = expires.astimezone(timezone.utc)
    if expires <= issued:
        raise MessageVerificationError(
            "MESSAGE_TIME_INVALID", "message expiry must be after issuance"
        )
    now = current_time or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("current_time must include a timezone")
    skew = timedelta(seconds=clock_skew_seconds)
    if issued > now.astimezone(timezone.utc) + skew:
        raise MessageVerificationError(
            "MESSAGE_NOT_YET_VALID", "message was issued in the future"
        )
    if expires < now.astimezone(timezone.utc) - skew:
        raise MessageVerificationError("MESSAGE_EXPIRED", "message has expired")


def _signed_payload(message: Mapping[str, Any]) -> bytes:
    payload = {"domain": _DOMAIN_MESSAGE, **copy.deepcopy(dict(message))}
    signature = payload.get("signature")
    if isinstance(signature, dict):
        signature["value"] = ""
    return _canonical(payload)


def _scope(project_id: object, workspace_id: object) -> ExecutionScope:
    try:
        return ExecutionScope(project_id, workspace_id)  # type: ignore[arg-type]
    except ExecutionScopeError as exc:
        raise MessageVerificationError(
            "MESSAGE_SCOPE_INVALID", "project_id and workspace_id must be valid"
        ) from exc


def sign_scoped_message(
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
    issuer: str,
    sender_agent_id: str,
    recipient_agent_id: str,
    scope: ExecutionScope,
    body: object,
    issued_at: str,
    expires_at: str,
    nonce: str,
    message_id: str | None = None,
) -> dict[str, Any]:
    """Create a short-lived Ed25519 message bound to sender and scope."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    for field, value in (
        ("key_id", key_id),
        ("issuer", issuer),
        ("sender_agent_id", sender_agent_id),
        ("recipient_agent_id", recipient_agent_id),
        ("nonce", nonce),
    ):
        _text(value, field)
    if not isinstance(scope, ExecutionScope):
        raise MessageVerificationError(
            "MESSAGE_SCOPE_INVALID", "scope must be an ExecutionScope instance"
        )
    resolved_message_id = message_id if message_id is not None else str(uuid.uuid4())
    _text(resolved_message_id, "message_id")
    encoded_body = _canonical(body)
    if len(encoded_body) > _MAX_MESSAGE_BYTES:
        raise MessageVerificationError(
            "MESSAGE_PAYLOAD_INVALID", "message body exceeds the maximum size"
        )
    _window(
        issued_at,
        expires_at,
        current_time=None,
        clock_skew_seconds=0,
    )
    message: dict[str, Any] = {
        "schema_version": MESSAGE_TRANSPORT_SCHEMA_VERSION,
        "message_id": resolved_message_id,
        "project_id": scope.project_id,
        "workspace_id": scope.workspace_id,
        "sender_agent_id": sender_agent_id,
        "recipient_agent_id": recipient_agent_id,
        "body": body,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
        "signature": {
            "algorithm": MESSAGE_SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "issuer": issuer,
            "value": "",
        },
    }
    message["signature"]["value"] = base64.b64encode(
        private_key.sign(_signed_payload(message))
    ).decode("ascii")
    return message


def verify_scoped_message(
    message: Mapping[str, Any],
    *,
    trusted_keys: Mapping[str, MessageTrustedKey],
    expected_scope: ExecutionScope,
    expected_recipient_agent_id: str,
    replay_guard: ReplayGuard | None,
    current_time: datetime | None = None,
    clock_skew_seconds: int = 60,
) -> VerifiedScopedMessage:
    """Verify signature, scope, recipient, freshness, and one-time delivery."""
    if not isinstance(message, Mapping):
        raise MessageVerificationError("MESSAGE_INVALID", "message must be an object")
    _text(expected_recipient_agent_id, "expected_recipient_agent_id")
    allowed = {
        "schema_version",
        "message_id",
        "project_id",
        "workspace_id",
        "sender_agent_id",
        "recipient_agent_id",
        "body",
        "issued_at",
        "expires_at",
        "nonce",
        "signature",
    }
    if set(message).difference(allowed):
        raise MessageVerificationError("MESSAGE_INVALID", "unknown message fields")
    required = allowed
    missing = required.difference(message)
    if missing:
        raise MessageVerificationError(
            "MESSAGE_INVALID", "required message fields are missing"
        )
    if message.get("schema_version") != MESSAGE_TRANSPORT_SCHEMA_VERSION:
        raise MessageVerificationError(
            "MESSAGE_VERSION_UNSUPPORTED", "unsupported message version"
        )
    for field in (
        "message_id",
        "sender_agent_id",
        "recipient_agent_id",
        "issued_at",
        "expires_at",
        "nonce",
    ):
        _text(message.get(field), field)
    sender = message["sender_agent_id"]
    recipient = message["recipient_agent_id"]
    message_id = message["message_id"]
    nonce = message["nonce"]
    assert isinstance(sender, str)
    assert isinstance(recipient, str)
    assert isinstance(message_id, str)
    assert isinstance(nonce, str)
    if recipient != expected_recipient_agent_id:
        raise MessageVerificationError(
            "MESSAGE_RECIPIENT_MISMATCH", "message recipient does not match"
        )
    if not isinstance(expected_scope, ExecutionScope):
        raise MessageVerificationError(
            "MESSAGE_SCOPE_INVALID", "expected_scope must be an ExecutionScope instance"
        )
    scope = _scope(message.get("project_id"), message.get("workspace_id"))
    if scope != expected_scope:
        raise MessageVerificationError(
            "MESSAGE_SCOPE_MISMATCH", "message scope does not match"
        )
    body_bytes = _canonical(message.get("body"))
    if len(body_bytes) > _MAX_MESSAGE_BYTES:
        raise MessageVerificationError(
            "MESSAGE_PAYLOAD_INVALID", "message body exceeds the maximum size"
        )
    _window(
        message.get("issued_at"),
        message.get("expires_at"),
        current_time=current_time,
        clock_skew_seconds=clock_skew_seconds,
    )
    issued_at = message["issued_at"]
    expires_at = message["expires_at"]
    assert isinstance(issued_at, str)
    assert isinstance(expires_at, str)
    signature = message.get("signature")
    if not isinstance(signature, Mapping) or set(signature) != _SIGNATURE_FIELDS:
        raise MessageVerificationError(
            "MESSAGE_SIGNATURE_INVALID", "signature fields are invalid"
        )
    if signature.get("algorithm") != MESSAGE_SIGNATURE_ALGORITHM:
        raise MessageVerificationError(
            "MESSAGE_SIGNATURE_INVALID", "unsupported signature algorithm"
        )
    key_id = signature.get("key_id")
    issuer = signature.get("issuer")
    encoded = signature.get("value")
    _text(key_id, "signature.key_id")
    _text(issuer, "signature.issuer")
    if not isinstance(encoded, str) or not encoded:
        raise MessageVerificationError(
            "MESSAGE_SIGNATURE_INVALID", "signature value is missing"
        )
    assert isinstance(key_id, str)
    assert isinstance(issuer, str)
    trusted = trusted_keys.get(key_id)
    if (
        not isinstance(trusted, MessageTrustedKey)
        or trusted.key_id != key_id
        or trusted.agent_id != sender
    ):
        raise MessageVerificationError(
            "MESSAGE_SENDER_UNTRUSTED", "sender key is not trusted for sender"
        )
    if trusted.issuer is not None and trusted.issuer != issuer:
        raise MessageVerificationError(
            "MESSAGE_ISSUER_INVALID", "issuer does not match trusted key"
        )
    try:
        signature_bytes = base64.b64decode(encoded, validate=True)
        trusted.public_key.verify(signature_bytes, _signed_payload(message))
    except (binascii.Error, TypeError, ValueError, InvalidSignature) as exc:
        raise MessageVerificationError(
            "MESSAGE_SIGNATURE_INVALID", "signature verification failed"
        ) from exc
    if replay_guard is None:
        raise MessageVerificationError(
            "MESSAGE_REPLAY_GUARD_REQUIRED", "message replay guard is required"
        )
    try:
        if replay_guard.is_revoked(message_id, nonce):
            raise MessageVerificationError("MESSAGE_REVOKED", "message was revoked")
        if not replay_guard.claim(message_id, nonce, expires_at):
            raise MessageVerificationError(
                "MESSAGE_REPLAYED", "message was already delivered"
            )
    except MessageVerificationError:
        raise
    except Exception as exc:
        raise MessageVerificationError(
            "MESSAGE_REPLAY_STATE_UNAVAILABLE", "unable to verify replay state"
        ) from exc
    return VerifiedScopedMessage(
        message_id=message_id,
        scope=scope,
        sender_agent_id=sender,
        recipient_agent_id=recipient,
        body=message.get("body"),
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        key_id=key_id,
        issuer=issuer,
    )


__all__ = [
    "MESSAGE_SIGNATURE_ALGORITHM",
    "MESSAGE_TRANSPORT_SCHEMA_VERSION",
    "MessageTrustedKey",
    "MessageVerificationError",
    "VerifiedScopedMessage",
    "sign_scoped_message",
    "verify_scoped_message",
]
