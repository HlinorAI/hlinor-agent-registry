"""Signed request-bound approvals and tamper-evident execution receipts.

This module is deliberately framework-neutral.  It authenticates the narrow
facts needed at the tool boundary; it does not claim to attest the host,
process, or side effects hidden inside an arbitrary callable.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .signing import TrustedKey
from .validator import validate_execution_receipt

APPROVAL_SCHEMA_VERSION = "1.0"
RECEIPT_SCHEMA_VERSION = "1.0"
RECEIPT_CHECKPOINT_SCHEMA_VERSION = "1.0"
SIGNATURE_ALGORITHM = "Ed25519"
_APPROVAL_SIGNATURE_FIELDS = {"algorithm", "key_id", "issuer", "value"}
_RECEIPT_SIGNATURE_FIELDS = {"algorithm", "key_id", "issuer", "value"}
_DOMAIN_APPROVAL = "hlinor/approval-token/v1"
_DOMAIN_RECEIPT = "hlinor/execution-receipt/v1"


class ApprovalVerificationError(ValueError):
    """Raised when a signed approval cannot be trusted or matched."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class ReplayGuardError(ApprovalVerificationError):
    """Raised when replay state cannot be checked safely."""


class ReceiptError(RuntimeError):
    """Raised when a receipt cannot be durably appended."""


class ReplayGuard(Protocol):
    """Atomic claim interface for single-use approval tokens."""

    def claim(self, token_id: str, nonce: str, expires_at: str) -> bool:
        """Return false when this token was already claimed."""

    def is_revoked(self, token_id: str, nonce: str) -> bool:
        """Return true when this token or nonce was revoked."""

    def revoke(self, token_id: str, nonce: str | None = None) -> None:
        """Revoke this token, or all nonces for its token ID."""


class ReceiptSink(Protocol):
    """Append one receipt and return the enriched stored record."""

    def append(self, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        """Persist one receipt before the governed side effect proceeds."""


class ExternalReceiptCollector(Protocol):
    """Minimal append contract for a collector outside the governed process."""

    def append(self, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        """Durably accept one receipt or raise when it is unavailable."""


class FailClosedReceiptSink:
    """Expose collector failure as a generic receipt error at the tool boundary.

    The wrapper intentionally does not retry: a collector must define its own
    idempotency and durability semantics. A pre-dispatch collector failure
    therefore blocks the governed call through the existing receipt path.
    """

    def __init__(self, collector: ExternalReceiptCollector) -> None:
        self._collector = collector

    def append(self, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            stored = self._collector.append(receipt)
        except Exception as exc:
            raise ReceiptError("external receipt collector unavailable") from exc
        if not isinstance(stored, Mapping):
            raise ReceiptError("external receipt collector returned an invalid record")
        return copy.deepcopy(dict(stored))


def _canonical(value: object) -> bytes:
    try:
        return rfc8785.dumps(value)  # type: ignore[arg-type]
    except Exception as exc:
        raise ReceiptError(f"RFC 8785 canonicalization failed: {exc}") from exc


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ApprovalVerificationError(
            "APPROVAL_TIMESTAMP_INVALID",
            f"{field} must be a non-empty ISO-8601 string",
        )
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ApprovalVerificationError(
            "APPROVAL_TIMESTAMP_INVALID", f"{field} is not valid ISO-8601"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ApprovalVerificationError(
            "APPROVAL_TIMESTAMP_INVALID", f"{field} must include a timezone"
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
        raise ApprovalVerificationError(
            "APPROVAL_WINDOW_INVALID", "expires_at must be after issued_at"
        )
    now = current_time or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("current_time must include a timezone")
    now = now.astimezone(timezone.utc)
    skew = timedelta(seconds=clock_skew_seconds)
    if issued > now + skew:
        raise ApprovalVerificationError(
            "APPROVAL_NOT_YET_VALID", "approval was issued in the future"
        )
    if expires < now - skew:
        raise ApprovalVerificationError("APPROVAL_EXPIRED", "approval has expired")


def _approval_signed_payload(token: Mapping[str, Any]) -> bytes:
    payload = copy.deepcopy(dict(token))
    signature = payload.get("signature")
    if not isinstance(signature, Mapping):
        raise ApprovalVerificationError(
            "APPROVAL_SIGNATURE_INVALID", "signature must be an object"
        )
    payload["signature"] = dict(signature)
    payload["signature"]["value"] = ""
    return _canonical({"domain": _DOMAIN_APPROVAL, "payload": payload})


def _validate_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ApprovalVerificationError(
            "APPROVAL_FIELD_INVALID", f"{field} must be a non-empty string"
        )


def sign_approval_token(
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
    issuer: str,
    subject_agent_id: str,
    action: str,
    arguments_digest: str,
    issued_at: str,
    expires_at: str,
    nonce: str,
    resource: str | None = None,
    tool_id: str | None = None,
    session_id: str | None = None,
    tenant_id: str | None = None,
    request_digest: str | None = None,
    approver_role: str | None = None,
    token_id: str | None = None,
    single_use: bool = True,
) -> dict[str, Any]:
    """Create a detached Ed25519 approval bound to one request target."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    for name, value in (
        ("key_id", key_id),
        ("issuer", issuer),
        ("subject_agent_id", subject_agent_id),
        ("action", action),
        ("arguments_digest", arguments_digest),
        ("nonce", nonce),
    ):
        _validate_text(value, name)
    if not isinstance(single_use, bool):
        raise TypeError("single_use must be a boolean")
    token: dict[str, Any] = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "token_id": token_id or str(uuid.uuid4()),
        "subject_agent_id": subject_agent_id,
        "action": action,
        "tool_id": tool_id,
        "resource": resource,
        "arguments_digest": arguments_digest,
        "request_digest": request_digest,
        "session_id": session_id,
        "tenant_id": tenant_id,
        "approver_role": approver_role,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
        "single_use": single_use,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "issuer": issuer,
            "value": "",
        },
    }
    _validate_text(token["token_id"], "token_id")
    _check_window(
        issued_at,
        expires_at,
        current_time=None,
        clock_skew_seconds=0,
    )
    signature = private_key.sign(_approval_signed_payload(token))
    token["signature"]["value"] = base64.b64encode(signature).decode("ascii")
    return token


@dataclass(frozen=True, slots=True)
class VerifiedApproval:
    """Verified target facts, safe to pass to the existing policy evaluator."""

    token_id: str
    key_id: str
    issuer: str
    subject_agent_id: str
    action: str
    arguments_digest: str
    resource: str | None
    tool_id: str | None
    session_id: str | None
    tenant_id: str | None
    request_digest: str | None
    approver_role: str | None
    issued_at: str
    expires_at: str
    nonce: str
    single_use: bool

    def as_policy_signal(self) -> dict[str, Any]:
        """Return only verified fields in the legacy approval signal shape."""
        granted_for = self.action
        if self.resource is not None:
            granted_for = f"{self.action}:{self.resource}"
        return {
            "token_id": self.token_id,
            "approver_role": self.approver_role,
            "granted_for": granted_for,
            "granted_at": self.issued_at,
            "verified": True,
        }


def verify_approval_token(
    token: Mapping[str, Any],
    *,
    trusted_keys: Mapping[str, TrustedKey],
    expected_agent_id: str,
    expected_action: str,
    expected_arguments_digest: str,
    expected_resource: str | None = None,
    expected_tool_id: str | None = None,
    expected_session_id: str | None = None,
    expected_tenant_id: str | None = None,
    expected_request_digest: str | None = None,
    replay_guard: ReplayGuard | None = None,
    current_time: datetime | None = None,
    clock_skew_seconds: int = 60,
) -> VerifiedApproval:
    """Verify signature, target equality, freshness, and optional single use."""
    if not isinstance(token, Mapping):
        raise ApprovalVerificationError("APPROVAL_INVALID", "token must be an object")
    allowed = {
        "schema_version",
        "token_id",
        "subject_agent_id",
        "action",
        "tool_id",
        "resource",
        "arguments_digest",
        "request_digest",
        "session_id",
        "tenant_id",
        "approver_role",
        "issued_at",
        "expires_at",
        "nonce",
        "single_use",
        "signature",
    }
    unknown = set(token).difference(allowed)
    if unknown:
        raise ApprovalVerificationError(
            "APPROVAL_INVALID", f"unknown fields: {sorted(unknown)}"
        )
    if token.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        raise ApprovalVerificationError(
            "APPROVAL_VERSION_UNSUPPORTED",
            f"expected {APPROVAL_SCHEMA_VERSION}",
        )
    for field in (
        "token_id",
        "subject_agent_id",
        "action",
        "arguments_digest",
        "issued_at",
        "expires_at",
        "nonce",
    ):
        _validate_text(token.get(field), field)
    single_use = token.get("single_use")
    if not isinstance(single_use, bool):
        raise ApprovalVerificationError("APPROVAL_INVALID", "single_use must be boolean")
    signature = token.get("signature")
    if not isinstance(signature, Mapping):
        raise ApprovalVerificationError("APPROVAL_SIGNATURE_INVALID", "signature must be an object")
    if set(signature) != _APPROVAL_SIGNATURE_FIELDS:
        raise ApprovalVerificationError("APPROVAL_SIGNATURE_INVALID", "signature fields are invalid")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        raise ApprovalVerificationError("APPROVAL_SIGNATURE_INVALID", "unsupported algorithm")
    key_id = signature.get("key_id")
    issuer = signature.get("issuer")
    _validate_text(key_id, "signature.key_id")
    _validate_text(issuer, "signature.issuer")
    assert isinstance(key_id, str)
    assert isinstance(issuer, str)
    trusted = trusted_keys.get(key_id)
    if trusted is None:
        raise ApprovalVerificationError("APPROVAL_KEY_UNTRUSTED", f"unknown key: {key_id}")
    if trusted.issuer is not None and trusted.issuer != issuer:
        raise ApprovalVerificationError("APPROVAL_ISSUER_INVALID", "issuer does not match trusted key")
    encoded = signature.get("value")
    if not isinstance(encoded, str) or not encoded:
        raise ApprovalVerificationError("APPROVAL_SIGNATURE_INVALID", "signature value is missing")
    try:
        signature_bytes = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ApprovalVerificationError("APPROVAL_SIGNATURE_INVALID", "signature is not valid base64") from exc
    try:
        trusted.public_key.verify(signature_bytes, _approval_signed_payload(token))
    except InvalidSignature as exc:
        raise ApprovalVerificationError("APPROVAL_SIGNATURE_INVALID", "signature verification failed") from exc

    _check_window(
        token["issued_at"],
        token["expires_at"],
        current_time=current_time,
        clock_skew_seconds=clock_skew_seconds,
    )
    expected = {
        "subject_agent_id": expected_agent_id,
        "action": expected_action,
        "arguments_digest": expected_arguments_digest,
        "resource": expected_resource,
        "tool_id": expected_tool_id,
        "session_id": expected_session_id,
        "tenant_id": expected_tenant_id,
    }
    for field, value in expected.items():
        if token.get(field) != value:
            raise ApprovalVerificationError(
                "APPROVAL_TARGET_MISMATCH",
                f"{field} does not match the requested target",
            )
    if expected_request_digest is not None and token.get("request_digest") != expected_request_digest:
        raise ApprovalVerificationError("APPROVAL_REQUEST_MISMATCH", "request digest does not match")
    if single_use:
        if replay_guard is None:
            raise ApprovalVerificationError("APPROVAL_REPLAY_GUARD_REQUIRED", "single-use approval requires a replay guard")
        is_revoked = getattr(replay_guard, "is_revoked", None)
        if not callable(is_revoked):
            raise ApprovalVerificationError("APPROVAL_REPLAY_GUARD_INVALID", "replay guard must support revocation checks")
        if is_revoked(token["token_id"], token["nonce"]):
            raise ApprovalVerificationError("APPROVAL_REVOKED", "approval token was revoked")
        if not replay_guard.claim(token["token_id"], token["nonce"], token["expires_at"]):
            raise ApprovalVerificationError("APPROVAL_REPLAYED", "approval token was already used")

    return VerifiedApproval(
        token_id=token["token_id"],
        key_id=key_id,
        issuer=issuer,
        subject_agent_id=token["subject_agent_id"],
        action=token["action"],
        arguments_digest=token["arguments_digest"],
        resource=token.get("resource"),
        tool_id=token.get("tool_id"),
        session_id=token.get("session_id"),
        tenant_id=token.get("tenant_id"),
        request_digest=token.get("request_digest"),
        approver_role=token.get("approver_role"),
        issued_at=token["issued_at"],
        expires_at=token["expires_at"],
        nonce=token["nonce"],
        single_use=single_use,
    )


class InMemoryReplayGuard:
    """Thread-safe replay guard for tests and one-process development only."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._claimed: dict[tuple[str, str], datetime] = {}
        self._revoked: set[tuple[str, str | None]] = set()

    def claim(self, token_id: str, nonce: str, expires_at: str) -> bool:
        expiry = _parse_time(expires_at, "expires_at")
        now = datetime.now(timezone.utc)
        key = (token_id, nonce)
        with self._lock:
            self._claimed = {key_: value for key_, value in self._claimed.items() if value > now}
            if key in self._claimed:
                return False
            self._claimed[key] = expiry
            return True

    def is_revoked(self, token_id: str, nonce: str) -> bool:
        with self._lock:
            return (token_id, None) in self._revoked or (token_id, nonce) in self._revoked

    def revoke(self, token_id: str, nonce: str | None = None) -> None:
        with self._lock:
            self._revoked.add((token_id, nonce))


class SQLiteReplayGuard:
    """Atomic cross-process replay and revocation state backed by SQLite."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS claimed_approvals ("
                    "token_id TEXT NOT NULL, nonce TEXT NOT NULL, "
                    "expires_at REAL NOT NULL, PRIMARY KEY (token_id, nonce))"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS revoked_approvals ("
                    "token_id TEXT NOT NULL, nonce TEXT, "
                    "PRIMARY KEY (token_id, nonce))"
                )
        except sqlite3.Error as exc:
            raise ReplayGuardError(
                "APPROVAL_REPLAY_STORE_UNAVAILABLE",
                f"unable to initialize replay store: {exc}",
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def claim(self, token_id: str, nonce: str, expires_at: str) -> bool:
        expiry = _parse_time(expires_at, "expires_at").timestamp()
        now = datetime.now(timezone.utc).timestamp()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM claimed_approvals WHERE expires_at <= ?", (now,))
                if self._is_revoked(connection, token_id, nonce):
                    connection.execute("ROLLBACK")
                    return False
                try:
                    connection.execute(
                        "INSERT INTO claimed_approvals(token_id, nonce, expires_at) VALUES (?, ?, ?)",
                        (token_id, nonce, expiry),
                    )
                except sqlite3.IntegrityError:
                    connection.execute("ROLLBACK")
                    return False
                connection.execute("COMMIT")
                return True
        except sqlite3.Error as exc:
            raise ReplayGuardError(
                "APPROVAL_REPLAY_STORE_UNAVAILABLE",
                f"unable to claim approval: {exc}",
            ) from exc

    @staticmethod
    def _is_revoked(connection: sqlite3.Connection, token_id: str, nonce: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM revoked_approvals WHERE token_id = ? AND (nonce IS NULL OR nonce = ?) LIMIT 1",
            (token_id, nonce),
        ).fetchone() is not None

    def is_revoked(self, token_id: str, nonce: str) -> bool:
        try:
            with self._connect() as connection:
                return self._is_revoked(connection, token_id, nonce)
        except sqlite3.Error as exc:
            raise ReplayGuardError(
                "APPROVAL_REPLAY_STORE_UNAVAILABLE",
                f"unable to check approval revocation: {exc}",
            ) from exc

    def revoke(self, token_id: str, nonce: str | None = None) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT OR IGNORE INTO revoked_approvals(token_id, nonce) VALUES (?, ?)",
                    (token_id, nonce),
                )
        except sqlite3.Error as exc:
            raise ReplayGuardError(
                "APPROVAL_REPLAY_STORE_UNAVAILABLE",
                f"unable to revoke approval: {exc}",
            ) from exc


class HashChainedReceiptSink:
    """Append receipts with a verifiable sequence and optional Ed25519 signature."""

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey | None = None,
        key_id: str | None = None,
        issuer: str | None = None,
    ) -> None:
        if (private_key is None) != (key_id is None or issuer is None):
            raise ValueError("private_key, key_id and issuer must be supplied together")
        self._private_key = private_key
        self._key_id = key_id
        self._issuer = issuer
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []

    @property
    def records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(copy.deepcopy(self._records))

    def append(self, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(receipt, Mapping):
            raise ReceiptError("receipt must be an object")
        with self._lock:
            record = copy.deepcopy(dict(receipt))
            errors = validate_execution_receipt(record)
            if errors:
                raise ReceiptError("invalid execution receipt: " + "; ".join(errors))
            record.setdefault("schema_version", RECEIPT_SCHEMA_VERSION)
            record.setdefault("receipt_id", str(uuid.uuid4()))
            record["sequence"] = len(self._records) + 1
            record["previous_receipt_hash"] = (
                self._records[-1]["receipt_hash"] if self._records else None
            )
            if self._private_key is not None:
                record["signature"] = {
                    "algorithm": SIGNATURE_ALGORITHM,
                    "key_id": self._key_id,
                    "issuer": self._issuer,
                    "value": "",
                }
            else:
                record.pop("signature", None)
            record["receipt_hash"] = ""
            record["receipt_hash"] = "sha256:" + hashlib.sha256(
                _receipt_hash_payload(record)
            ).hexdigest()
            if self._private_key is not None:
                signature = self._private_key.sign(_receipt_signed_payload(record))
                record["signature"]["value"] = base64.b64encode(signature).decode("ascii")
            self._commit(record)
            return copy.deepcopy(record)

    def _commit(self, record: dict[str, Any]) -> None:
        self._records.append(record)


def _receipt_hash_payload(receipt: Mapping[str, Any]) -> bytes:
    payload = copy.deepcopy(dict(receipt))
    payload["receipt_hash"] = ""
    signature = payload.get("signature")
    if isinstance(signature, dict):
        signature["value"] = ""
    return _canonical({"domain": _DOMAIN_RECEIPT, "payload": payload})


def _receipt_signed_payload(receipt: Mapping[str, Any]) -> bytes:
    payload = copy.deepcopy(dict(receipt))
    signature = payload.get("signature")
    if not isinstance(signature, Mapping):
        raise ReceiptError("receipt signature must be an object")
    payload["signature"] = dict(signature)
    payload["signature"]["value"] = ""
    return _canonical({"domain": _DOMAIN_RECEIPT, "payload": payload})


def verify_receipt_chain(
    records: Sequence[Mapping[str, Any]],
    *,
    trusted_keys: Mapping[str, TrustedKey] | None = None,
) -> None:
    """Verify sequence, previous-hash links, and optional receipt signatures."""
    previous: str | None = None
    for expected_sequence, original in enumerate(records, start=1):
        if not isinstance(original, Mapping):
            raise ReceiptError("receipt record must be an object")
        record = copy.deepcopy(dict(original))
        shape_errors = validate_execution_receipt(record)
        if shape_errors:
            raise ReceiptError("invalid execution receipt: " + "; ".join(shape_errors))
        if record.get("sequence") != expected_sequence:
            raise ReceiptError("receipt sequence is not contiguous")
        if record.get("previous_receipt_hash") != previous:
            raise ReceiptError("receipt chain link is invalid")
        actual_hash = record.get("receipt_hash")
        if not isinstance(actual_hash, str) or not actual_hash:
            raise ReceiptError("receipt hash is missing")
        expected_hash = "sha256:" + hashlib.sha256(
            _receipt_hash_payload(record)
        ).hexdigest()
        if actual_hash != expected_hash:
            raise ReceiptError("receipt hash verification failed")
        signature = original.get("signature")
        if signature is not None:
            if not isinstance(signature, Mapping) or set(signature) != _RECEIPT_SIGNATURE_FIELDS:
                raise ReceiptError("receipt signature fields are invalid")
            if signature.get("algorithm") != SIGNATURE_ALGORITHM:
                raise ReceiptError("receipt signature algorithm is unsupported")
            key_id = signature.get("key_id")
            if not isinstance(key_id, str):
                raise ReceiptError("receipt signature key_id is invalid")
            trusted = (trusted_keys or {}).get(key_id)
            if trusted is None:
                raise ReceiptError("receipt signing key is not trusted")
            if trusted.issuer is not None and signature.get("issuer") != trusted.issuer:
                raise ReceiptError("receipt signature issuer is invalid")
            encoded = signature.get("value")
            if not isinstance(encoded, str) or not encoded:
                raise ReceiptError("receipt signature value is missing")
            try:
                signature_bytes = base64.b64decode(encoded, validate=True)
                trusted.public_key.verify(signature_bytes, _receipt_signed_payload(original))
            except (binascii.Error, ValueError, InvalidSignature) as exc:
                raise ReceiptError("receipt signature verification failed") from exc
        previous = actual_hash


class JsonlReceiptSink(HashChainedReceiptSink):
    """Durably append and optionally resume a checkpointed JSONL hash chain."""

    def __init__(
        self,
        path: str | Path,
        *,
        resume: bool = False,
        checkpoint_path: str | Path | None = None,
        trusted_keys: Mapping[str, TrustedKey] | None = None,
        **kwargs: Any,
    ) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path = (
            Path(checkpoint_path).resolve() if checkpoint_path is not None else None
        )
        if self.checkpoint_path == self.path:
            raise ReceiptError("receipt checkpoint must use a different path")
        self._broken = False
        has_existing_records = self.path.exists() and self.path.stat().st_size > 0
        if has_existing_records and not resume:
            raise ReceiptError(
                "existing receipt files must be verified and resumed explicitly"
            )
        if resume and self.checkpoint_path is None:
            raise ReceiptError("resume requires an explicit receipt checkpoint")
        super().__init__(**kwargs)
        if resume:
            records = self._read_records()
            verify_receipt_chain(records, trusted_keys=trusted_keys)
            self._verify_checkpoint(records)
            self._records = records

    def append(self, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        if self._broken:
            raise ReceiptError("receipt sink is broken and requires operator recovery")
        return super().append(receipt)

    def _commit(self, record: dict[str, Any]) -> None:
        try:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            self._broken = True
            raise ReceiptError(f"unable to persist execution receipt: {exc}") from exc
        if self.checkpoint_path is not None:
            try:
                self._write_checkpoint(record)
            except ReceiptError:
                self._broken = True
                raise
        super()._commit(record)

    def _read_records(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            with self.path.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    if not line.strip():
                        raise ReceiptError(
                            f"receipt file contains a blank line at {line_number}"
                        )
                    try:
                        decoded = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ReceiptError(
                            f"receipt file contains invalid JSON at line {line_number}"
                        ) from exc
                    if not isinstance(decoded, dict):
                        raise ReceiptError(
                            f"receipt line {line_number} must contain an object"
                        )
                    records.append(decoded)
        except OSError as exc:
            raise ReceiptError(f"unable to read execution receipts: {exc}") from exc
        return records

    def _verify_checkpoint(self, records: Sequence[Mapping[str, Any]]) -> None:
        assert self.checkpoint_path is not None
        try:
            with self.checkpoint_path.open("r", encoding="utf-8") as stream:
                checkpoint = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise ReceiptError("receipt checkpoint is unavailable or invalid") from exc
        if not isinstance(checkpoint, dict):
            raise ReceiptError("receipt checkpoint must be an object")
        if set(checkpoint) != {
            "schema_version",
            "last_sequence",
            "last_receipt_hash",
        }:
            raise ReceiptError("receipt checkpoint fields are invalid")
        if checkpoint.get("schema_version") != RECEIPT_CHECKPOINT_SCHEMA_VERSION:
            raise ReceiptError("receipt checkpoint version is unsupported")
        last_sequence = checkpoint.get("last_sequence")
        if (
            not isinstance(last_sequence, int)
            or isinstance(last_sequence, bool)
            or last_sequence < 0
        ):
            raise ReceiptError("receipt checkpoint sequence is invalid")
        last_receipt_hash = checkpoint.get("last_receipt_hash")
        if last_receipt_hash is not None and (
            not isinstance(last_receipt_hash, str)
            or not last_receipt_hash.startswith("sha256:")
        ):
            raise ReceiptError("receipt checkpoint hash is invalid")
        expected_sequence = len(records)
        expected_hash = records[-1]["receipt_hash"] if records else None
        if last_sequence != expected_sequence or last_receipt_hash != expected_hash:
            raise ReceiptError("receipt checkpoint does not match receipt chain")

    def _write_checkpoint(self, record: Mapping[str, Any]) -> None:
        assert self.checkpoint_path is not None
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": RECEIPT_CHECKPOINT_SCHEMA_VERSION,
            "last_sequence": record["sequence"],
            "last_receipt_hash": record["receipt_hash"],
        }
        temporary_path: str | None = None
        try:
            descriptor, temporary_path = tempfile.mkstemp(
                prefix=f".{self.checkpoint_path.name}.",
                suffix=".tmp",
                dir=str(self.checkpoint_path.parent),
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, ensure_ascii=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self.checkpoint_path)
            temporary_path = None
            try:
                directory_descriptor = os.open(
                    self.checkpoint_path.parent,
                    os.O_RDONLY,
                )
            except OSError:
                directory_descriptor = None
            if directory_descriptor is not None:
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        except OSError as exc:
            raise ReceiptError(f"unable to persist receipt checkpoint: {exc}") from exc
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass


__all__ = [
    "APPROVAL_SCHEMA_VERSION",
    "RECEIPT_CHECKPOINT_SCHEMA_VERSION",
    "ApprovalVerificationError",
    "ExternalReceiptCollector",
    "FailClosedReceiptSink",
    "HashChainedReceiptSink",
    "InMemoryReplayGuard",
    "JsonlReceiptSink",
    "ReceiptError",
    "ReceiptSink",
    "ReplayGuard",
    "ReplayGuardError",
    "SQLiteReplayGuard",
    "VerifiedApproval",
    "sign_approval_token",
    "verify_approval_token",
    "verify_receipt_chain",
]
