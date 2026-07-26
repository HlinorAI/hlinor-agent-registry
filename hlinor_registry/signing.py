"""Ed25519 signing and trust verification for compiled policy bundles."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNATURE_ALGORITHM = "Ed25519"
TRUST_STORE_SCHEMA_VERSION = "1.0"
_SIGNATURE_FIELDS = {
    "algorithm",
    "key_id",
    "issuer",
    "issued_at",
    "expires_at",
    "value",
}


class BundleSignatureError(ValueError):
    """Raised when a signed policy bundle cannot be trusted."""


@dataclass(frozen=True)
class TrustedKey:
    """One preconfigured Ed25519 trust root.

    ``source_path`` records the PEM file a trust-store entry was read from so a
    long-lived verifier can notice that the file changed. It is ``None`` for
    keys supplied programmatically, which have no file to watch.
    """

    key_id: str
    public_key: Ed25519PublicKey
    issuer: str | None = None
    source_path: Path | None = None


@dataclass(frozen=True)
class VerifiedSignature:
    """Validated signature metadata safe to expose as provenance."""

    algorithm: str
    key_id: str
    key_fingerprint: str
    issuer: str
    issued_at: str
    expires_at: str


def _verification_time(
    current_time: datetime | None,
    clock_skew_seconds: int,
) -> tuple[datetime, timedelta]:
    if clock_skew_seconds < 0:
        raise ValueError("clock_skew_seconds cannot be negative")
    now_value = current_time or datetime.now(timezone.utc)
    if now_value.tzinfo is None or now_value.utcoffset() is None:
        raise ValueError("current_time must include a timezone")
    return (
        now_value.astimezone(timezone.utc),
        timedelta(seconds=clock_skew_seconds),
    )


def validate_signature_window(
    signature: VerifiedSignature,
    *,
    clock_skew_seconds: int = 60,
    current_time: datetime | None = None,
) -> None:
    """Fail closed when verified signature metadata is not currently valid."""
    issued_at = parse_timestamp(signature.issued_at, "issued_at")
    expires_at = parse_timestamp(signature.expires_at, "expires_at")
    now, skew = _verification_time(current_time, clock_skew_seconds)
    if issued_at > now + skew:
        raise BundleSignatureError("Policy bundle was issued in the future")
    if expires_at < now - skew:
        raise BundleSignatureError("Policy bundle signature has expired")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _without_signature_value(bundle: Mapping[str, Any]) -> dict[str, Any]:
    canonical_bundle = copy.deepcopy(dict(bundle))
    signature = canonical_bundle.get("signature")
    if signature is not None:
        if not isinstance(signature, dict):
            raise BundleSignatureError("Policy bundle signature must be an object")
        signature["value"] = ""
    return canonical_bundle


def canonical_digest_payload(bundle: Mapping[str, Any]) -> bytes:
    """Return canonical bytes covered by the bundle SHA-256 digest."""
    canonical_bundle = _without_signature_value(bundle)
    canonical_bundle["digest"] = ""
    return _canonical_json(canonical_bundle)


def compute_bundle_digest(bundle: Mapping[str, Any]) -> str:
    """Return the canonical SHA-256 digest for signed or unsigned bundles."""
    return hashlib.sha256(canonical_digest_payload(bundle)).hexdigest()


def canonical_signature_payload(bundle: Mapping[str, Any]) -> bytes:
    """Return canonical bytes covered by an Ed25519 bundle signature."""
    canonical_bundle = _without_signature_value(bundle)
    digest = canonical_bundle.get("digest")
    if not isinstance(digest, str) or not digest:
        raise BundleSignatureError("Policy bundle is missing a digest")
    return _canonical_json(canonical_bundle)


def parse_timestamp(value: object, field_name: str) -> datetime:
    """Parse one timezone-aware ISO-8601 timestamp."""
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise BundleSignatureError(
            f"Signature {field_name} must be a non-empty ISO-8601 string"
        )
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise BundleSignatureError(
            f"Signature {field_name} must be a valid ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BundleSignatureError(f"Signature {field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key_path = Path(path).resolve()
    if not key_path.is_file():
        raise BundleSignatureError(f"Signing key not found: {key_path}")
    try:
        loaded = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=None,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise BundleSignatureError(
            "Signing key must be an unencrypted PEM Ed25519 private key"
        ) from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise BundleSignatureError("Signing key must use Ed25519")
    return loaded


def load_public_key(value: str | bytes | Path) -> Ed25519PublicKey:
    """Load one Ed25519 public key from PEM bytes, PEM text, or a path."""
    if isinstance(value, Path):
        key_bytes = value.resolve().read_bytes()
    elif isinstance(value, str) and "-----BEGIN PUBLIC KEY-----" not in value:
        key_bytes = Path(value).resolve().read_bytes()
    elif isinstance(value, str):
        key_bytes = value.encode("utf-8")
    elif isinstance(value, bytes):
        key_bytes = value
    else:
        raise TypeError("Trusted public key must be PEM text, bytes, or a path")

    try:
        loaded = serialization.load_pem_public_key(key_bytes)
    except (OSError, TypeError, ValueError) as exc:
        raise BundleSignatureError(
            "Trusted key must be a valid PEM public key"
        ) from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise BundleSignatureError("Trusted key must use Ed25519")
    return loaded


def sign_bundle(
    bundle: Mapping[str, Any],
    *,
    private_key_path: str | Path,
    key_id: str,
    issuer: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Return a signed copy of a compiled policy bundle."""
    for field_name, value in (("key_id", key_id), ("issuer", issuer)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise BundleSignatureError(
                f"Signature {field_name} must be a non-empty string"
            )

    issued = parse_timestamp(issued_at, "issued_at")
    expires = parse_timestamp(expires_at, "expires_at")
    if expires <= issued:
        raise BundleSignatureError("Signature expires_at must be after issued_at")

    signed_bundle = copy.deepcopy(dict(bundle))
    signed_bundle["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "issuer": issuer,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "value": "",
    }
    signed_bundle["digest"] = compute_bundle_digest(signed_bundle)

    private_key = _load_private_key(private_key_path)
    signature = private_key.sign(canonical_signature_payload(signed_bundle))
    signed_bundle["signature"]["value"] = base64.b64encode(signature).decode("ascii")

    try:
        private_key.public_key().verify(
            signature,
            canonical_signature_payload(signed_bundle),
        )
    except InvalidSignature as exc:  # pragma: no cover - cryptography invariant
        raise BundleSignatureError(
            "Generated bundle signature failed verification"
        ) from exc
    return signed_bundle


def _validate_signature_object(bundle: Mapping[str, Any]) -> dict[str, Any]:
    signature = bundle.get("signature")
    if not isinstance(signature, dict):
        raise BundleSignatureError("Policy bundle is missing a signature")
    unknown_fields = set(signature).difference(_SIGNATURE_FIELDS)
    missing_fields = _SIGNATURE_FIELDS.difference(signature)
    if unknown_fields:
        raise BundleSignatureError(
            f"Policy bundle signature has unknown fields: {sorted(unknown_fields)}"
        )
    if missing_fields:
        raise BundleSignatureError(
            f"Policy bundle signature is missing fields: {sorted(missing_fields)}"
        )
    return signature


def verify_bundle_signature(
    bundle: Mapping[str, Any],
    *,
    trusted_keys: Mapping[str, TrustedKey],
    required_issuer: str | None = None,
    clock_skew_seconds: int = 60,
    current_time: datetime | None = None,
) -> VerifiedSignature:
    """Verify signature, trust root, issuer, and validity window."""
    signature = _validate_signature_object(bundle)
    algorithm = signature["algorithm"]
    if algorithm != SIGNATURE_ALGORITHM:
        raise BundleSignatureError(f"Unsupported signature algorithm: {algorithm}")

    key_id = signature["key_id"]
    issuer = signature["issuer"]
    for field_name, value in (("key_id", key_id), ("issuer", issuer)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise BundleSignatureError(
                f"Signature {field_name} must be a non-empty string"
            )

    trusted_key = trusted_keys.get(key_id)
    if trusted_key is None:
        raise BundleSignatureError(f"Unknown policy signing key: {key_id}")
    if trusted_key.issuer is not None and issuer != trusted_key.issuer:
        raise BundleSignatureError(
            f"Signature issuer does not match trusted key '{key_id}'"
        )
    if required_issuer is not None and issuer != required_issuer:
        raise BundleSignatureError("Signature issuer does not match required issuer")

    issued_at = parse_timestamp(signature["issued_at"], "issued_at")
    expires_at = parse_timestamp(signature["expires_at"], "expires_at")
    if expires_at <= issued_at:
        raise BundleSignatureError("Signature expires_at must be after issued_at")

    verified_signature = VerifiedSignature(
        algorithm=algorithm,
        key_id=key_id,
        key_fingerprint=(
            "sha256:"
            + hashlib.sha256(
                trusted_key.public_key.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ).hexdigest()
        ),
        issuer=issuer,
        issued_at=signature["issued_at"],
        expires_at=signature["expires_at"],
    )

    encoded_signature = signature["value"]
    if not isinstance(encoded_signature, str) or not encoded_signature:
        raise BundleSignatureError("Policy bundle signature value is missing")
    try:
        signature_bytes = base64.b64decode(encoded_signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleSignatureError(
            "Policy bundle signature value is not valid base64"
        ) from exc

    try:
        trusted_key.public_key.verify(
            signature_bytes,
            canonical_signature_payload(bundle),
        )
    except InvalidSignature as exc:
        raise BundleSignatureError(
            "Policy bundle signature verification failed"
        ) from exc

    validate_signature_window(
        verified_signature,
        clock_skew_seconds=clock_skew_seconds,
        current_time=current_time,
    )
    return verified_signature


def load_trust_store(path: str | Path) -> dict[str, TrustedKey]:
    """Load a strict JSON trust store with path-relative PEM public keys."""
    trust_store_path = Path(path).resolve()
    if not trust_store_path.is_file():
        raise FileNotFoundError(f"Trust store not found: {trust_store_path}")
    try:
        data = json.loads(trust_store_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BundleSignatureError(f"Invalid trust store JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BundleSignatureError("Trust store root must be an object")
    if data.get("schema_version") != TRUST_STORE_SCHEMA_VERSION:
        raise BundleSignatureError(
            f"Unsupported trust store schema: {data.get('schema_version')}"
        )
    if set(data).difference({"schema_version", "keys"}):
        raise BundleSignatureError("Trust store contains unknown top-level fields")

    keys = data.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise BundleSignatureError("Trust store must contain a non-empty keys object")

    trusted_keys: dict[str, TrustedKey] = {}
    for key_id, key_config in keys.items():
        if (
            not isinstance(key_id, str)
            or not key_id.strip()
            or key_id != key_id.strip()
        ):
            raise BundleSignatureError("Trust store key IDs must be non-empty strings")
        if not isinstance(key_config, dict):
            raise BundleSignatureError(
                f"Trust store entry '{key_id}' must be an object"
            )
        unknown_fields = set(key_config).difference(
            {"algorithm", "public_key_path", "issuer"}
        )
        if unknown_fields:
            raise BundleSignatureError(
                f"Trust store entry '{key_id}' has unknown fields: "
                f"{sorted(unknown_fields)}"
            )
        if key_config.get("algorithm") != SIGNATURE_ALGORITHM:
            raise BundleSignatureError(
                f"Trust store entry '{key_id}' must use {SIGNATURE_ALGORITHM}"
            )
        public_key_path = key_config.get("public_key_path")
        if not isinstance(public_key_path, str) or not public_key_path.strip():
            raise BundleSignatureError(
                f"Trust store entry '{key_id}' is missing public_key_path"
            )
        issuer = key_config.get("issuer")
        if issuer is not None and (
            not isinstance(issuer, str)
            or not issuer.strip()
            or issuer != issuer.strip()
        ):
            raise BundleSignatureError(
                f"Trust store entry '{key_id}' has an invalid issuer"
            )

        key_path = Path(public_key_path)
        if not key_path.is_absolute():
            key_path = trust_store_path.parent / key_path
        try:
            public_key = load_public_key(key_path)
        except (OSError, TypeError, BundleSignatureError) as exc:
            raise BundleSignatureError(
                f"Unable to load trusted key '{key_id}': {exc}"
            ) from exc
        trusted_keys[key_id] = TrustedKey(
            key_id=key_id,
            public_key=public_key,
            issuer=issuer,
            source_path=key_path,
        )
    return trusted_keys


def normalize_trusted_keys(
    trusted_keys: Mapping[str, TrustedKey | str | bytes | Path] | None,
) -> dict[str, TrustedKey]:
    """Normalize programmatic trust roots into verified Ed25519 keys."""
    normalized: dict[str, TrustedKey] = {}
    for key_id, value in (trusted_keys or {}).items():
        if (
            not isinstance(key_id, str)
            or not key_id.strip()
            or key_id != key_id.strip()
        ):
            raise BundleSignatureError("Trusted key IDs must be non-empty strings")
        if isinstance(value, TrustedKey):
            if value.key_id != key_id:
                raise BundleSignatureError(
                    f"Trusted key mapping ID '{key_id}' does not match '{value.key_id}'"
                )
            normalized[key_id] = value
        else:
            normalized[key_id] = TrustedKey(
                key_id=key_id,
                public_key=load_public_key(value),
            )
    return normalized
