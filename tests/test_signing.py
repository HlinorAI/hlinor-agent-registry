"""Security-negative tests for signed policy bundle trust."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from hlinor_registry import BundleSignatureError, PolicyChecker, TrustedKey
from hlinor_registry.cli import main
from hlinor_registry.signing import (
    canonical_signature_payload,
    compute_bundle_digest,
    load_public_key,
    load_trust_store,
    normalize_trusted_keys,
    sign_bundle,
    verify_bundle_signature,
)

VALID_ISSUED_AT = "2026-01-01T00:00:00Z"
VALID_EXPIRES_AT = "2027-01-01T00:00:00Z"


def write_keypair(directory: Path, name: str) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_path = directory / f"{name}.private.pem"
    public_path = directory / f"{name}.public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def write_policy_inputs(
    directory: Path,
    *,
    environment: str = "production",
    bundle_revision: int = 7,
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    policy_path = directory / "agent.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "id": "signed-agent",
                "type": "agent",
                "name": "Signed Agent",
                "department": "security",
                "description": "Agent used to test signed policy bundles.",
                "skills": ["read"],
                "validators": ["input-validator"],
                "policies": [],
                "allowed_actions": ["read"],
                "blocked_actions": ["delete"],
                "enforcement_mode": "strict",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    manifest_path = directory / "registry.yaml"
    manifest_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "policies": [{"path": "agent.yaml"}],
                "metadata": {
                    "environment": environment,
                    "bundle_revision": bundle_revision,
                    "policy_revision": f"revision-{bundle_revision}",
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return manifest_path, policy_path


def write_trust_store(
    path: Path,
    public_key_path: Path,
    *,
    key_id: str = "prod-key-2026",
    issuer: str = "hlinor-policy-ci",
) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "keys": {
                    key_id: {
                        "algorithm": "Ed25519",
                        "public_key_path": str(public_key_path),
                        "issuer": issuer,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def compile_signed_bundle(
    directory: Path,
    *,
    key_id: str = "prod-key-2026",
    issuer: str = "hlinor-policy-ci",
    issued_at: str = VALID_ISSUED_AT,
    expires_at: str = VALID_EXPIRES_AT,
    bundle_revision: int = 7,
) -> tuple[Path, Path, Path]:
    manifest_path, _ = write_policy_inputs(
        directory,
        bundle_revision=bundle_revision,
    )
    private_path, public_path = write_keypair(directory / "keys", key_id)
    bundle_path = directory / "dist" / "policy-bundle.json"
    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--output",
                str(bundle_path),
                "--signing-key",
                str(private_path),
                "--key-id",
                key_id,
                "--issuer",
                issuer,
                "--issued-at",
                issued_at,
                "--expires-at",
                expires_at,
            ]
        )
        == 0
    )
    return bundle_path, private_path, public_path


def test_signed_production_bundle_is_verified(tmp_path: Path) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    trust_store = write_trust_store(tmp_path / "trust-store.json", public_path)

    checker = PolicyChecker(
        str(bundle_path),
        trust_store=str(trust_store),
        signature_policy="required",
        required_issuer="hlinor-policy-ci",
        minimum_bundle_revision=7,
    )
    decision = checker.check_action("signed-agent", "read")

    assert decision.allowed
    assert decision.signature_key_id == "prod-key-2026"
    assert decision.signature_key_fingerprint
    assert decision.signature_key_fingerprint.startswith("sha256:")
    assert decision.signature_issuer == "hlinor-policy-ci"
    assert decision.signature_issued_at == VALID_ISSUED_AT
    assert decision.signature_expires_at == VALID_EXPIRES_AT
    event = checker.audit_event(decision)
    assert event["signature_key_id"] == "prod-key-2026"
    assert event["signature_key_fingerprint"] == decision.signature_key_fingerprint
    assert event["signature_issuer"] == "hlinor-policy-ci"


def test_long_lived_checker_revalidates_signature_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    checker = PolicyChecker(
        str(bundle_path),
        trusted_keys={"prod-key-2026": public_path},
        signature_policy="required",
    )

    def expired(*args: object, **kwargs: object) -> None:
        raise BundleSignatureError("Policy bundle signature has expired")

    monkeypatch.setattr(
        "hlinor_registry.policy_checker.validate_signature_window",
        expired,
    )

    with pytest.raises(BundleSignatureError, match="has expired"):
        checker.check_action("signed-agent", "read")
    with pytest.raises(BundleSignatureError, match="has expired"):
        checker.reload_if_changed()


def test_long_lived_checker_applies_trust_store_key_revocation(
    tmp_path: Path,
) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    trust_store = write_trust_store(tmp_path / "trust-store.json", public_path)
    checker = PolicyChecker(
        str(bundle_path),
        trust_store=str(trust_store),
        signature_policy="required",
    )
    assert checker.check_action("signed-agent", "read").allowed

    _, replacement_public = write_keypair(tmp_path / "replacement", "replacement")
    write_trust_store(trust_store, replacement_public)

    with pytest.raises(BundleSignatureError, match="signature verification failed"):
        checker.check_action("signed-agent", "read")


def test_signed_compilation_is_deterministic_and_excludes_private_key(
    tmp_path: Path,
) -> None:
    first_bundle, private_path, _ = compile_signed_bundle(tmp_path)
    second_bundle = tmp_path / "dist" / "policy-bundle-copy.json"
    assert (
        main(
            [
                "compile",
                "--manifest",
                str(tmp_path / "registry.yaml"),
                "--output",
                str(second_bundle),
                "--signing-key",
                str(private_path),
                "--key-id",
                "prod-key-2026",
                "--issuer",
                "hlinor-policy-ci",
                "--issued-at",
                VALID_ISSUED_AT,
                "--expires-at",
                VALID_EXPIRES_AT,
            ]
        )
        == 0
    )

    first_data = json.loads(first_bundle.read_text(encoding="utf-8"))
    second_data = json.loads(second_bundle.read_text(encoding="utf-8"))
    assert first_data == second_data
    assert "PRIVATE KEY" not in first_bundle.read_text(encoding="utf-8")
    assert set(first_data["signature"]) == {
        "algorithm",
        "key_id",
        "issuer",
        "issued_at",
        "expires_at",
        "value",
    }


def test_cli_verifies_signed_bundle_as_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    trust_store = write_trust_store(tmp_path / "trust-store.json", public_path)
    capsys.readouterr()

    result = main(
        [
            "verify-bundle",
            "--bundle",
            str(bundle_path),
            "--trust-store",
            str(trust_store),
            "--signature-policy",
            "required",
            "--required-issuer",
            "hlinor-policy-ci",
            "--minimum-bundle-revision",
            "7",
            "--format",
            "json",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["verified"] is True
    assert output["signature"]["key_id"] == "prod-key-2026"


def test_cli_check_uses_signed_bundle_trust_options(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    trust_store = write_trust_store(tmp_path / "trust-store.json", public_path)
    capsys.readouterr()

    result = main(
        [
            "check",
            "--bundle",
            str(bundle_path),
            "--trust-store",
            str(trust_store),
            "--signature-policy",
            "required",
            "--required-issuer",
            "hlinor-policy-ci",
            "--minimum-bundle-revision",
            "7",
            "--agent",
            "signed-agent",
            "--action",
            "read",
            "--format",
            "jsonl",
        ]
    )

    event = json.loads(capsys.readouterr().out)
    assert result == 0
    assert event["result"] == "allowed"
    assert event["signature_key_id"] == "prod-key-2026"
    assert event["signature_key_fingerprint"].startswith("sha256:")


def test_tampering_with_recomputed_digest_does_not_bypass_signature(
    tmp_path: Path,
) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["agents"]["signed-agent"]["config"]["allowed_actions"] = ["delete"]
    bundle["digest"] = compute_bundle_digest(bundle)
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(
        BundleSignatureError,
        match="signature verification failed",
    ):
        PolicyChecker(
            str(bundle_path),
            trusted_keys={"prod-key-2026": public_path},
            signature_policy="required",
        )


def test_signature_from_untrusted_private_key_is_rejected(tmp_path: Path) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    untrusted_private, _ = write_keypair(tmp_path / "untrusted", "untrusted")
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    forged = sign_bundle(
        bundle,
        private_key_path=untrusted_private,
        key_id="prod-key-2026",
        issuer="hlinor-policy-ci",
        issued_at=VALID_ISSUED_AT,
        expires_at=VALID_EXPIRES_AT,
    )
    bundle_path.write_text(json.dumps(forged), encoding="utf-8")

    with pytest.raises(
        BundleSignatureError,
        match="signature verification failed",
    ):
        PolicyChecker(
            str(bundle_path),
            trusted_keys={"prod-key-2026": public_path},
            signature_policy="required",
        )


def test_unknown_signing_key_is_rejected(tmp_path: Path) -> None:
    bundle_path, _, _ = compile_signed_bundle(tmp_path)

    with pytest.raises(BundleSignatureError, match="Unknown policy signing key"):
        PolicyChecker(str(bundle_path), signature_policy="required")


def test_expired_signature_is_rejected(tmp_path: Path) -> None:
    bundle_path, _, public_path = compile_signed_bundle(
        tmp_path,
        issued_at="2020-01-01T00:00:00Z",
        expires_at="2021-01-01T00:00:00Z",
    )

    with pytest.raises(BundleSignatureError, match="has expired"):
        PolicyChecker(
            str(bundle_path),
            trusted_keys={"prod-key-2026": public_path},
            signature_policy="required",
        )


def test_future_issued_signature_is_rejected(tmp_path: Path) -> None:
    bundle_path, _, public_path = compile_signed_bundle(
        tmp_path,
        issued_at="2099-01-01T00:00:00Z",
        expires_at="2100-01-01T00:00:00Z",
    )

    with pytest.raises(BundleSignatureError, match="issued in the future"):
        PolicyChecker(
            str(bundle_path),
            trusted_keys={"prod-key-2026": public_path},
            signature_policy="required",
        )


def test_wrong_required_issuer_is_rejected(tmp_path: Path) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)

    with pytest.raises(BundleSignatureError, match="required issuer"):
        PolicyChecker(
            str(bundle_path),
            trusted_keys={"prod-key-2026": public_path},
            signature_policy="required",
            required_issuer="different-policy-ci",
        )


def test_trust_store_key_issuer_is_enforced(tmp_path: Path) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    trust_store = write_trust_store(
        tmp_path / "trust-store.json",
        public_path,
        issuer="different-policy-ci",
    )

    with pytest.raises(BundleSignatureError, match="trusted key"):
        PolicyChecker(
            str(bundle_path),
            trust_store=str(trust_store),
            signature_policy="required",
        )


def test_revision_below_deployment_floor_is_rejected(tmp_path: Path) -> None:
    bundle_path, _, public_path = compile_signed_bundle(
        tmp_path,
        bundle_revision=7,
    )

    with pytest.raises(ValueError, match="below the trusted minimum 8"):
        PolicyChecker(
            str(bundle_path),
            trusted_keys={"prod-key-2026": public_path},
            signature_policy="required",
            minimum_bundle_revision=8,
        )


def test_unsigned_production_requires_explicit_override(tmp_path: Path) -> None:
    manifest_path, _ = write_policy_inputs(tmp_path)
    bundle_path = tmp_path / "bundle.json"
    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--output",
                str(bundle_path),
            ]
        )
        == 0
    )

    with pytest.raises(ValueError, match="Unsigned policy bundles"):
        PolicyChecker(str(bundle_path))

    checker = PolicyChecker(str(bundle_path), signature_policy="optional")
    assert checker.check_action("signed-agent", "read").allowed


def test_required_policy_rejects_unsigned_development_bundle(tmp_path: Path) -> None:
    manifest_path, _ = write_policy_inputs(tmp_path, environment="development")
    bundle_path = tmp_path / "bundle.json"
    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--output",
                str(bundle_path),
            ]
        )
        == 0
    )

    with pytest.raises(ValueError, match="signature is required"):
        PolicyChecker(str(bundle_path), signature_policy="required")


def test_unsigned_development_bundle_remains_compatible(tmp_path: Path) -> None:
    manifest_path, _ = write_policy_inputs(tmp_path, environment="development")
    bundle_path = tmp_path / "bundle.json"
    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--output",
                str(bundle_path),
            ]
        )
        == 0
    )

    assert PolicyChecker(str(bundle_path)).check_action("signed-agent", "read").allowed


def test_compile_requires_complete_signing_options(tmp_path: Path) -> None:
    manifest_path, _ = write_policy_inputs(tmp_path)
    private_path, _ = write_keypair(tmp_path / "keys", "incomplete")

    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--output",
                str(tmp_path / "bundle.json"),
                "--signing-key",
                str(private_path),
                "--key-id",
                "incomplete",
            ]
        )
        == 1
    )


def test_compile_rejects_naive_signature_timestamps(tmp_path: Path) -> None:
    manifest_path, _ = write_policy_inputs(tmp_path)
    private_path, _ = write_keypair(tmp_path / "keys", "naive-time")

    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--output",
                str(tmp_path / "bundle.json"),
                "--signing-key",
                str(private_path),
                "--key-id",
                "naive-time",
                "--issuer",
                "hlinor-policy-ci",
                "--issued-at",
                "2026-01-01T00:00:00",
                "--expires-at",
                VALID_EXPIRES_AT,
            ]
        )
        == 1
    )


@pytest.mark.parametrize("value", [None, "", "not-a-timestamp"])
def test_invalid_signature_timestamp_values_are_rejected(
    tmp_path: Path,
    value: object,
) -> None:
    private_path, _ = write_keypair(tmp_path, "timestamp")

    with pytest.raises(BundleSignatureError):
        sign_bundle(
            {"digest": "", "agents": {}, "capabilities": {}},
            private_key_path=private_path,
            key_id="timestamp",
            issuer="hlinor-policy-ci",
            issued_at=value,  # type: ignore[arg-type]
            expires_at=VALID_EXPIRES_AT,
        )


def test_signature_expiration_must_follow_issuance(tmp_path: Path) -> None:
    private_path, _ = write_keypair(tmp_path, "window")

    with pytest.raises(BundleSignatureError, match="must be after issued_at"):
        sign_bundle(
            {"digest": "", "agents": {}, "capabilities": {}},
            private_key_path=private_path,
            key_id="window",
            issuer="hlinor-policy-ci",
            issued_at=VALID_EXPIRES_AT,
            expires_at=VALID_ISSUED_AT,
        )


def test_signing_rejects_missing_invalid_and_wrong_algorithm_keys(
    tmp_path: Path,
) -> None:
    bundle = {"digest": "", "agents": {}, "capabilities": {}}
    common = {
        "key_id": "key",
        "issuer": "issuer",
        "issued_at": VALID_ISSUED_AT,
        "expires_at": VALID_EXPIRES_AT,
    }
    with pytest.raises(BundleSignatureError, match="not found"):
        sign_bundle(
            bundle,
            private_key_path=tmp_path / "missing.pem",
            **common,
        )

    invalid_path = tmp_path / "invalid.pem"
    invalid_path.write_text("not a private key", encoding="utf-8")
    with pytest.raises(BundleSignatureError, match="unencrypted PEM"):
        sign_bundle(bundle, private_key_path=invalid_path, **common)

    rsa_path = tmp_path / "rsa.pem"
    rsa_key = generate_private_key(public_exponent=65537, key_size=2048)
    rsa_path.write_bytes(
        rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(BundleSignatureError, match="must use Ed25519"):
        sign_bundle(bundle, private_key_path=rsa_path, **common)


def test_public_key_loading_accepts_supported_inputs_and_rejects_invalid(
    tmp_path: Path,
) -> None:
    _, public_path = write_keypair(tmp_path, "public")
    public_bytes = public_path.read_bytes()
    public_text = public_bytes.decode("utf-8")

    assert load_public_key(public_path)
    assert load_public_key(str(public_path))
    assert load_public_key(public_text)
    assert load_public_key(public_bytes)
    with pytest.raises(TypeError, match="PEM text"):
        load_public_key(123)  # type: ignore[arg-type]
    with pytest.raises(BundleSignatureError, match="valid PEM"):
        load_public_key(b"not a public key")

    rsa_public = generate_private_key(
        public_exponent=65537,
        key_size=2048,
    ).public_key()
    rsa_public_bytes = rsa_public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(BundleSignatureError, match="must use Ed25519"):
        load_public_key(rsa_public_bytes)


def test_canonical_payload_rejects_malformed_signature_and_missing_digest() -> None:
    with pytest.raises(BundleSignatureError, match="must be an object"):
        compute_bundle_digest({"digest": "", "signature": "invalid"})
    with pytest.raises(BundleSignatureError, match="missing a digest"):
        canonical_signature_payload({"agents": {}, "capabilities": {}})


def test_signature_envelope_validation_rejects_malformed_fields(
    tmp_path: Path,
) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    trusted_key = TrustedKey("prod-key-2026", load_public_key(public_path))
    original = json.loads(bundle_path.read_text(encoding="utf-8"))

    with pytest.raises(BundleSignatureError, match="missing a signature"):
        verify_bundle_signature(
            {"digest": original["digest"]},
            trusted_keys={"prod-key-2026": trusted_key},
        )

    for field_name, expected_error in (
        ("unknown", "unknown fields"),
        ("missing", "missing fields"),
        ("algorithm", "Unsupported signature algorithm"),
        ("key_id", "must be a non-empty string"),
        ("expires_at", "must be after issued_at"),
        ("value", "not valid base64"),
    ):
        candidate = json.loads(json.dumps(original))
        if field_name == "unknown":
            candidate["signature"]["unexpected"] = True
        elif field_name == "missing":
            del candidate["signature"]["issuer"]
        elif field_name == "algorithm":
            candidate["signature"]["algorithm"] = "RSA"
        elif field_name == "key_id":
            candidate["signature"]["key_id"] = ""
        elif field_name == "expires_at":
            candidate["signature"]["expires_at"] = candidate["signature"]["issued_at"]
        else:
            candidate["signature"]["value"] = "not-base64!"
        candidate["digest"] = compute_bundle_digest(candidate)

        with pytest.raises(BundleSignatureError, match=expected_error):
            verify_bundle_signature(
                candidate,
                trusted_keys={"prod-key-2026": trusted_key},
            )

    with pytest.raises(ValueError, match="clock_skew_seconds"):
        verify_bundle_signature(
            original,
            trusted_keys={"prod-key-2026": trusted_key},
            clock_skew_seconds=-1,
        )
    with pytest.raises(ValueError, match="current_time"):
        verify_bundle_signature(
            original,
            trusted_keys={"prod-key-2026": trusted_key},
            current_time=datetime(2026, 7, 26),  # noqa: DTZ001
        )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ("not-json", "Invalid trust store JSON"),
        ([], "root must be an object"),
        ({"schema_version": "2.0", "keys": {}}, "Unsupported trust store schema"),
        (
            {"schema_version": "1.0", "keys": {}, "extra": True},
            "unknown top-level",
        ),
        ({"schema_version": "1.0", "keys": {}}, "non-empty keys"),
        (
            {"schema_version": "1.0", "keys": {" bad ": {}}},
            "key IDs",
        ),
        (
            {"schema_version": "1.0", "keys": {"key": "invalid"}},
            "must be an object",
        ),
        (
            {
                "schema_version": "1.0",
                "keys": {
                    "key": {
                        "algorithm": "Ed25519",
                        "public_key_path": "key.pem",
                        "extra": True,
                    }
                },
            },
            "unknown fields",
        ),
        (
            {
                "schema_version": "1.0",
                "keys": {"key": {"algorithm": "RSA", "public_key_path": "key.pem"}},
            },
            "must use Ed25519",
        ),
        (
            {
                "schema_version": "1.0",
                "keys": {"key": {"algorithm": "Ed25519"}},
            },
            "missing public_key_path",
        ),
        (
            {
                "schema_version": "1.0",
                "keys": {
                    "key": {
                        "algorithm": "Ed25519",
                        "public_key_path": "key.pem",
                        "issuer": " bad ",
                    }
                },
            },
            "invalid issuer",
        ),
        (
            {
                "schema_version": "1.0",
                "keys": {
                    "key": {
                        "algorithm": "Ed25519",
                        "public_key_path": "missing.pem",
                    }
                },
            },
            "Unable to load trusted key",
        ),
    ],
)
def test_invalid_trust_store_contracts_are_rejected(
    tmp_path: Path,
    data: object,
    message: str,
) -> None:
    path = tmp_path / "trust-store.json"
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(BundleSignatureError, match=message):
        load_trust_store(path)


def test_trust_store_relative_key_path_and_programmatic_key_contract(
    tmp_path: Path,
) -> None:
    _, public_path = write_keypair(tmp_path / "keys", "relative")
    trust_store_path = tmp_path / "trust-store.json"
    trust_store_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "keys": {
                    "relative": {
                        "algorithm": "Ed25519",
                        "public_key_path": "keys/relative.public.pem",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    loaded = load_trust_store(trust_store_path)
    assert loaded["relative"].key_id == "relative"

    trusted = TrustedKey("relative", load_public_key(public_path))
    assert normalize_trusted_keys({"relative": trusted}) == {"relative": trusted}
    with pytest.raises(BundleSignatureError, match="does not match"):
        normalize_trusted_keys({"other": trusted})
    with pytest.raises(BundleSignatureError, match="non-empty strings"):
        normalize_trusted_keys({" bad ": public_path})
    with pytest.raises(FileNotFoundError, match="Trust store not found"):
        load_trust_store(tmp_path / "missing-trust-store.json")


@pytest.mark.parametrize(
    ("keyword_arguments", "message"),
    [
        ({"signature_policy": "invalid"}, "signature_policy"),
        ({"minimum_bundle_revision": -1}, "minimum_bundle_revision"),
        ({"minimum_bundle_revision": True}, "minimum_bundle_revision"),
        ({"clock_skew_seconds": -1}, "clock_skew_seconds"),
        ({"clock_skew_seconds": True}, "clock_skew_seconds"),
    ],
)
def test_policy_checker_rejects_invalid_trust_configuration(
    tmp_path: Path,
    keyword_arguments: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        PolicyChecker(str(tmp_path / "unused.json"), **keyword_arguments)  # type: ignore[arg-type]


def test_policy_checker_rejects_duplicate_programmatic_and_store_keys(
    tmp_path: Path,
) -> None:
    bundle_path, _, public_path = compile_signed_bundle(tmp_path)
    trust_store = write_trust_store(tmp_path / "trust-store.json", public_path)

    with pytest.raises(ValueError, match="Duplicate trusted key IDs"):
        PolicyChecker(
            str(bundle_path),
            trust_store=str(trust_store),
            trusted_keys={"prod-key-2026": public_path},
        )


@pytest.mark.parametrize(
    ("mutation", "message", "error_type"),
    [
        ({"schema_version": None}, "missing a schema", ValueError),
        ({"digest": ""}, "missing a digest", ValueError),
        ({"metadata": []}, "metadata must be an object", TypeError),
        (
            {"metadata": {"environment": ""}},
            "environment must be a non-empty string",
            ValueError,
        ),
        ({"bundle_revision": 0}, "revision must be a positive integer", ValueError),
        ({"agents": []}, "must contain an agents object", TypeError),
        (
            {"agents": {"": {"config": {}}}},
            "invalid agent ID",
            ValueError,
        ),
        ({"agents": {"agent": []}}, "Invalid bundle entry", TypeError),
        (
            {"agents": {"agent": {"source_path": "agent.yaml"}}},
            "Missing config",
            TypeError,
        ),
        (
            {
                "agents": {
                    "agent": {
                        "config": {"allowed_actions": "read"},
                        "source_path": "agent.yaml",
                    }
                }
            },
            "expected a list",
            ValueError,
        ),
    ],
)
def test_policy_checker_rejects_malformed_bundle_contracts(
    tmp_path: Path,
    mutation: dict[str, object],
    message: str,
    error_type: type[Exception],
) -> None:
    manifest_path, _ = write_policy_inputs(tmp_path, environment="development")
    bundle_path = tmp_path / "bundle.json"
    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--output",
                str(bundle_path),
            ]
        )
        == 0
    )
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle.update(mutation)
    if mutation.get("digest") != "":
        bundle["digest"] = compute_bundle_digest(bundle)
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(error_type, match=message):
        PolicyChecker(str(bundle_path))


def test_policy_checker_handles_invalid_json_and_safe_reload(tmp_path: Path) -> None:
    manifest_path, _ = write_policy_inputs(tmp_path, environment="development")
    bundle_path = tmp_path / "bundle.json"
    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--output",
                str(bundle_path),
            ]
        )
        == 0
    )
    checker = PolicyChecker(str(bundle_path))
    assert checker.reload_if_changed() is False

    bundle_path.unlink()
    with pytest.raises(FileNotFoundError, match="Policy bundle not found"):
        checker.reload_if_changed()

    bundle_path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        PolicyChecker(str(bundle_path))
