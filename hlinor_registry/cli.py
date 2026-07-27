"""Command-line interface for Hlinor Agent Registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from enum import Enum
from pathlib import Path
from typing import Any, cast


class DecisionResult(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"


import yaml

from hlinor_registry import __version__
from hlinor_registry._limits import MAX_SOURCE_BYTES, read_text_capped
from hlinor_registry.signing import (
    BundleSignatureError,
    compute_bundle_digest,
    sign_bundle,
)
from hlinor_registry.validator import (
    load_yaml,
    validate_action_preflight,
    validate_agent,
    validate_capability_registration,
    validate_capability_verification,
    validate_department,
    validate_evidence_claim_binding,
    validate_execution_context,
    validate_failure_circuit_breaker,
    validate_lifecycle_map,
    validate_lifecycle_receipt,
    validate_lifecycle_schema,
    validate_policy,
    validate_production_action_boundary_example,
    validate_protected_resource_boundary,
    validate_registry_file,
    validate_runtime_example,
    validate_skill,
    validate_validator,
)

VALIDATION_COMMANDS = {
    "validate-agent": ("Agent", validate_agent),
    "validate-department": ("Department", validate_department),
    "validate-policy": ("Policy", validate_policy),
    "validate-skill": ("Skill", validate_skill),
    "validate-validator": ("Validator", validate_validator),
    "validate-runtime-example": ("Runtime example", validate_runtime_example),
    "validate-production-action-boundary-example": (
        "Production action boundary example",
        validate_production_action_boundary_example,
    ),
    "validate-lifecycle-map": ("Lifecycle map", validate_lifecycle_map),
    "validate-lifecycle-receipt": ("Lifecycle receipt", validate_lifecycle_receipt),
    "validate-lifecycle-schema": ("Lifecycle schema", validate_lifecycle_schema),
    "validate": ("Registry file", validate_agent),
    "validate-execution-context": ("Execution context", validate_execution_context),
    "validate-action-preflight": ("Action preflight", validate_action_preflight),
    "validate-capability": (
        "Capability verification",
        validate_capability_verification,
    ),
    "validate-capability-registration": (
        "Capability registration",
        validate_capability_registration,
    ),
    "validate-protected-resource-boundary": (
        "Protected resource boundary",
        validate_protected_resource_boundary,
    ),
    "validate-evidence-claim": (
        "Evidence claim binding",
        validate_evidence_claim_binding,
    ),
    "validate-circuit-breaker": (
        "Failure circuit breaker",
        validate_failure_circuit_breaker,
    ),
}


#: A policy decision was reached and the action is permitted.
EXIT_ALLOWED = 0
#: A policy decision was reached and the action is denied.
EXIT_DENIED = 1
#: No decision could be reached: bad arguments, unreadable bundle, broken trust
#: configuration, or a failed audit-log write. A caller that cannot tell this
#: apart from EXIT_DENIED will read a broken deployment as working governance.
EXIT_ERROR = 2


def _compact_error(error: Exception) -> str:
    return " ".join(str(error).split())


def _runtime_error(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return EXIT_ERROR


def _run_validation(label: str, validator, path: str) -> int:
    try:
        errors = validator(path)
    except FileNotFoundError as error:
        errors = [_compact_error(error)]
    except (TypeError, ValueError, yaml.YAMLError) as error:
        errors = [_compact_error(error)]

    if errors:
        print(f"Invalid {label}:")
        for validation_error in errors:
            print(f"- {validation_error}")
        return 1

    print(f"{label} is valid.")
    return 0


def _inspect(path: str) -> int:
    try:
        data = load_yaml(path)
    except FileNotFoundError as error:
        print(f"Error: {_compact_error(error)}")
        return 1
    except (TypeError, ValueError) as error:
        print(f"Error: {_compact_error(error)}")
        return 1
    except yaml.YAMLError as error:
        print(f"Error: Invalid YAML: {_compact_error(error)}")
        return 1

    keys = ", ".join(sorted(data))
    print(f"Path: {path}")
    print(f"id: {data.get('id', '<missing>')}")
    print(f"name: {data.get('name', '<missing>')}")
    print(f"keys: {keys}")
    return 0


def _compute_file_digest(filepath: Path) -> str:
    """Compute a SHA-256 digest for a source policy file."""
    sha256 = hashlib.sha256()
    with filepath.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _compute_bundle_digest(bundle: dict[str, Any]) -> str:
    """Compute the canonical digest for a bundle with its digest cleared."""
    return compute_bundle_digest(bundle)


def _compile_error(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return 1


def _schema_major(version: object) -> int:
    """Return a numeric schema major or raise a validation error."""
    if not isinstance(version, str) or not version.strip():
        raise ValueError("Schema version must be a non-empty string")
    major_text = version.split(".", maxsplit=1)[0]
    if not major_text.isdigit():
        raise ValueError(f"Invalid schema version: {version}")
    return int(major_text)


def _write_bundle_atomic(bundle: dict[str, Any], output_path: Path) -> None:
    """Verify a durable temporary bundle before atomically replacing output."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            json.dump(bundle, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        with temporary_path.open("r", encoding="utf-8") as stream:
            verified_bundle = json.load(stream)
        if not isinstance(verified_bundle, dict):
            raise TypeError("Compiled bundle root must be an object")
        if verified_bundle.get("digest") != _compute_bundle_digest(verified_bundle):
            raise ValueError("Compiled bundle failed digest verification")

        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _append_audit_event(event: dict[str, Any], audit_log: str | None) -> None:
    """Append one structured decision event to an optional JSONL audit sink."""
    if audit_log is None:
        return

    audit_log_path = Path(audit_log).resolve()
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_log_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True))
        stream.write("\n")


def cmd_compile(args: argparse.Namespace) -> int:
    """Compile an explicit registry manifest into an integrity-checked bundle."""
    manifest_path = Path(args.manifest).resolve()
    output_path = Path(args.output).resolve()

    if not manifest_path.is_file():
        return _compile_error(f"Manifest file not found: {manifest_path}")

    try:
        manifest = yaml.safe_load(
            read_text_capped(manifest_path, MAX_SOURCE_BYTES, "Manifest")
        )
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return _compile_error(f"Unable to read manifest: {exc}")

    if not isinstance(manifest, dict):
        return _compile_error("Manifest root must be an object.")

    policies = manifest.get("policies")
    if not isinstance(policies, list) or not policies:
        return _compile_error("Manifest must contain a non-empty 'policies' list.")

    metadata = manifest.get("metadata", {})
    if not isinstance(metadata, dict):
        return _compile_error("Manifest metadata must be an object.")

    schema_version = manifest.get("schema_version", manifest.get("version", "1.0"))
    try:
        schema_major = _schema_major(schema_version)
    except ValueError as exc:
        return _compile_error(str(exc))
    if schema_major != 1:
        return _compile_error(f"Unsupported schema major version: {schema_version}")

    environment = metadata.get("environment", "development")
    if not isinstance(environment, str) or not environment.strip():
        return _compile_error("Manifest environment must be a non-empty string.")

    bundle_revision = metadata.get("bundle_revision", 1)
    if (
        not isinstance(bundle_revision, int)
        or isinstance(bundle_revision, bool)
        or bundle_revision < 1
    ):
        return _compile_error("Manifest bundle_revision must be a positive integer.")

    policy_revision = metadata.get("policy_revision", "unknown")
    if not isinstance(policy_revision, str) or not policy_revision.strip():
        return _compile_error("Manifest policy_revision must be a non-empty string.")

    if output_path == manifest_path:
        return _compile_error("Output path must not overwrite the manifest.")

    manifest_dir = manifest_path.parent
    bundle: dict[str, Any] = {
        "schema_version": schema_version,
        "compiler_version": __version__,
        "bundle_revision": bundle_revision,
        "policy_revision": policy_revision,
        "metadata": metadata,
        "agents": {},
        "capabilities": {},
        "digest": "",
    }
    seen_paths: set[Path] = set()
    seen_ids: dict[str, str] = {}

    for index, policy_entry in enumerate(policies):
        if not isinstance(policy_entry, dict):
            return _compile_error(
                f"Invalid policy entry at index {index}: expected an object."
            )

        relative_path = policy_entry.get("path")
        if not isinstance(relative_path, str) or not relative_path.strip():
            return _compile_error(f"Policy entry at index {index} must contain a path.")

        source_path = Path(relative_path)
        if source_path.is_absolute():
            return _compile_error(
                f"Policy path must be relative to the manifest: {relative_path}"
            )

        file_path = (manifest_dir / source_path).resolve()
        try:
            file_path.relative_to(manifest_dir)
        except ValueError:
            return _compile_error(
                f"Policy path escapes the manifest directory: {relative_path}"
            )

        if file_path in seen_paths:
            return _compile_error(f"Duplicate policy path in manifest: {relative_path}")
        seen_paths.add(file_path)

        if not file_path.is_file():
            return _compile_error(f"Policy file not found: {file_path}")

        if output_path == file_path:
            return _compile_error(
                f"Output path must not overwrite a listed policy file: {relative_path}"
            )

        try:
            config = load_yaml(file_path)
        except (FileNotFoundError, TypeError, ValueError, yaml.YAMLError) as exc:
            return _compile_error(f"Unable to load {file_path}: {exc}")

        declared_type = config.get("type")
        if declared_type is None:
            entity_type = "agent"
        elif declared_type in {"agent", "capability"}:
            entity_type = declared_type
        else:
            return _compile_error(
                f"Unsupported entity type '{declared_type}' in {file_path}"
            )
        errors = (
            validate_capability_registration(file_path)
            if entity_type == "capability"
            else validate_registry_file("agent", file_path)
        )
        if errors:
            print(f"Error: Validation failed for {file_path}:", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1

        entity_id = config.get("id")
        if not isinstance(entity_id, str) or not entity_id.strip():
            return _compile_error(f"Missing non-empty 'id' in {file_path}")

        normalized_id = entity_id.casefold()
        if normalized_id in seen_ids:
            return _compile_error(
                f"Duplicate normalized entity ID '{entity_id}' conflicts with "
                f"'{seen_ids[normalized_id]}'."
            )
        seen_ids[normalized_id] = entity_id

        if (
            entity_type == "agent"
            and environment.casefold() == "production"
            and config.get("enforcement_mode", "strict") == "permissive"
            and not getattr(args, "allow_permissive_production", False)
        ):
            return _compile_error(
                f"Agent '{entity_id}' uses permissive mode in production. "
                "Use --allow-permissive-production only for an explicit unsafe override."
            )

        namespace = "capabilities" if entity_type == "capability" else "agents"
        bundle[namespace][entity_id] = {
            "config": config,
            "entity_type": entity_type,
            "source_path": source_path.as_posix(),
            "digest": _compute_file_digest(file_path),
        }

    signing_fields = {
        "signing_key": getattr(args, "signing_key", None),
        "key_id": getattr(args, "key_id", None),
        "issuer": getattr(args, "issuer", None),
        "issued_at": getattr(args, "issued_at", None),
        "expires_at": getattr(args, "expires_at", None),
    }
    configured_signing_fields = {
        field_name for field_name, value in signing_fields.items() if value is not None
    }
    if configured_signing_fields and len(configured_signing_fields) != len(
        signing_fields
    ):
        missing_fields = sorted(
            set(signing_fields).difference(configured_signing_fields)
        )
        return _compile_error(
            "Signed compilation requires all signing options; missing "
            + ", ".join(
                f"--{field_name.replace('_', '-')}" for field_name in missing_fields
            )
        )

    if signing_fields["signing_key"] is not None:
        signing_key_path = Path(signing_fields["signing_key"]).resolve()
        if signing_key_path in seen_paths or signing_key_path in {
            manifest_path,
            output_path,
        }:
            return _compile_error(
                "Signing key must be separate from the manifest, policy sources, "
                "and output bundle."
            )
        try:
            bundle = sign_bundle(
                bundle,
                private_key_path=signing_key_path,
                key_id=cast(str, signing_fields["key_id"]),
                issuer=cast(str, signing_fields["issuer"]),
                issued_at=cast(str, signing_fields["issued_at"]),
                expires_at=cast(str, signing_fields["expires_at"]),
            )
        except (OSError, TypeError, ValueError, BundleSignatureError) as exc:
            return _compile_error(f"Unable to sign bundle: {exc}")
    else:
        bundle["digest"] = _compute_bundle_digest(bundle)

    try:
        _write_bundle_atomic(bundle, output_path)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _compile_error(f"Unable to write bundle: {exc}")

    entry_count = len(bundle["agents"]) + len(bundle["capabilities"])
    print(f"Successfully compiled {entry_count} entries to {output_path}")
    print(f"Bundle digest: {bundle['digest']}")
    if "signature" in bundle:
        print(f"Signature key: {bundle['signature']['key_id']}")
    return 0


def cmd_init(args) -> int:
    """Generate template registry.yaml and agent policy files."""
    from pathlib import Path

    registry_template = (
        '# registry.yaml\nschema_version: "1.0"\npolicies:\n'
        '  - path: "my_agent.yaml"\nmetadata:\n'
        "  environment: development\n  bundle_revision: 1\n"
        '  policy_revision: "local"\n'
    )
    agent_template = (
        "# my_agent.yaml\n"
        "id: my-agent\n"
        "type: agent\n"
        "name: My First Agent\n"
        "department: engineering\n"
        "description: An example agent for testing governance\n"
        "skills:\n  - read_database\n"
        "validators:\n  - input_sanitization\n"
        "policies:\n  - no_pii_in_logs\n"
        "allowed_actions:\n  - read_database\n"
        "blocked_actions:\n  - send_external_email\n"
        "enforcement_mode: strict\n"
    )

    registry_path = Path("registry.yaml")
    agent_path = Path("my_agent.yaml")

    if not registry_path.exists():
        with open(registry_path, "w") as f:
            f.write(registry_template)
        print(f"Created {registry_path}")
    else:
        print(f"{registry_path} already exists, skipping")

    if not agent_path.exists():
        with open(agent_path, "w") as f:
            f.write(agent_template)
        print(f"Created {agent_path}")
    else:
        print(f"{agent_path} already exists, skipping")

    return 0


def _policy_checker_from_args(args: argparse.Namespace):
    """Create a PolicyChecker from shared CLI trust options."""
    from .policy_checker import PolicyChecker

    return PolicyChecker(
        bundle_path=str(Path(args.bundle).resolve()),
        trust_store=getattr(args, "trust_store", None),
        signature_policy=getattr(args, "signature_policy", "auto"),
        required_issuer=getattr(args, "required_issuer", None),
        minimum_bundle_revision=getattr(args, "minimum_bundle_revision", 0),
        clock_skew_seconds=getattr(args, "clock_skew_seconds", 60),
    )


def cmd_check(args) -> int:
    """Check if an action is allowed for an agent using a compiled bundle."""
    from pathlib import Path

    bundle_path = Path(args.bundle).resolve()

    if not bundle_path.is_file():
        return _runtime_error(f"Bundle file not found: {bundle_path}")

    try:
        checker = _policy_checker_from_args(args)
    except (OSError, ValueError, TypeError) as error:
        return _runtime_error(f"Failed to load bundle: {_compact_error(error)}")

    decision = checker.check_action(args.agent, args.action)
    output_format = getattr(args, "format", "text")
    event = checker.audit_event(decision)

    try:
        _append_audit_event(event, getattr(args, "audit_log", None))
    except OSError as error:
        return _runtime_error(f"Failed to write audit log: {_compact_error(error)}")

    if output_format == "jsonl":
        print(json.dumps(event, sort_keys=True))
    else:
        status = "ALLOWED" if decision.allowed else "DENIED"
        print(f"[{status}] {decision.reason_code}")
        print(f"Agent: {args.agent}")
        print(f"Action: {args.action}")
        print(f"Decision ID: {decision.decision_id}")
        print(f"Timestamp: {decision.checked_at}")

    return EXIT_ALLOWED if decision.allowed else EXIT_DENIED


def cmd_explain(args) -> int:
    """Explain why an action is allowed or denied for an agent."""
    from pathlib import Path

    bundle_path = Path(args.bundle).resolve()

    if not bundle_path.is_file():
        return _runtime_error(f"Bundle file not found: {bundle_path}")

    try:
        checker = _policy_checker_from_args(args)
    except (OSError, ValueError, TypeError) as error:
        return _runtime_error(f"Failed to load bundle: {_compact_error(error)}")

    decision = checker.check_action(args.agent, args.action)
    output_format = getattr(args, "format", "text")
    event = checker.audit_event(decision)
    event["explanation"] = (
        "Action explicitly allowed" if decision.allowed else "Action blocked by policy"
    )

    try:
        _append_audit_event(event, getattr(args, "audit_log", None))
    except OSError as error:
        return _runtime_error(f"Failed to write audit log: {_compact_error(error)}")

    if output_format == "jsonl":
        print(json.dumps(event, sort_keys=True))
        return EXIT_ALLOWED if decision.allowed else EXIT_DENIED

    print("=" * 60)
    print("GOVERNANCE DECISION EXPLANATION")
    print("=" * 60)
    print()
    print(f"Agent:    {args.agent}")
    print(f"Action:   {args.action}")
    print(f"Result:   {'✅ ALLOWED' if decision.allowed else '❌ DENIED'}")
    print(f"Reason:   {decision.reason_code}")
    print(f"Decision ID: {decision.decision_id}")
    print(f"Checked at: {decision.checked_at}")
    print()

    agent_info = checker.get_agent_info(args.agent)
    if agent_info is None:
        print(f"Warning: Agent '{args.agent}' not found in bundle")
        print("Available agents:")
        for agent_id in checker.agents:
            print(f"  - {agent_id}")
        print("=" * 60)
        # An unknown agent is still a policy decision: strict mode denies it.
        return EXIT_DENIED

    agent_config = agent_info["data"]
    allowed = agent_config.get("allowed_actions", [])
    blocked = agent_config.get("blocked_actions", [])
    print("-" * 60)
    print("AGENT CONFIGURATION")
    print("-" * 60)
    print(f"Name:           {agent_config.get('name', 'N/A')}")
    print(f"Department:     {agent_config.get('department', 'N/A')}")
    print(f"Enforcement:    {agent_info['enforcement_mode']}")
    print(f"Bundle digest:  {agent_info['bundle_digest']}")
    print()
    print("Allowed actions:")
    for action in allowed:
        marker = "← THIS ONE" if action == args.action and decision.allowed else ""
        print(f"  • {action} {marker}")
    print()
    print("Blocked actions:")
    for action in blocked:
        marker = "← THIS ONE" if action == args.action and decision.denied else ""
        print(f"  • {action} {marker}")
    print()
    print("Policies:")
    for policy in agent_config.get("policies", []):
        print(f"  • {policy}")
    print()
    print("-" * 60)
    print("ANALYSIS")
    print("-" * 60)

    if decision.denied:
        if args.action in blocked:
            print("✗ Action is explicitly listed in blocked_actions")
        else:
            print("✗ Action is NOT in allowed_actions (fail-closed enforcement)")
        print()
        print("HOW TO FIX:")
        print("  1. If this action should be allowed:")
        print("     - Add it to allowed_actions in the agent YAML")
        print("     - Ensure it's NOT in blocked_actions")
        print(
            "     - Recompile: hlinor-registry compile --manifest registry.yaml --output bundle.json"
        )
        print()
        print("  2. If this action should remain blocked:")
        print("     - No changes needed - governance is working correctly")
    else:
        print("✓ Action is explicitly allowed")
        print("✓ Agent can perform this action safely")

    print("=" * 60)
    return EXIT_ALLOWED if decision.allowed else EXIT_DENIED


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    """Verify bundle integrity, signature trust, validity, and rollback floor."""
    bundle_path = Path(args.bundle).resolve()
    if not bundle_path.is_file():
        print(f"Error: Bundle file not found: {bundle_path}", file=sys.stderr)
        return 1

    try:
        checker = _policy_checker_from_args(args)
    except (OSError, ValueError, TypeError) as error:
        print(
            f"Error: Bundle verification failed: {_compact_error(error)}",
            file=sys.stderr,
        )
        return 1

    signature = checker.verified_signature
    result = {
        "bundle": str(bundle_path),
        "bundle_digest": checker.bundle_digest,
        "bundle_revision": checker.bundle_revision,
        "policy_revision": checker.policy_revision,
        "environment": checker.environment,
        "signature": (
            {
                "algorithm": signature.algorithm,
                "key_id": signature.key_id,
                "key_fingerprint": signature.key_fingerprint,
                "issuer": signature.issuer,
                "issued_at": signature.issued_at,
                "expires_at": signature.expires_at,
            }
            if signature is not None
            else None
        ),
        "verified": True,
    }
    if getattr(args, "format", "text") == "json":
        print(json.dumps(result, sort_keys=True))
    else:
        trust_status = (
            f"signed by {signature.key_id} ({signature.issuer})"
            if signature is not None
            else "unsigned development bundle"
        )
        print(f"Bundle verified: {bundle_path}")
        print(f"Trust: {trust_status}")
        print(f"Digest: {checker.bundle_digest}")
        print(f"Revision: {checker.bundle_revision}")
    return 0


def cmd_lint(args) -> int:
    """Lint an agent YAML file for logical inconsistencies."""
    from pathlib import Path

    path = Path(args.path).resolve()
    if not path.is_file():
        print(f"Error: File not found: {path}")
        return 1
    try:
        data = load_yaml(path)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as error:
        print(f"Error: Invalid YAML: {_compact_error(error)}")
        return 1

    validation_errors = validate_agent(path)
    if validation_errors:
        print(f"Error: Invalid agent policy: {path}")
        for validation_error in validation_errors:
            print(f"- {validation_error}")
        return 1

    warnings = []
    allowed = data.get("allowed_actions") or []
    blocked = data.get("blocked_actions") or []
    mode = data.get("enforcement_mode", "strict")

    metadata = data.get("metadata", {})
    if (
        mode == "permissive"
        and isinstance(metadata, dict)
        and str(metadata.get("environment", "")).casefold() == "production"
    ):
        warnings.append("Permissive enforcement is unsafe in production.")

    allowed_set = set(allowed)
    blocked_set = set(blocked)

    # Check 1: Overlap (blocklist always wins, so this is confusing)
    overlap = allowed_set.intersection(blocked_set)
    if overlap:
        warnings.append(
            f"Actions found in both allowed and blocked lists (blocked takes priority): {overlap}"
        )

    # Check 2: Empty allowed in strict mode (agent will be completely paralyzed)
    if mode == "strict" and not allowed_set:
        warnings.append(
            "Enforcement mode is 'strict' but 'allowed_actions' is empty. The agent will be unable to perform any actions."
        )

    # Check 3: Duplicates
    normalized_allowed = {action.casefold() for action in allowed}
    normalized_blocked = {action.casefold() for action in blocked}
    if len(normalized_allowed) != len(allowed):
        warnings.append("Duplicate normalized entries found in 'allowed_actions'.")
    if len(normalized_blocked) != len(blocked):
        warnings.append("Duplicate normalized entries found in 'blocked_actions'.")

    if warnings:
        print(f"Linting warnings for {path}:")
        for w in warnings:
            print(f"  ⚠️  {w}")
        return 1
    else:
        print(f"✅ {path} passed logical checks.")
        return 0


def _add_trust_arguments(parser: argparse.ArgumentParser) -> None:
    """Add shared runtime bundle trust options to a CLI parser."""
    parser.add_argument(
        "--trust-store",
        help="Path to a JSON trust store containing Ed25519 public keys",
    )
    parser.add_argument(
        "--signature-policy",
        choices=["auto", "required", "optional"],
        default="auto",
        help=(
            "Signature policy: auto requires signatures outside development/test/local; "
            "required always requires one; optional is an explicit unsafe override"
        ),
    )
    parser.add_argument(
        "--required-issuer",
        help="Require the signed bundle to name this issuer",
    )
    parser.add_argument(
        "--minimum-bundle-revision",
        type=int,
        default=0,
        help="Reject bundle revisions below this trusted deployment floor",
    )
    parser.add_argument(
        "--clock-skew-seconds",
        type=int,
        default=60,
        help="Allowed clock skew for signature validity checks",
    )


def main(argv: list[str] | None = None) -> int:
    # Handle --version before argparse
    if argv is None:
        argv = sys.argv[1:]
    if "--version" in argv:
        print(f"hlinor-registry {__version__}")
        return 0

    parser = argparse.ArgumentParser(
        prog="hlinor-registry",
        description="Validate Hlinor Agent Registry YAML files.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Register explain command FIRST (order matters for subparsers)
    lint_parser = subparsers.add_parser(
        "lint", help="Lint an agent YAML file for logical inconsistencies"
    )
    lint_parser.add_argument("path", help="Path to YAML file")

    explain_parser = subparsers.add_parser(
        "explain", help="Explain why an action is allowed or denied"
    )
    explain_parser.add_argument(
        "--bundle", required=True, help="Path to compiled JSON bundle"
    )
    explain_parser.add_argument("--agent", required=True, help="Agent ID to check")
    explain_parser.add_argument("--action", required=True, help="Action to explain")
    explain_parser.add_argument(
        "--format",
        choices=["text", "jsonl"],
        default="text",
        help="Output format (text or jsonl)",
    )
    explain_parser.add_argument(
        "--audit-log",
        help="Append a provenance-aware JSONL decision event to this file",
    )
    _add_trust_arguments(explain_parser)

    # Register init command
    subparsers.add_parser("init", help="Generate template registry and agent files")

    # Register check command
    check_parser = subparsers.add_parser(
        "check", help="Check if an action is allowed for an agent"
    )
    check_parser.add_argument(
        "--bundle", required=True, help="Path to compiled JSON bundle"
    )
    check_parser.add_argument("--agent", required=True, help="Agent ID to check")
    check_parser.add_argument("--action", required=True, help="Action to check")
    check_parser.add_argument(
        "--format",
        choices=["text", "jsonl"],
        default="text",
        help="Output format (text or jsonl)",
    )
    check_parser.add_argument(
        "--audit-log",
        help="Append a provenance-aware JSONL decision event to this file",
    )
    _add_trust_arguments(check_parser)

    verify_bundle_parser = subparsers.add_parser(
        "verify-bundle",
        help="Verify bundle integrity, signature trust, validity, and revision",
    )
    verify_bundle_parser.add_argument(
        "--bundle",
        required=True,
        help="Path to compiled JSON bundle",
    )
    verify_bundle_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    _add_trust_arguments(verify_bundle_parser)

    # Register validation commands
    validate_parser = subparsers.add_parser(
        "validate", help="Validate an agent YAML file"
    )
    validate_parser.add_argument("path", help="Path to YAML file")

    for command in VALIDATION_COMMANDS:
        command_parser = subparsers.add_parser(command, help=f"Run {command}")
        command_parser.add_argument("path", help="Path to YAML file")

    inspect_parser = subparsers.add_parser(
        "inspect", help="Inspect a YAML registry file"
    )
    inspect_parser.add_argument("path", help="Path to YAML file")

    execution_context_parser = subparsers.add_parser(
        "validate-execution-context",
        help="Validate an execution context YAML file",
    )
    execution_context_parser.add_argument("path", help="Path to YAML file")

    validate_action_preflight_parser = subparsers.add_parser(
        "validate-action-preflight",
        help="Validate action preflight YAML",
    )
    validate_action_preflight_parser.add_argument("path", help="Path to YAML file")

    validate_capability_parser = subparsers.add_parser(
        "validate-capability",
        help="Validate capability verification YAML",
    )
    validate_capability_parser.add_argument("path", help="Path to YAML file")

    validate_capability_registration_parser = subparsers.add_parser(
        "validate-capability-registration",
        help="Validate capability registration YAML",
    )
    validate_capability_registration_parser.add_argument(
        "path", help="Path to YAML file"
    )

    validate_protected_resource_boundary_parser = subparsers.add_parser(
        "validate-protected-resource-boundary",
        help="Validate protected resource boundary YAML",
    )
    validate_protected_resource_boundary_parser.add_argument(
        "path", help="Path to YAML file"
    )

    validate_evidence_claim_parser = subparsers.add_parser(
        "validate-evidence-claim",
        help="Validate evidence claim binding YAML",
    )
    validate_evidence_claim_parser.add_argument("path", help="Path to YAML file")

    validate_circuit_breaker_parser = subparsers.add_parser(
        "validate-circuit-breaker",
        help="Validate failure circuit breaker YAML",
    )
    validate_circuit_breaker_parser.add_argument("path", help="Path to YAML file")

    # Register compile command
    compile_parser = subparsers.add_parser(
        "compile",
        help="Compile an explicit registry manifest into a JSON bundle",
    )
    compile_parser.add_argument(
        "--manifest",
        required=True,
        help="Path to registry manifest YAML",
    )
    compile_parser.add_argument(
        "--output",
        required=True,
        help="Path to compiled JSON bundle",
    )
    compile_parser.add_argument(
        "--allow-permissive-production",
        action="store_true",
        help="Explicitly allow unsafe permissive agents in a production bundle",
    )
    compile_parser.add_argument(
        "--signing-key",
        help="Path to an unencrypted PEM Ed25519 private key",
    )
    compile_parser.add_argument(
        "--key-id",
        help="Trusted key identifier embedded in the signature",
    )
    compile_parser.add_argument(
        "--issuer",
        help="Trusted policy issuer embedded in the signature",
    )
    compile_parser.add_argument(
        "--issued-at",
        help="Timezone-aware ISO-8601 signature issuance time",
    )
    compile_parser.add_argument(
        "--expires-at",
        help="Timezone-aware ISO-8601 signature expiration time",
    )

    args = parser.parse_args(argv)

    # Command handlers (order doesn't matter here)
    if args.command == "lint":
        return cmd_lint(args)

    if args.command == "explain":
        return cmd_explain(args)

    if args.command == "init":
        return cmd_init(args)

    if args.command == "check":
        return cmd_check(args)

    if args.command == "verify-bundle":
        return cmd_verify_bundle(args)

    if args.command == "compile":
        return cmd_compile(args)

    if args.command in VALIDATION_COMMANDS:
        label, validator = VALIDATION_COMMANDS[args.command]
        return _run_validation(label, validator, args.path)

    if args.command == "inspect":
        return _inspect(args.path)

    return 1


if __name__ == "__main__":
    sys.exit(main())
