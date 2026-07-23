"""Command-line interface for Hlinor Agent Registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from hlinor_registry.validator import (
    validate_failure_circuit_breaker,
    validate_evidence_claim_binding,
    validate_protected_resource_boundary,
    validate_capability_verification,
    validate_capability_registration,
    validate_action_preflight,
    validate_execution_context,
    load_yaml,
    validate_agent,
    validate_department,
    validate_policy,
    validate_production_action_boundary_example,
    validate_runtime_example,
    validate_skill,
    validate_validator,
    validate_lifecycle_map,
    validate_lifecycle_receipt,
    validate_lifecycle_schema,
    validate_registry_file,
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
}


def _compact_error(error: Exception) -> str:
    return " ".join(str(error).split())


def _run_validation(label: str, validator, path: str) -> int:
    try:
        errors = validator(path)
    except FileNotFoundError as error:
        errors = [_compact_error(error)]
    except (ValueError, yaml.YAMLError) as error:
        errors = [_compact_error(error)]

    if errors:
        print(f"Invalid {label}:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"{label} is valid.")
    return 0


def _inspect(path: str) -> int:
    try:
        data = load_yaml(path)
    except FileNotFoundError as error:
        print(f"Error: {_compact_error(error)}")
        return 1
    except ValueError as error:
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
    unsigned_bundle = dict(bundle)
    unsigned_bundle["digest"] = ""
    payload = json.dumps(
        unsigned_bundle,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _compile_error(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return 1


def cmd_compile(args: argparse.Namespace) -> int:
    """Compile an explicit registry manifest into an immutable JSON bundle."""
    manifest_path = Path(args.manifest).resolve()
    output_path = Path(args.output).resolve()

    if not manifest_path.is_file():
        return _compile_error(f"Manifest file not found: {manifest_path}")

    try:
        with manifest_path.open("r", encoding="utf-8") as stream:
            manifest = yaml.safe_load(stream)
    except (OSError, yaml.YAMLError) as exc:
        return _compile_error(f"Unable to read manifest: {exc}")

    if not isinstance(manifest, dict):
        return _compile_error("Manifest root must be an object.")

    policies = manifest.get("policies")
    if not isinstance(policies, list) or not policies:
        return _compile_error("Manifest must contain a non-empty 'policies' list.")

    metadata = manifest.get("metadata", {})
    if not isinstance(metadata, dict):
        return _compile_error("Manifest metadata must be an object.")

    if output_path == manifest_path:
        return _compile_error("Output path must not overwrite the manifest.")

    manifest_dir = manifest_path.parent
    bundle: dict[str, Any] = {
        "version": manifest.get("version", "1.0"),
        "metadata": metadata,
        "agents": {},
        "digest": "",
    }
    seen_paths: set[Path] = set()

    for index, policy_entry in enumerate(policies):
        if not isinstance(policy_entry, dict):
            return _compile_error(f"Invalid policy entry at index {index}: expected an object.")

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
        except (FileNotFoundError, ValueError, yaml.YAMLError) as exc:
            return _compile_error(f"Unable to load {file_path}: {exc}")

        entity_type = "capability" if config.get("type") == "capability" else "agent"
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

        agent_id = config.get("id")
        if not isinstance(agent_id, str) or not agent_id.strip():
            return _compile_error(f"Missing non-empty 'id' in {file_path}")

        if agent_id in bundle["agents"]:
            return _compile_error(f"Duplicate agent ID '{agent_id}' in manifest.")

        bundle["agents"][agent_id] = {
            "config": config,
            "entity_type": entity_type,
            "source_path": source_path.as_posix(),
            "digest": _compute_file_digest(file_path),
        }

    bundle["digest"] = _compute_bundle_digest(bundle)

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as stream:
            json.dump(bundle, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except OSError as exc:
        return _compile_error(f"Unable to write bundle: {exc}")

    print(f"Successfully compiled {len(bundle['agents'])} entries to {output_path}")
    print(f"Bundle digest: {bundle['digest']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hlinor-registry",
        description="Validate Hlinor Agent Registry YAML files.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate an agent YAML file")
    validate_parser.add_argument("path", help="Path to YAML file")

    for command in VALIDATION_COMMANDS:
        command_parser = subparsers.add_parser(command, help=f"Run {command}")
        command_parser.add_argument("path", help="Path to YAML file")

    inspect_parser = subparsers.add_parser("inspect", help="Inspect a YAML registry file")
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
    validate_capability_registration_parser.add_argument("path", help="Path to YAML file")

    validate_protected_resource_boundary_parser = subparsers.add_parser(
        "validate-protected-resource-boundary",
        help="Validate protected resource boundary YAML",
    )
    validate_protected_resource_boundary_parser.add_argument("path", help="Path to YAML file")

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

    args = parser.parse_args(argv)

    if args.command == "compile":
        return cmd_compile(args)

    if args.command == "validate":
        errors = validate_agent(args.path)

        if errors:
            print("Invalid registry file:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Registry file is valid.")
        return 0

    if args.command in VALIDATION_COMMANDS:
        label, validator = VALIDATION_COMMANDS[args.command]
        return _run_validation(label, validator, args.path)

    if args.command == "inspect":
        return _inspect(args.path)

    if args.command == "validate-execution-context":
        try:
            errors = validate_execution_context(args.path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Invalid execution context: {exc}")
            return 1

        if errors:
            print("Invalid execution context:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Execution context is valid.")
        return 0

    if args.command == "validate-action-preflight":
        try:
            errors = validate_action_preflight(args.path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Invalid action preflight: {exc}")
            return 1

        if errors:
            print("Invalid action preflight:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Action preflight is valid.")
        return 0

    if args.command == "validate-capability":
        try:
            errors = validate_capability_verification(args.path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Invalid capability verification: {exc}")
            return 1

        if errors:
            print("Invalid capability verification:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Capability verification is valid.")
        return 0

    if args.command == "validate-capability-registration":
        try:
            errors = validate_capability_registration(args.path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Invalid capability registration: {exc}")
            return 1

        if errors:
            print("Invalid capability registration:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Capability registration is valid.")
        return 0

    if args.command == "validate-protected-resource-boundary":
        try:
            errors = validate_protected_resource_boundary(args.path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Invalid protected resource boundary: {exc}")
            return 1

        if errors:
            print("Invalid protected resource boundary:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Protected resource boundary is valid.")
        return 0

    if args.command == "validate-evidence-claim":
        try:
            errors = validate_evidence_claim_binding(args.path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Invalid evidence claim binding: {exc}")
            return 1

        if errors:
            print("Invalid evidence claim binding:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Evidence claim binding is valid.")
        return 0

    if args.command == "validate-circuit-breaker":
        try:
            errors = validate_failure_circuit_breaker(args.path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Invalid failure circuit breaker: {exc}")
            return 1

        if errors:
            print("Invalid failure circuit breaker:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Failure circuit breaker is valid.")
        return 0

    return 1

if __name__ == "__main__":
    sys.exit(main())
