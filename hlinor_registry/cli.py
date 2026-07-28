"""Command-line interface for Hlinor Agent Registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

import yaml

from hlinor_registry import __version__
from hlinor_registry._limits import MAX_SOURCE_BYTES, read_text_capped
from hlinor_registry._matching import overlapping_allow_patterns
from hlinor_registry.action_request import ActionRequest
from hlinor_registry.enums import ReasonCode
from hlinor_registry.policies import POLICY_KINDS
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


#: Where each declared entity type lands in the compiled bundle.
_BUNDLE_NAMESPACES = {
    "agent": "agents",
    "capability": "capabilities",
    "policy": "policies",
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
        "policies": {},
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
        elif declared_type in {"agent", "capability", "policy"}:
            entity_type = declared_type
        else:
            return _compile_error(
                f"Unsupported entity type '{declared_type}' in {file_path}"
            )
        if entity_type == "capability":
            errors = validate_capability_registration(file_path)
        elif entity_type == "policy":
            errors = validate_policy(file_path)
        else:
            errors = validate_registry_file("agent", file_path)
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

        namespace = _BUNDLE_NAMESPACES[entity_type]
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

    entry_count = (
        len(bundle["agents"]) + len(bundle["capabilities"]) + len(bundle["policies"])
    )
    print(f"Successfully compiled {entry_count} entries to {output_path}")
    print(f"Bundle digest: {bundle['digest']}")
    if "signature" in bundle:
        print(f"Signature key: {bundle['signature']['key_id']}")
    for line in _policy_binding_report(bundle):
        print(line)
    return 0


def _policy_binding_report(bundle: dict[str, Any]) -> list[str]:
    """Say which declared policies are enforced and which are only prose.

    An agent naming a policy that compiled to no rule behaves exactly as it did
    before typed policies existed -- the name is documentation. That is a
    reasonable state to be in, and a dangerous one to be in by accident: drop
    the policy file from the manifest and enforcement disappears with nothing
    in the agent file changing. Compile is the last place to notice before the
    bundle is signed, so it says so here rather than leaving it to be inferred
    from behaviour in production.
    """
    enforceable = {
        policy_id
        for policy_id, entry in bundle["policies"].items()
        if isinstance(entry.get("config"), dict)
        and entry["config"].get("kind") in POLICY_KINDS
    }
    lines: list[str] = []
    for agent_id, entry in sorted(bundle["agents"].items()):
        declared = entry["config"].get("policies") or []
        named = [item for item in declared if isinstance(item, str)]
        bound = [policy_id for policy_id in named if policy_id in enforceable]
        unbound = [policy_id for policy_id in named if policy_id not in enforceable]
        if bound:
            lines.append(f"Agent '{agent_id}' enforces: {', '.join(bound)}")
        if unbound:
            lines.append(
                f"Agent '{agent_id}' declares but does not enforce: "
                f"{', '.join(unbound)} (no compiled policy with that id)"
            )
    return lines


#: Files written by `init`. The starter template is the first and often only
#: thing a new user reads closely, so it demonstrates what the runtime actually
#: enforces and nothing else. An earlier version declared a policy, a validator
#: and a skill that nothing evaluated, which meant the very next command --
#: `compile` -- warned about the file `init` had just written.
INIT_TEMPLATES: dict[str, str] = {
    "registry.yaml": """\
# registry.yaml -- the manifest. Compilation reads exactly these files and
# nothing else, so what runs is always a file someone listed on purpose.
schema_version: "1.0"
policies:
  - path: "my_agent.yaml"
  - path: "refund-needs-approval.yaml"
metadata:
  environment: development
  bundle_revision: 1
  policy_revision: "local"
""",
    "my_agent.yaml": """\
# my_agent.yaml -- one agent and its action boundary.
id: my-agent
type: agent
name: My First Agent
department: engineering
description: An example agent for testing governance

# An entry is matched against "action:resource". With no wildcard it is an
# exact match, so `read_database` permits the action with no resource named
# and nothing more. With `*` it scopes the action to what it may touch:
# reports are readable, anything else under the database is not.
allowed_actions:
  - read_database
  - read_database:reports/*
  - refund_payment:order/*

# Blocked always wins over allowed, and a bare entry here covers every
# resource. This agent can never send external email, whatever it is asked.
blocked_actions:
  - send_external_email

# Enforced: the policy below is compiled into the bundle and evaluated on
# every matching request. Try `refund_payment` without an approval and see.
policies:
  - refund-needs-approval

# Declarative: skills and validators are context for whoever reviews this
# file. PolicyChecker does not read them. See "What is enforced at runtime"
# in the README.
skills:
  - read_database
validators:
  - input_sanitization

enforcement_mode: strict
""",
    "refund-needs-approval.yaml": """\
# refund-needs-approval.yaml -- a typed policy.
#
# The action lists above answer "may this agent touch this resource at all".
# A policy answers what must be true of the particular request once it may:
# here, that a human approved this specific refund, recently.
id: refund-needs-approval
type: policy
name: Refund Needs Approval
description: A refund requires a recent approval naming that order.
enforcement: >-
  Enforced by PolicyChecker. The caller supplies the approval in
  ActionRequest.signals["approval"].

kind: requires_approval

# Matched with the same syntax as the action lists.
trigger:
  - refund_payment:*

requires:
  approver_role: support-lead
  # The approval must name what it approved, so one obtained for a small
  # refund cannot be replayed onto a larger one.
  bind_to_request: true
  max_age_seconds: 900
""",
}


def cmd_init(args) -> int:
    """Generate a starter manifest, agent, and typed policy."""
    created = []
    for filename, contents in INIT_TEMPLATES.items():
        path = Path(filename)
        if path.exists():
            print(f"{path} already exists, skipping")
            continue
        path.write_text(contents, encoding="utf-8")
        print(f"Created {path}")
        created.append(filename)

    if created:
        print()
        print("Next: compile the manifest, then ask the bundle a question.")
        print("  hlinor-registry compile --manifest registry.yaml --output bundle.json")
        print(
            "  hlinor-registry check --bundle bundle.json "
            "--agent my-agent --action refund_payment --resource order/1234"
        )

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

    try:
        request = _build_request(args, checker.environment)
    except (ValueError, TypeError) as error:
        return _runtime_error(_compact_error(error))

    decision = checker.evaluate(request)
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
        # A denial produced by a policy is otherwise indistinguishable from one
        # produced by the action lists, and the operator would have no way to
        # tell "this action is forbidden" from "this action needs an approval
        # nobody attached".
        if decision.policy_detail:
            print(f"Policy: {decision.policy_detail}")
        print(f"Decision ID: {decision.decision_id}")
        print(f"Timestamp: {decision.checked_at}")

    return EXIT_ALLOWED if decision.allowed else EXIT_DENIED


def _decision_explanation(decision: Any) -> tuple[str, list[str]]:
    """Describe a decision from its reason code, and say what to do about it.

    The previous version assumed two shapes: every denial came from the action
    lists, and every allowance was explicit. Neither holds. A denial can now
    come from a typed policy, and permissive mode can allow an action nobody
    listed.

    Wrong remediation advice is worse than none in a governance tool. An
    operator denied for a missing approval must not be told to widen the allow
    list -- that removes a control to work around a control that was doing its
    job. So the text is derived from ``reason_code``, ``matched_pattern`` and
    ``policy_detail`` rather than re-deducing the decision from the YAML.
    """
    code = ReasonCode(decision.reason_code)
    pattern = decision.matched_pattern
    detail = decision.policy_detail
    policies = ", ".join(decision.matched_policy_ids)

    if code is ReasonCode.ACTION_BLOCKLISTED:
        return (
            f"Denied by the block list entry {pattern!r}",
            [
                "The block list always wins, so no allow entry can override this.",
                f"To permit it, remove or narrow {pattern!r} in blocked_actions,",
                "then recompile the bundle.",
            ],
        )

    if code is ReasonCode.ACTION_NOT_ALLOWLISTED:
        return (
            "Denied because no allow pattern matched this action and resource",
            [
                "Strict enforcement denies anything not named. Add an entry to",
                "allowed_actions covering it -- remember the entry is matched",
                "against 'action:resource', so a bare name does not cover a",
                "request that names a resource. Then recompile.",
            ],
        )

    if code is ReasonCode.UNKNOWN_AGENT:
        return (
            "Denied because the bundle contains no agent with this ID",
            [
                "Check the spelling, or add the agent's file to the manifest",
                "and recompile.",
            ],
        )

    if code is ReasonCode.POLICY_SIGNAL_MISSING:
        return (
            f"Denied by policy {policies}: the request carried no such signal",
            [
                detail,
                "The action lists permit this action; a policy requires the",
                "request to supply something and it was absent. Widening",
                "allowed_actions will not help and would remove a control.",
                "Supply the signal from the adapter, or via --signals-file.",
            ],
        )

    if code is ReasonCode.APPROVAL_REQUIRED:
        return (
            f"Denied by policy {policies}: the approval did not satisfy it",
            [
                detail,
                "An approval arrived but does not meet the policy. Check the",
                "approver role, that granted_for names this request, and that",
                "granted_at is inside the freshness window and not in the future.",
            ],
        )

    if code is ReasonCode.EVIDENCE_REQUIRED:
        return (
            f"Denied by policy {policies}: the evidence did not satisfy it",
            [
                detail,
                "Check that a claim of each required type is present, names the",
                "same resource as the request, and carries a timezone-aware",
                "observed_at inside the window.",
            ],
        )

    if code is ReasonCode.FAILURE_THRESHOLD_REACHED:
        return (
            (
                f"Denied by policy {policies}: the reported failure count "
                f"reached its limit"
            ),
            [
                detail,
                "This is the breaker working. Resolve the underlying failures",
                "and reset the counter the adapter reports; do not raise the",
                "threshold to get past it.",
            ],
        )

    if code is ReasonCode.ALLOWED_NOT_BLOCKLISTED:
        return (
            "Allowed because permissive enforcement does not require a match",
            [
                "Nothing allowed this action explicitly and nothing blocked it.",
                "In strict mode the same request would be denied.",
            ],
        )

    if code is ReasonCode.EXPLICITLY_ALLOWED:
        summary = (
            f"Allowed by the allow list entry {pattern!r}"
            if pattern
            else "Allowed by the allow list"
        )
        remedy = []
        if policies:
            remedy.append(f"Policies evaluated and satisfied: {policies}.")
        return summary, remedy

    return (f"Decision reported {code}", [detail] if detail else [])


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

    try:
        request = _build_request(args, checker.environment)
    except (ValueError, TypeError) as error:
        return _runtime_error(_compact_error(error))

    decision = checker.evaluate(request)
    output_format = getattr(args, "format", "text")
    event = checker.audit_event(decision)
    summary, remedy = _decision_explanation(decision)
    event["explanation"] = summary

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

    print(f"{'✗' if decision.denied else '✓'} {summary}")
    if decision.matched_policy_ids:
        print(f"  Policies evaluated: {', '.join(decision.matched_policy_ids)}")
    if remedy:
        print()
        print("WHAT THIS MEANS:")
        for line in remedy:
            if line:
                print(f"  {line}")

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

    # Two severities. A warning is something to change before shipping and
    # fails the command. A note is a true statement about the policy that its
    # author may well have intended; it is printed and does not fail, because
    # a linter that rejects idiomatic policies is a linter people turn off.
    warnings: list[str] = []
    notes: list[str] = []
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

    # Check 4: An allow pattern that only the block list keeps in bounds.
    # '*' crosses ':', so the allow entry reaches further than its shape
    # suggests. This is a note rather than a warning: the syntax has no
    # negation, so "everything under this prefix except that" can only be
    # written as a broad allow plus a block, and that is a policy worth
    # describing rather than rejecting.
    for allow_pattern, block_pattern in overlapping_allow_patterns(allowed, blocked):
        notes.append(
            f"'{allow_pattern}' also covers '{block_pattern}'; the wildcard "
            f"crosses ':' and only 'blocked_actions' narrows it. Removing the "
            f"block entry would widen what this agent may do."
        )

    # Check 5: An allowlist that allows everything is a permissive policy
    # wearing a strict label. That is a warning, not a note: the file says
    # one thing and does another.
    if "*" in allowed:
        warnings.append(
            "'allowed_actions' contains '*', which permits every action. This is "
            "'permissive' enforcement written in the allowlist; set "
            "enforcement_mode instead so the intent is visible."
        )

    if notes:
        print(f"Notes for {path}:")
        for note in notes:
            print(f"  - {note}")

    if warnings:
        print(f"Linting warnings for {path}:")
        for w in warnings:
            print(f"  ⚠️  {w}")
        return 1

    print(f"✅ {path} passed logical checks.")
    return 0


def _add_request_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the request fields a decision can turn on.

    Without these the CLI can only ask about a bare action name, so an agent
    whose allow list scopes an action to a resource, or whose policies demand
    an approval, cannot be exercised from the terminal at all -- the one place
    a reviewer is most likely to check what a bundle actually does.
    """
    parser.add_argument(
        "--resource",
        help="Resource the action targets; matched as 'action:resource'",
    )
    parser.add_argument(
        "--signals-file",
        help=(
            "Path to a JSON object supplying policy signals "
            "(approval, evidence, failure_counts)"
        ),
    )


def _build_request(args: argparse.Namespace, environment: str) -> ActionRequest:
    """Build the request a decision command evaluates.

    Raises ValueError with a message fit for the terminal; the caller turns
    that into EXIT_ERROR rather than a denial, because a malformed signals
    file means no decision was reached, not that the action is refused.
    """
    signals: dict[str, Any] = {}
    signals_file = getattr(args, "signals_file", None)
    if signals_file:
        path = Path(signals_file).resolve()
        if not path.is_file():
            raise ValueError(f"Signals file not found: {path}")
        try:
            loaded = json.loads(read_text_capped(path, MAX_SOURCE_BYTES, "Signals"))
        except (OSError, ValueError) as error:
            raise ValueError(
                f"Unable to read signals file: {_compact_error(error)}"
            ) from error
        if not isinstance(loaded, dict):
            raise ValueError("Signals file must contain a JSON object")
        signals = loaded

    return ActionRequest(
        agent_id=args.agent,
        action=args.action,
        resource=getattr(args, "resource", None),
        signals=signals,
        environment=environment,
    )


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
    _add_request_arguments(explain_parser)
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
    _add_request_arguments(check_parser)
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

    for command in VALIDATION_COMMANDS:
        command_parser = subparsers.add_parser(command, help=f"Run {command}")
        command_parser.add_argument("path", help="Path to YAML file")

    inspect_parser = subparsers.add_parser(
        "inspect", help="Inspect a YAML registry file"
    )
    inspect_parser.add_argument("path", help="Path to YAML file")

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
