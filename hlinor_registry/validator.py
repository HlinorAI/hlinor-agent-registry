from pathlib import Path
import yaml

REQUIRED_EXECUTION_CONTEXT_FIELDS = [
    "context_id",
    "context_type",
    "status",
    "network_access",
    "production_access",
    "verification_method",
    "allowed_operations",
    "blocked_operations",
    "verified_at",
]

EXECUTION_CONTEXT_TYPES = {
    "sandbox",
    "restricted",
    "host_native",
    "remote_approved",
}

EXECUTION_CONTEXT_STATUSES = {
    "verified",
    "unverified",
    "invalid",
}

REQUIRED_AGENT_FIELDS = [
    "id",
    "name",
    "department",
    "description",
    "skills",
    "validators",
    "policies",
    "allowed_actions",
    "blocked_actions",
]

REQUIRED_DEPARTMENT_FIELDS = [
    "id",
    "name",
    "description",
    "agents",
    "shared_policies",
    "shared_validators",
]

REQUIRED_POLICY_FIELDS = [
    "id",
    "name",
    "description",
    "enforcement",
]

REQUIRED_SKILL_FIELDS = [
    "id",
    "name",
    "description",
    "inputs",
    "outputs",
    "required_permissions",
]

REQUIRED_VALIDATOR_FIELDS = [
    "id",
    "name",
    "description",
    "rules",
]

REQUIRED_RUNTIME_BINDING_FIELDS = [
    "binding_id",
    "session_id",
    "project_id",
    "workspace_id",
    "agent_id",
    "registry_version",
    "policy_bundle_digest",
    "tool_name",
    "tool_descriptor_digest",
    "normalized_argument_digest",
    "target_resource_scope",
    "approval_id_or_lease_id",
    "status",
    "issued_at",
    "expires_at",
]

REQUIRED_PRE_DISPATCH_CHECK_FIELDS = [
    "check_id",
    "session_id",
    "binding_id",
    "requested_tool_name",
    "observed_registry_version",
    "observed_policy_bundle_digest",
    "observed_tool_descriptor_digest",
    "observed_normalized_argument_digest",
    "observed_target_resource_scope",
    "matched_approved_binding",
    "decision",
    "checked_at",
]

REQUIRED_EXECUTION_RECEIPT_FIELDS = [
    "receipt_id",
    "session_id",
    "binding_id",
    "check_id",
    "timestamp",
    "actor",
    "requested_tool_name",
    "authorization_result",
    "side_effect_state",
    "matched_approved_binding",
    "registry_version",
    "policy_bundle_digest",
    "tool_descriptor_digest",
    "normalized_argument_digest",
    "target_resource_scope",
    "approval_id_or_lease_id",
]

REQUIRED_PRODUCTION_ACTION_BOUNDARY_FIELDS = [
    "boundary_id",
    "project_id",
    "workspace_id",
    "requested_action",
    "target_resource_scope",
    "approval_level",
    "pre_dispatch_check_required",
    "execution_receipt_required",
]

PRODUCTION_APPROVAL_LEVELS = {
    "automatic",
    "human_approval",
    "owner_approval",
    "denied_by_default",
}

AUTHORIZATION_RESULTS = {
    "allowed",
    "denied",
    "expired",
    "reapproval_required",
}

SIDE_EFFECT_STATES = {
    "blocked_before_side_effect",
    "side_effect_attempted",
}

def load_yaml(path: str | Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("YAML root must be an object")

    return data

def validate_execution_context(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(
        data,
        REQUIRED_EXECUTION_CONTEXT_FIELDS,
        "execution_context",
    )

    if "context_type" in data and data["context_type"] not in EXECUTION_CONTEXT_TYPES:
        errors.append("execution_context: Invalid context_type")

    if "status" in data and data["status"] not in EXECUTION_CONTEXT_STATUSES:
        errors.append("execution_context: Invalid status")

    for bool_field in ["network_access", "production_access"]:
        if bool_field in data and not isinstance(data[bool_field], bool):
            errors.append(f"execution_context: Field must be a boolean: {bool_field}")

    for list_field in [
        "verification_method",
        "allowed_operations",
        "blocked_operations",
    ]:
        if list_field in data and not isinstance(data[list_field], list):
            errors.append(f"execution_context: Field must be a list: {list_field}")

    if data.get("status") == "verified" and not data.get("verification_method"):
        errors.append(
            "execution_context: Verified context requires verification_method"
        )

    if data.get("context_type") in {"sandbox", "restricted"}:
        if data.get("production_access") is True:
            errors.append(
                "execution_context: Sandbox or restricted context cannot declare production_access"
            )

    if data.get("context_type") == "host_native":
        methods = data.get("verification_method")
        if isinstance(methods, list) and methods == ["environment_marker"]:
            errors.append(
                "execution_context: Environment marker alone does not verify host_native context"
            )

    return errors



ACTION_PREFLIGHT_REQUIRED_FIELDS = [
    "preflight_id",
    "execution_context_status",
    "dependency_status",
    "capability_status",
    "budget_status",
    "decision",
    "checked_at",
]

CAPABILITY_VERIFICATION_REQUIRED_FIELDS = [
    "verification_id",
    "requested_capability",
    "observed_capabilities",
    "required_permissions",
    "matched",
    "status",
    "verified_at",
]

CAPABILITY_REGISTRATION_REQUIRED_FIELDS = [
    "id",
    "type",
    "name",
    "description",
    "repository",
    "version",
    "interfaces",
    "policies",
    "validators",
    "metadata",
]

CAPABILITY_POLICY_SEVERITIES = {"low", "medium", "high", "critical"}

PROTECTED_RESOURCE_BOUNDARY_REQUIRED_FIELDS = [
    "boundary_id",
    "resource_class",
    "resource_scope",
    "allowed_operations",
    "blocked_operations",
    "approval_level",
    "audit_required",
]

EVIDENCE_CLAIM_BINDING_REQUIRED_FIELDS = [
    "binding_id",
    "claim",
    "evidence_reference",
    "evidence_type",
    "observation_time",
    "freshness_status",
    "same_object_verified",
    "validator_result",
]

FAILURE_CIRCUIT_BREAKER_REQUIRED_FIELDS = [
    "breaker_id",
    "failure_fingerprint",
    "threshold",
    "current_count",
    "state",
    "next_action",
    "updated_at",
]

def validate_action_preflight(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(data, ACTION_PREFLIGHT_REQUIRED_FIELDS, "action_preflight")
    if data.get("decision") not in {"allowed", "blocked", "reapproval_required"}:
        errors.append("action_preflight: Invalid decision")
    for field in ["execution_context_status", "dependency_status", "capability_status", "budget_status"]:
        if field in data and data[field] not in {"passed", "failed", "not_required", "unknown"}:
            errors.append(f"action_preflight: Invalid status: {field}")
    return errors

def validate_capability_verification(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(data, CAPABILITY_VERIFICATION_REQUIRED_FIELDS, "capability_verification")
    for field in ["observed_capabilities", "required_permissions"]:
        if field in data and not isinstance(data[field], list):
            errors.append(f"capability_verification: Field must be a list: {field}")
    if "matched" in data and not isinstance(data["matched"], bool):
        errors.append("capability_verification: Field must be a boolean: matched")
    if data.get("status") not in {"verified", "unverified", "invalid"}:
        errors.append("capability_verification: Invalid status")
    if data.get("status") == "verified" and data.get("matched") is not True:
        errors.append("capability_verification: Verified capability must match")
    return errors


def validate_capability_registration(path: str | Path) -> list[str]:
    """Validate a capability registration and its governance contracts."""
    data = load_yaml(path)
    errors = _validate_required_fields(
        data,
        CAPABILITY_REGISTRATION_REQUIRED_FIELDS,
        "capability_registration",
    )

    for field in ["id", "name", "description", "repository", "version"]:
        if field in data and (not isinstance(data[field], str) or not data[field].strip()):
            errors.append(f"capability_registration: Field must be a non-empty string: {field}")

    if data.get("type") != "capability":
        errors.append("capability_registration: Field must equal capability: type")

    interfaces = data.get("interfaces")
    if not isinstance(interfaces, dict):
        errors.append("capability_registration: Field must be an object: interfaces")
    else:
        for section in ["inputs", "outputs"]:
            values = interfaces.get(section)
            if not isinstance(values, list):
                errors.append(f"capability_registration: Interface section must be a list: {section}")
                continue
            for index, interface in enumerate(values):
                prefix = f"capability_registration: {section}[{index}]"
                if not isinstance(interface, dict):
                    errors.append(f"{prefix} must be an object")
                    continue
                for field in ["name", "type"]:
                    if not isinstance(interface.get(field), str) or not interface[field].strip():
                        errors.append(f"{prefix}: Missing or invalid field: {field}")
                if "required" in interface and not isinstance(interface["required"], bool):
                    errors.append(f"{prefix}: Field must be a boolean: required")

    policies = data.get("policies")
    if not isinstance(policies, list) or not policies:
        errors.append("capability_registration: Policies must be a non-empty list")
    else:
        for index, policy in enumerate(policies):
            prefix = f"capability_registration: policies[{index}]"
            if not isinstance(policy, dict):
                errors.append(f"{prefix} must be an object")
                continue
            for field in ["id", "description", "severity"]:
                if not isinstance(policy.get(field), str) or not policy[field].strip():
                    errors.append(f"{prefix}: Missing or invalid field: {field}")
            if policy.get("severity") not in CAPABILITY_POLICY_SEVERITIES:
                errors.append(f"{prefix}: Invalid severity")

    validators = data.get("validators")
    errors.extend(_validate_string_list_values(
        {"validators": validators},
        ["validators"],
        "capability_registration",
    ))

    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        errors.append("capability_registration: Field must be an object: metadata")
    else:
        for field in ["owner", "compliance_level", "last_audit"]:
            if not isinstance(metadata.get(field), str) or not metadata[field].strip():
                errors.append(f"capability_registration: Missing or invalid metadata field: {field}")

    return errors

def validate_protected_resource_boundary(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(data, PROTECTED_RESOURCE_BOUNDARY_REQUIRED_FIELDS, "protected_resource_boundary")
    if "resource_scope" in data and not isinstance(data["resource_scope"], dict):
        errors.append("protected_resource_boundary: Field must be an object: resource_scope")
    for field in ["allowed_operations", "blocked_operations"]:
        if field in data and not isinstance(data[field], list):
            errors.append(f"protected_resource_boundary: Field must be a list: {field}")
    if "audit_required" in data and not isinstance(data["audit_required"], bool):
        errors.append("protected_resource_boundary: Field must be a boolean: audit_required")
    if data.get("approval_level") not in PRODUCTION_APPROVAL_LEVELS:
        errors.append("protected_resource_boundary: Invalid approval_level")
    return errors

def validate_evidence_claim_binding(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(data, EVIDENCE_CLAIM_BINDING_REQUIRED_FIELDS, "evidence_claim_binding")
    if data.get("freshness_status") not in {"fresh", "stale", "unknown"}:
        errors.append("evidence_claim_binding: Invalid freshness_status")
    if data.get("validator_result") not in {"passed", "failed", "insufficient_evidence"}:
        errors.append("evidence_claim_binding: Invalid validator_result")
    if "same_object_verified" in data and not isinstance(data["same_object_verified"], bool):
        errors.append("evidence_claim_binding: Field must be a boolean: same_object_verified")
    if data.get("validator_result") == "passed":
        if data.get("freshness_status") != "fresh":
            errors.append("evidence_claim_binding: Passed claim requires fresh evidence")
        if data.get("same_object_verified") is not True:
            errors.append("evidence_claim_binding: Passed claim requires same-object verification")
    return errors

def validate_failure_circuit_breaker(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(data, FAILURE_CIRCUIT_BREAKER_REQUIRED_FIELDS, "failure_circuit_breaker")
    if data.get("state") not in {"closed", "open", "half_open"}:
        errors.append("failure_circuit_breaker: Invalid state")
    if data.get("next_action") not in {"continue", "stop", "retry_probe", "require_review"}:
        errors.append("failure_circuit_breaker: Invalid next_action")
    for field in ["threshold", "current_count"]:
        if field in data and (not isinstance(data[field], int) or data[field] < 0):
            errors.append(f"failure_circuit_breaker: Field must be a non-negative integer: {field}")
    if (
        isinstance(data.get("threshold"), int)
        and isinstance(data.get("current_count"), int)
        and data["current_count"] >= data["threshold"]
        and data.get("state") != "open"
    ):
        errors.append("failure_circuit_breaker: Threshold reached requires open state")
    if data.get("state") == "open" and data.get("next_action") == "continue":
        errors.append("failure_circuit_breaker: Open breaker cannot continue")
    return errors


def validate_agent(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors: list[str] = []

    for field in REQUIRED_AGENT_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    for list_field in ["skills", "validators", "policies", "allowed_actions", "blocked_actions"]:
        if list_field in data and not isinstance(data[list_field], list):
            errors.append(f"Field must be a list: {list_field}")

    return errors

def _validate_required_fields(data: dict, required_fields: list[str], prefix: str) -> list[str]:
    errors: list[str] = []

    for field in required_fields:
        if field not in data:
            errors.append(f"{prefix}: Missing required field: {field}")

    return errors

def _validate_list_fields(data: dict, list_fields: list[str], prefix: str) -> list[str]:
    errors: list[str] = []

    for list_field in list_fields:
        if list_field in data and not isinstance(data[list_field], list):
            errors.append(f"{prefix}: Field must be a list: {list_field}")

    return errors

def validate_department(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(
        data,
        REQUIRED_DEPARTMENT_FIELDS,
        "department",
    )
    errors.extend(_validate_list_fields(
        data,
        ["agents", "shared_policies", "shared_validators"],
        "department",
    ))

    return errors

def validate_policy(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(
        data,
        REQUIRED_POLICY_FIELDS,
        "policy",
    )

    if "enforcement" in data and (
        not isinstance(data["enforcement"], str) or not data["enforcement"].strip()
    ):
        errors.append("policy: Field must be a non-empty string: enforcement")

    return errors

def validate_skill(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(
        data,
        REQUIRED_SKILL_FIELDS,
        "skill",
    )
    errors.extend(_validate_list_fields(
        data,
        ["inputs", "outputs", "required_permissions"],
        "skill",
    ))

    return errors

def validate_validator(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(
        data,
        REQUIRED_VALIDATOR_FIELDS,
        "validator",
    )
    errors.extend(_validate_list_fields(
        data,
        ["rules"],
        "validator",
    ))

    return errors

def validate_runtime_binding(data: dict) -> list[str]:
    errors = _validate_required_fields(
        data,
        REQUIRED_RUNTIME_BINDING_FIELDS,
        "binding",
    )

    if "target_resource_scope" in data and not isinstance(data["target_resource_scope"], dict):
        errors.append("binding: Field must be an object: target_resource_scope")

    return errors

def validate_pre_dispatch_authorization_check(data: dict) -> list[str]:
    errors = _validate_required_fields(
        data,
        REQUIRED_PRE_DISPATCH_CHECK_FIELDS,
        "pre_dispatch_authorization_check",
    )

    if "matched_approved_binding" in data and not isinstance(data["matched_approved_binding"], bool):
        errors.append("pre_dispatch_authorization_check: Field must be a boolean: matched_approved_binding")

    if "decision" in data and data["decision"] not in AUTHORIZATION_RESULTS:
        errors.append("pre_dispatch_authorization_check: Invalid decision")

    if "observed_target_resource_scope" in data and not isinstance(data["observed_target_resource_scope"], dict):
        errors.append("pre_dispatch_authorization_check: Field must be an object: observed_target_resource_scope")

    return errors


def validate_registry_file(entity_type: str, path: str | Path) -> list[str]:
    validators = {
        "agent": validate_agent,
        "execution-context": validate_execution_context,
        "department": validate_department,
        "policy": validate_policy,
        "skill": validate_skill,
        "validator": validate_validator,
        "runtime-example": validate_runtime_example,
        "production-action-boundary-example": validate_production_action_boundary_example,
    }

    validator = validators.get(entity_type)
    if validator is None:
        return [f"Unsupported entity type: {entity_type}"]

    return validator(path)

def validate_execution_receipt(data: dict) -> list[str]:
    errors = _validate_required_fields(
        data,
        REQUIRED_EXECUTION_RECEIPT_FIELDS,
        "execution_receipt",
    )

    if "authorization_result" in data and data["authorization_result"] not in AUTHORIZATION_RESULTS:
        errors.append("execution_receipt: Invalid authorization_result")

    if "side_effect_state" in data and data["side_effect_state"] not in SIDE_EFFECT_STATES:
        errors.append("execution_receipt: Invalid side_effect_state")

    if "matched_approved_binding" in data and not isinstance(data["matched_approved_binding"], bool):
        errors.append("execution_receipt: Field must be a boolean: matched_approved_binding")

    if "target_resource_scope" in data and not isinstance(data["target_resource_scope"], dict):
        errors.append("execution_receipt: Field must be an object: target_resource_scope")

    if data.get("authorization_result") in {"denied", "expired", "reapproval_required"}:
        if data.get("side_effect_state") != "blocked_before_side_effect":
            errors.append("execution_receipt: Negative authorization results must block before side effect")

    if data.get("authorization_result") == "allowed" and data.get("matched_approved_binding") is not True:
        errors.append("execution_receipt: Allowed receipts must match an approved binding")

    return errors

def validate_runtime_example(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors: list[str] = []

    for section in ["binding", "pre_dispatch_authorization_check", "execution_receipt"]:
        if section not in data:
            errors.append(f"Missing required section: {section}")

    if "binding" in data:
        errors.extend(validate_runtime_binding(data["binding"]))

    if "pre_dispatch_authorization_check" in data:
        errors.extend(validate_pre_dispatch_authorization_check(data["pre_dispatch_authorization_check"]))

    if "execution_receipt" in data:
        errors.extend(validate_execution_receipt(data["execution_receipt"]))

    return errors


def validate_production_action_boundary_example(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors: list[str] = []

    for section in ["privacy", "boundary", "side_effect_allowed_only_when", "blocked_outcomes"]:
        if section not in data:
            errors.append(f"Missing required section: {section}")

    boundary = data.get("boundary")
    if isinstance(boundary, dict):
        errors.extend(_validate_required_fields(
            boundary,
            REQUIRED_PRODUCTION_ACTION_BOUNDARY_FIELDS,
            "boundary",
        ))

        if "target_resource_scope" in boundary and not isinstance(boundary["target_resource_scope"], dict):
            errors.append("boundary: Field must be an object: target_resource_scope")

        if "approval_level" in boundary and boundary["approval_level"] not in PRODUCTION_APPROVAL_LEVELS:
            errors.append("boundary: Invalid approval_level")

        for bool_field in ["pre_dispatch_check_required", "execution_receipt_required"]:
            if bool_field in boundary and not isinstance(boundary[bool_field], bool):
                errors.append(f"boundary: Field must be a boolean: {bool_field}")
    elif "boundary" in data:
        errors.append("boundary: Section must be an object")

    privacy = data.get("privacy")
    if isinstance(privacy, dict):
        for field in [
            "contains_customer_data",
            "contains_recipients",
            "contains_secrets",
            "contains_provider_specific_identifiers",
            "contains_production_paths",
        ]:
            if privacy.get(field) is not False:
                errors.append(f"privacy: Public example must set {field} to false")
    elif "privacy" in data:
        errors.append("privacy: Section must be an object")

    for list_field in ["side_effect_allowed_only_when", "blocked_outcomes"]:
        if list_field in data and not isinstance(data[list_field], list):
            errors.append(f"Field must be a list: {list_field}")

    return errors


LIFECYCLE_MODES = {
    "prototyper",
    "builder",
    "sweeper",
    "grower",
    "maintainer",
}

REQUIRED_LIFECYCLE_MODE_FIELDS = [
    "mode",
    "role_name",
    "mission",
    "allowed_inputs",
    "required_outputs",
    "hard_rules",
    "failure_conditions",
    "evidence_requirements",
    "never_do",
    "valid_handoff_targets",
]

REQUIRED_LIFECYCLE_RECEIPT_FIELDS = [
    "task_id",
    "lifecycle_mode",
    "input_refs",
    "output_refs",
    "changed_files",
    "checks_run",
    "risks_detected",
    "next_recommended_mode",
    "stop_reason",
    "secrets_touched",
    "production_behavior_changed",
    "external_messages_sent",
    "services_restarted",
]

LIFECYCLE_RECEIPT_STOP_REASONS = {
    "completed",
    "blocked",
    "failed",
    "needs_approval",
    "handed_off",
}

REQUIRED_LIFECYCLE_SCHEMA_FIELDS = [
    "$schema",
    "title",
    "type",
    "required",
    "properties",
]


def _validate_string_list_values(data: dict, fields: list[str], prefix: str) -> list[str]:
    errors: list[str] = []

    for field in fields:
        if field not in data:
            continue
        value = data[field]
        if not isinstance(value, list):
            errors.append(f"{prefix}: Field must be a list: {field}")
            continue
        for index, item in enumerate(value):
            if not isinstance(item, str) or not item.strip():
                errors.append(f"{prefix}: List item must be a non-empty string: {field}[{index}]")

    return errors


def _validate_lifecycle_mode_object(data: dict, prefix: str) -> list[str]:
    errors = _validate_required_fields(data, REQUIRED_LIFECYCLE_MODE_FIELDS, prefix)

    list_fields = [
        "allowed_inputs",
        "required_outputs",
        "hard_rules",
        "failure_conditions",
        "evidence_requirements",
        "never_do",
        "valid_handoff_targets",
    ]
    errors.extend(_validate_string_list_values(data, list_fields, prefix))

    mode = data.get("mode")
    if mode is not None and mode not in LIFECYCLE_MODES:
        errors.append(f"{prefix}: Invalid lifecycle mode: {mode}")

    for target in data.get("valid_handoff_targets", []) if isinstance(data.get("valid_handoff_targets"), list) else []:
        if target not in LIFECYCLE_MODES:
            errors.append(f"{prefix}: Invalid handoff target: {target}")

    for field in ["role_name", "mission"]:
        if field in data and (not isinstance(data[field], str) or not data[field].strip()):
            errors.append(f"{prefix}: Field must be a non-empty string: {field}")

    return errors


def validate_lifecycle_map(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors: list[str] = []

    lifecycle_modes = data.get("lifecycle_modes")
    if not isinstance(lifecycle_modes, list) or not lifecycle_modes:
        return ["lifecycle_map: Missing or invalid required section: lifecycle_modes"]

    seen_modes: set[str] = set()
    for index, mode_contract in enumerate(lifecycle_modes):
        prefix = f"lifecycle_modes[{index}]"
        if not isinstance(mode_contract, dict):
            errors.append(f"{prefix}: Mode contract must be an object")
            continue
        errors.extend(_validate_lifecycle_mode_object(mode_contract, prefix))

        mode = mode_contract.get("mode")
        if mode in seen_modes:
            errors.append(f"{prefix}: Duplicate lifecycle mode: {mode}")
        if isinstance(mode, str):
            seen_modes.add(mode)

    missing_modes = sorted(LIFECYCLE_MODES - seen_modes)
    if missing_modes:
        errors.append("lifecycle_map: Missing lifecycle modes: " + ", ".join(missing_modes))

    return errors


def validate_lifecycle_receipt(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(data, REQUIRED_LIFECYCLE_RECEIPT_FIELDS, "lifecycle_receipt")

    lifecycle_mode = data.get("lifecycle_mode")
    if lifecycle_mode is not None and lifecycle_mode not in LIFECYCLE_MODES:
        errors.append(f"lifecycle_receipt: Invalid lifecycle_mode: {lifecycle_mode}")

    next_mode = data.get("next_recommended_mode")
    if next_mode is not None and next_mode not in LIFECYCLE_MODES:
        errors.append(f"lifecycle_receipt: Invalid next_recommended_mode: {next_mode}")

    stop_reason = data.get("stop_reason")
    if stop_reason is not None and stop_reason not in LIFECYCLE_RECEIPT_STOP_REASONS:
        errors.append(f"lifecycle_receipt: Invalid stop_reason: {stop_reason}")

    errors.extend(_validate_list_fields(
        data,
        ["input_refs", "output_refs", "changed_files", "checks_run", "risks_detected"],
        "lifecycle_receipt",
    ))

    for bool_field in [
        "secrets_touched",
        "production_behavior_changed",
        "external_messages_sent",
        "services_restarted",
    ]:
        if bool_field in data and not isinstance(data[bool_field], bool):
            errors.append(f"lifecycle_receipt: Field must be a boolean: {bool_field}")

    return errors


def validate_lifecycle_schema(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors = _validate_required_fields(data, REQUIRED_LIFECYCLE_SCHEMA_FIELDS, "lifecycle_schema")

    if "$defs" not in data:
        errors.append("lifecycle_schema: Missing required field: $defs")

    if "type" in data and data["type"] != "object":
        errors.append("lifecycle_schema: Field must equal object: type")

    for list_field in ["required"]:
        if list_field in data and not isinstance(data[list_field], list):
            errors.append(f"lifecycle_schema: Field must be a list: {list_field}")

    for object_field in ["properties", "$defs"]:
        if object_field in data and not isinstance(data[object_field], dict):
            errors.append(f"lifecycle_schema: Field must be an object: {object_field}")

    return errors
