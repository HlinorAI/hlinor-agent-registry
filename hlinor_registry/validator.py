from pathlib import Path
import yaml

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
