import sys
from pathlib import Path

import yaml

from hlinor_registry.cli import main
from hlinor_registry.validator import (
    validate_agent,
    validate_department,
    validate_lifecycle_map,
    validate_lifecycle_receipt,
    validate_lifecycle_schema,
    validate_policy,
    validate_production_action_boundary_example,
    validate_registry_file,
    validate_runtime_example,
    validate_skill,
    validate_tool_contract,
    validate_validator,
)


def test_search_agent_example_is_valid():
    errors = validate_agent("examples/search-agent.yaml")
    assert errors == []


def test_validate_command_remains_backward_compatible(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hlinor-registry",
            "validate",
            "examples/search-agent.yaml",
        ],
    )

    exit_code = main()

    assert exit_code == 0
    assert capsys.readouterr().out == "Registry file is valid.\n"


def test_department_schema_example_is_valid():
    errors = validate_department("registry/schema/department.yaml")
    assert errors == []


def test_policy_schema_example_is_valid():
    errors = validate_policy("registry/schema/policy.yaml")
    assert errors == []


def test_skill_schema_example_is_valid():
    errors = validate_skill("registry/schema/skill.yaml")
    assert errors == []


def test_validator_schema_example_is_valid():
    errors = validate_validator("registry/schema/validator.yaml")
    assert errors == []


def test_tool_contract_example_is_valid():
    errors = validate_tool_contract(
        "examples/tool-contracts/customer-support-tools.yaml"
    )
    assert errors == []


def test_wrong_type_for_list_field_produces_error(tmp_path):
    path = tmp_path / "skill.yaml"
    path.write_text(
        """\
id: web-search
name: Web Search
description: Searches for businesses.
inputs: query
outputs:
  - candidates
required_permissions:
  - internet-access
""",
        encoding="utf-8",
    )

    errors = validate_skill(path)

    assert "skill: Field must be a list: inputs" in errors


def test_validate_registry_file_dispatches_correctly():
    errors = validate_registry_file("department", "registry/schema/department.yaml")
    assert errors == []


def test_validate_registry_file_unsupported_entity_type():
    errors = validate_registry_file("unknown", "registry/schema/department.yaml")
    assert errors == ["Unsupported entity type: unknown"]


def test_inspect_output_is_deterministic(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hlinor-registry",
            "inspect",
            "registry/schema/agent.yaml",
        ],
    )

    exit_code = main()

    assert exit_code == 0
    assert capsys.readouterr().out == (
        "Path: registry/schema/agent.yaml\n"
        "id: search-agent\n"
        "name: Search Agent\n"
        "keys: allowed_actions, blocked_actions, department, description, id, "
        "name, policies, skills, validators\n"
    )


def test_runtime_receipt_examples_are_valid():
    paths = list(Path("examples/runtime").glob("*.yaml"))
    assert paths

    for path in paths:
        errors = validate_runtime_example(path)
        assert errors == []


def test_production_action_boundary_example_is_valid():
    errors = validate_production_action_boundary_example(
        "examples/control-loops/production-action-boundary.yaml"
    )
    assert errors == []


def test_lifecycle_map_example_is_valid():
    errors = validate_lifecycle_map(
        "examples/lifecycle/generic-agent-lifecycle-map.yaml"
    )
    assert errors == []


def test_lifecycle_receipt_example_is_valid():
    errors = validate_lifecycle_receipt(
        "examples/lifecycle/generic-lifecycle-receipt.yaml"
    )
    assert errors == []


def test_lifecycle_schema_files_are_valid():
    paths = sorted(Path("registry/schema").glob("lifecycle-*.schema.yaml"))
    assert paths

    for path in paths:
        errors = validate_lifecycle_schema(path)
        assert errors == []


def test_lifecycle_receipt_invalid_mode_produces_error(tmp_path):
    path = tmp_path / "receipt.yaml"
    path.write_text(
        """\
task_id: test-task
lifecycle_mode: wrong
input_refs: []
output_refs: []
changed_files: []
checks_run: []
risks_detected: []
next_recommended_mode: sweeper
stop_reason: completed
secrets_touched: false
production_behavior_changed: false
external_messages_sent: false
services_restarted: false
""",
        encoding="utf-8",
    )

    errors = validate_lifecycle_receipt(path)

    assert "lifecycle_receipt: Invalid lifecycle_mode: wrong" in errors


def test_validate_lifecycle_map_cli_command(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hlinor-registry",
            "validate-lifecycle-map",
            "examples/lifecycle/generic-agent-lifecycle-map.yaml",
        ],
    )

    exit_code = main()

    assert exit_code == 0
    assert capsys.readouterr().out == "Lifecycle map is valid.\n"


def test_verified_host_native_execution_context_is_valid():
    from hlinor_registry.validator import validate_execution_context

    errors = validate_execution_context(
        "examples/execution-context/verified-host-native-execution-context.yaml"
    )
    assert errors == []


def test_sandbox_cannot_declare_production_access(tmp_path):
    from hlinor_registry.validator import validate_execution_context

    path = tmp_path / "invalid-context.yaml"
    path.write_text(
        """
context_id: ctx-invalid
context_type: sandbox
status: verified
network_access: false
production_access: true
verification_method:
  - environment_classification
allowed_operations: []
blocked_operations:
  - production_write
verified_at: "2026-01-01T00:00:00Z"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    errors = validate_execution_context(path)

    assert (
        "execution_context: Sandbox or restricted context cannot declare production_access"
        in errors
    )


def test_host_native_marker_alone_is_not_verification(tmp_path):
    from hlinor_registry.validator import validate_execution_context

    path = tmp_path / "marker-only.yaml"
    path.write_text(
        """
context_id: ctx-marker-only
context_type: host_native
status: verified
network_access: true
production_access: false
verification_method:
  - environment_marker
allowed_operations:
  - live_public_discovery
blocked_operations:
  - production_write
verified_at: "2026-01-01T00:00:00Z"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    errors = validate_execution_context(path)

    assert (
        "execution_context: Environment marker alone does not verify host_native context"
        in errors
    )


def test_runtime_governance_examples_are_valid():
    from hlinor_registry.validator import (
        validate_action_preflight,
        validate_capability_verification,
        validate_evidence_claim_binding,
        validate_failure_circuit_breaker,
        validate_protected_resource_boundary,
    )

    assert (
        validate_action_preflight(
            "examples/runtime-governance/cost-bounded-action-preflight.yaml"
        )
        == []
    )
    assert (
        validate_capability_verification(
            "examples/runtime-governance/verified-capability.yaml"
        )
        == []
    )
    assert (
        validate_protected_resource_boundary(
            "examples/runtime-governance/protected-resource-boundary.yaml"
        )
        == []
    )
    assert (
        validate_evidence_claim_binding("examples/evidence/evidence-claim-check.yaml")
        == []
    )
    assert (
        validate_failure_circuit_breaker(
            "examples/control-loops/repeated-failure-stop.yaml"
        )
        == []
    )


def test_funding_intelligence_capability_registration_is_valid():
    from hlinor_registry.validator import validate_capability_registration

    assert validate_capability_registration("examples/funding_intelligence.yaml") == []


def test_passed_evidence_claim_requires_fresh_same_object(tmp_path):
    from hlinor_registry.validator import validate_evidence_claim_binding

    path = tmp_path / "invalid-evidence.yaml"
    path.write_text(
        """
binding_id: evidence-invalid
claim: unsupported claim
evidence_reference: evidence://example/other-object
evidence_type: screenshot
observation_time: "2026-01-01T00:00:00Z"
freshness_status: stale
same_object_verified: false
validator_result: passed
""".strip()
        + "\n",
        encoding="utf-8",
    )

    errors = validate_evidence_claim_binding(path)
    assert "evidence_claim_binding: Passed claim requires fresh evidence" in errors
    assert (
        "evidence_claim_binding: Passed claim requires same-object verification"
        in errors
    )


def test_open_circuit_breaker_cannot_continue(tmp_path):
    from hlinor_registry.validator import validate_failure_circuit_breaker

    path = tmp_path / "invalid-breaker.yaml"
    path.write_text(
        """
breaker_id: breaker-invalid
failure_fingerprint: repeated.failure
threshold: 2
current_count: 2
state: open
next_action: continue
updated_at: "2026-01-01T00:00:00Z"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    errors = validate_failure_circuit_breaker(path)
    assert "failure_circuit_breaker: Open breaker cannot continue" in errors


def test_case_colliding_actions_within_one_list_are_rejected(tmp_path):
    """Two spellings of one action inside a list are an authoring mistake."""
    path = tmp_path / "agent.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "id": "case-agent",
                "name": "Case Agent",
                "department": "testing",
                "description": "Agent with case-colliding action names.",
                "skills": [],
                "validators": [],
                "policies": [],
                "allowed_actions": ["read_db", "Read_DB"],
                "blocked_actions": [],
            }
        ),
        encoding="utf-8",
    )

    errors = validate_agent(path)

    assert any("differ only by case" in error for error in errors)


def test_case_colliding_actions_across_lists_are_rejected(tmp_path):
    """An allow entry that shadows a block entry by case must not compile.

    ``allowed_actions: [Read_DB]`` beside ``blocked_actions: [read_db]`` reads
    as a block but historically permitted the request.
    """
    path = tmp_path / "agent.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "id": "case-agent",
                "name": "Case Agent",
                "department": "testing",
                "description": "Agent with a block shadowed by case.",
                "skills": [],
                "validators": [],
                "policies": [],
                "allowed_actions": ["Read_DB"],
                "blocked_actions": ["read_db"],
            }
        ),
        encoding="utf-8",
    )

    errors = validate_agent(path)

    assert any("differs only by case" in error for error in errors)


def test_identical_action_in_both_lists_remains_valid(tmp_path):
    """The documented block-wins overlap is not a case collision."""
    path = tmp_path / "agent.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "id": "overlap-agent",
                "name": "Overlap Agent",
                "department": "testing",
                "description": "Agent relying on documented block priority.",
                "skills": [],
                "validators": [],
                "policies": [],
                "allowed_actions": ["read_db"],
                "blocked_actions": ["read_db"],
            }
        ),
        encoding="utf-8",
    )

    assert validate_agent(path) == []


REGISTRY_ENTRIES = [
    ("registry/agents/ticket-triage-agent.yaml", validate_agent),
    ("registry/departments/support.yaml", validate_department),
    ("registry/skills/classify-ticket.yaml", validate_skill),
    ("registry/validators/ticket-input-validator.yaml", validate_validator),
    ("registry/policies/no-customer-pii-in-logs.yaml", validate_policy),
]


def test_registry_entries_are_valid():
    """The entries shipped in registry/ are meant to be copied, so they must work.

    They exist because five empty directories in a project called a registry
    tell a reader nothing. Validating them here means a schema change that
    breaks them is caught rather than shipped as a broken starting point.
    """
    for path, validator in REGISTRY_ENTRIES:
        assert Path(path).is_file(), f"{path} is missing"
        errors = validator(path)
        assert errors == [], f"{path}: {errors}"


def test_registry_entries_reference_each_other():
    """The set is a worked example, not five unrelated stubs.

    Every cross-reference resolves, so a reader following one entry to the next
    does not hit a name that exists nowhere.
    """
    import yaml as yaml_module

    def load(path):
        return yaml_module.safe_load(Path(path).read_text(encoding="utf-8"))

    agent = load("registry/agents/ticket-triage-agent.yaml")
    department = load("registry/departments/support.yaml")
    skill = load("registry/skills/classify-ticket.yaml")
    validator = load("registry/validators/ticket-input-validator.yaml")
    policy = load("registry/policies/no-customer-pii-in-logs.yaml")

    assert agent["department"] == department["id"]
    assert agent["id"] in department["agents"]
    assert skill["id"] in agent["skills"]
    assert validator["id"] in agent["validators"]
    assert policy["id"] in agent["policies"]

    # The department's shared controls are the ones the agent declares.
    assert policy["id"] in department["shared_policies"]
    assert validator["id"] in department["shared_validators"]

    # A skill's required permissions should be actions the agent may perform.
    for permission in skill["required_permissions"]:
        assert permission in agent["allowed_actions"], (
            f"skill requires {permission!r}, which the agent is not allowed"
        )


def test_registry_agent_compiles_and_enforces():
    """An entry someone copies must survive compile and produce a decision."""
    import tempfile

    from hlinor_registry import PolicyChecker

    with tempfile.TemporaryDirectory() as workspace:
        manifest = Path(workspace) / "registry.yaml"
        manifest.write_text(
            "schema_version: '1.0'\n"
            "policies:\n"
            f"  - path: '{Path('registry/agents/ticket-triage-agent.yaml').resolve()}'\n"
            "metadata:\n"
            "  environment: test\n",
            encoding="utf-8",
        )
        bundle = Path(workspace) / "bundle.json"
        # Absolute source paths are rejected by design, so compile from a copy
        # placed beside the manifest instead.
        source = Path(workspace) / "agent.yaml"
        source.write_text(
            Path("registry/agents/ticket-triage-agent.yaml").read_text(
                encoding="utf-8"
            ),
            encoding="utf-8",
        )
        manifest.write_text(
            "schema_version: '1.0'\n"
            "policies:\n"
            "  - path: 'agent.yaml'\n"
            "metadata:\n"
            "  environment: test\n",
            encoding="utf-8",
        )
        assert (
            main(["compile", "--manifest", str(manifest), "--output", str(bundle)]) == 0
        )

        checker = PolicyChecker(str(bundle))
        assert checker.check_action("ticket-triage-agent", "classify_ticket").allowed
        assert checker.check_action("ticket-triage-agent", "refund_payment").denied
        # Case variants of a blocked action are still blocked.
        assert checker.check_action("ticket-triage-agent", "Refund_Payment").denied
