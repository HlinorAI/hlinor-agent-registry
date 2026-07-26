import sys

from hlinor_registry.cli import main
from hlinor_registry.validator import validate_capability_registration


def test_capability_registration_cli_command(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hlinor-registry",
            "validate-capability-registration",
            "examples/funding_intelligence.yaml",
        ],
    )

    exit_code = main()

    assert exit_code == 0
    assert capsys.readouterr().out == "Capability registration is valid.\n"


def test_capability_registration_rejects_unknown_policy_severity(tmp_path):
    path = tmp_path / "invalid-capability.yaml"
    lines = [
        "id: invalid-capability",
        "type: capability",
        "name: Invalid Capability",
        "description: Test capability",
        "repository: https://github.com/example/project",
        'version: "1.0.0"',
        "interfaces:",
        "  inputs:",
        "    - name: request",
        "      type: object",
        "  outputs:",
        "    - name: result",
        "      type: object",
        "policies:",
        "  - id: invalid-severity",
        "    description: Test policy",
        "    severity: urgent",
        "validators:",
        "  - schema_validator",
        "metadata:",
        "  owner: HlinorAI Team",
        "  compliance_level: internal-use",
        '  last_audit: "2026-07-22"',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    errors = validate_capability_registration(path)

    assert "capability_registration: policies[0]: Invalid severity" in errors
