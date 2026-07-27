"""Tests for the zero-friction CLI commands: init, check, and explain."""

import argparse
import json
from pathlib import Path

import pytest
import yaml

from hlinor_registry.cli import (
    EXIT_ALLOWED,
    EXIT_DENIED,
    EXIT_ERROR,
    cmd_check,
    cmd_compile,
    cmd_explain,
    cmd_init,
    cmd_lint,
    main,
)


@pytest.fixture
def compiled_bundle(tmp_path: Path) -> Path:
    """Helper fixture to create a valid agent, manifest, and compile a bundle."""
    agent_config = {
        "id": "test-agent",
        "name": "Test Agent",
        "department": "qa",
        "description": "Agent for testing CLI commands",
        "skills": ["read_data"],
        "validators": ["input_sanitization"],
        "policies": ["no_pii_in_logs"],
        "allowed_actions": ["read_data"],
        "blocked_actions": ["send_email"],
        "enforcement_mode": "strict",
    }

    agent_file = tmp_path / "agent.yaml"
    with open(agent_file, "w") as f:
        yaml.dump(agent_config, f)

    manifest = {
        "version": "1.0",
        "policies": [{"path": "agent.yaml"}],
        "metadata": {"environment": "test"},
    }

    manifest_file = tmp_path / "registry.yaml"
    with open(manifest_file, "w") as f:
        yaml.dump(manifest, f)

    bundle_path = tmp_path / "bundle.json"

    args = argparse.Namespace(manifest=str(manifest_file), output=str(bundle_path))

    assert cmd_compile(args) == 0
    assert bundle_path.exists()
    return bundle_path


def test_cmd_init_creates_templates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Test that init creates registry.yaml and my_agent.yaml."""
    monkeypatch.chdir(tmp_path)

    args = argparse.Namespace()
    assert cmd_init(args) == 0

    assert (tmp_path / "registry.yaml").exists()
    assert (tmp_path / "my_agent.yaml").exists()

    # Verify content
    with open(tmp_path / "my_agent.yaml") as f:
        content = f.read()
    assert "id: my-agent" in content
    assert "blocked_actions:" in content


def test_cmd_init_skips_existing_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
):
    """Test that init does not overwrite existing files."""
    monkeypatch.chdir(tmp_path)

    # Create dummy files
    (tmp_path / "registry.yaml").write_text("dummy")
    (tmp_path / "my_agent.yaml").write_text("dummy")

    args = argparse.Namespace()
    assert cmd_init(args) == 0

    captured = capsys.readouterr()
    assert "already exists, skipping" in captured.out
    assert (tmp_path / "registry.yaml").read_text() == "dummy"


def test_cmd_check_allowed_action(compiled_bundle: Path, capsys: pytest.CaptureFixture):
    """Test check command returns 0 for allowed actions."""
    args = argparse.Namespace(
        bundle=str(compiled_bundle), agent="test-agent", action="read_data"
    )

    assert cmd_check(args) == 0

    captured = capsys.readouterr()
    assert "[ALLOWED]" in captured.out
    assert "EXPLICITLY_ALLOWED" in captured.out


def test_cmd_check_denied_action(compiled_bundle: Path, capsys: pytest.CaptureFixture):
    """Test check command returns 1 for blocked actions."""
    args = argparse.Namespace(
        bundle=str(compiled_bundle), agent="test-agent", action="send_email"
    )

    assert cmd_check(args) == 1

    captured = capsys.readouterr()
    assert "[DENIED]" in captured.out
    assert "ACTION_BLOCKLISTED" in captured.out


def test_cmd_check_missing_bundle(capsys: pytest.CaptureFixture):
    """Test check command handles missing bundle file gracefully."""
    args = argparse.Namespace(
        bundle="/tmp/non_existent_bundle_xyz.json",
        agent="test-agent",
        action="read_data",
    )

    assert cmd_check(args) == EXIT_ERROR
    captured = capsys.readouterr()
    assert "Error: Bundle file not found" in captured.err


def test_cmd_check_reports_an_invalid_bundle(
    capsys: pytest.CaptureFixture, tmp_path: Path
):
    """Check reports malformed bundle structure without a traceback."""
    bundle_path = tmp_path / "invalid-bundle.json"
    bundle_path.write_text("[]", encoding="utf-8")
    args = argparse.Namespace(
        bundle=str(bundle_path), agent="test-agent", action="read_data"
    )

    assert cmd_check(args) == EXIT_ERROR
    assert "Policy bundle root must be an object" in capsys.readouterr().err


def test_cmd_explain_denied_action(
    compiled_bundle: Path, capsys: pytest.CaptureFixture
):
    """Test explain command provides detailed analysis for denied actions."""
    args = argparse.Namespace(
        bundle=str(compiled_bundle), agent="test-agent", action="send_email"
    )

    assert cmd_explain(args) == 1

    captured = capsys.readouterr()
    assert "❌ DENIED" in captured.out
    assert "← THIS ONE" in captured.out
    assert " Action is explicitly listed in blocked_actions" in captured.out
    assert "HOW TO FIX:" in captured.out


def test_cmd_explain_allowed_action(
    compiled_bundle: Path, capsys: pytest.CaptureFixture
):
    """Test explain command provides detailed analysis for allowed actions."""
    args = argparse.Namespace(
        bundle=str(compiled_bundle), agent="test-agent", action="read_data"
    )

    assert cmd_explain(args) == 0

    captured = capsys.readouterr()
    assert "✅ ALLOWED" in captured.out
    assert "✓ Action is explicitly allowed" in captured.out


def test_cmd_explain_unknown_agent(
    compiled_bundle: Path, capsys: pytest.CaptureFixture
):
    """Test explain command handles unknown agents gracefully."""
    args = argparse.Namespace(
        bundle=str(compiled_bundle), agent="ghost-agent", action="read_data"
    )

    assert cmd_explain(args) == 1

    captured = capsys.readouterr()
    assert "Warning: Agent 'ghost-agent' not found in bundle" in captured.out


def test_cmd_check_jsonl_includes_policy_provenance(
    compiled_bundle: Path, tmp_path: Path, capsys: pytest.CaptureFixture
):
    """JSONL output is one parseable event with the active bundle digest."""
    audit_log = tmp_path / "audit" / "decisions.jsonl"
    args = argparse.Namespace(
        bundle=str(compiled_bundle),
        agent="test-agent",
        action="read_data",
        format="jsonl",
        audit_log=str(audit_log),
    )

    assert cmd_check(args) == 0

    event = json.loads(capsys.readouterr().out)
    persisted_event = json.loads(audit_log.read_text(encoding="utf-8"))
    assert event == persisted_event
    assert event["result"] == "allowed"
    assert event["policy_bundle_digest"]


def test_cmd_explain_jsonl_emits_only_one_json_record(
    compiled_bundle: Path, capsys: pytest.CaptureFixture
):
    """Machine-readable explain output does not mix in text formatting."""
    args = argparse.Namespace(
        bundle=str(compiled_bundle),
        agent="test-agent",
        action="send_email",
        format="jsonl",
        audit_log=None,
    )

    assert cmd_explain(args) == 1

    event = json.loads(capsys.readouterr().out)
    assert event["result"] == "denied"
    assert event["explanation"] == "Action blocked by policy"
    assert event["policy_bundle_digest"]


def test_cmd_lint_rejects_schema_invalid_list_values(
    tmp_path: Path, capsys: pytest.CaptureFixture
):
    """Lint fails safely instead of coercing malformed policy fields."""
    path = tmp_path / "invalid-agent.yaml"
    path.write_text(
        """\
id: invalid-agent
name: Invalid Agent
department: testing
description: Invalid policy for lint testing.
skills: []
validators: []
policies: []
allowed_actions: 42
blocked_actions: []
""",
        encoding="utf-8",
    )

    assert cmd_lint(argparse.Namespace(path=str(path))) == 1
    assert "Field must be a list: allowed_actions" in capsys.readouterr().out


def test_cmd_lint_rejects_permissive_production_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    path = tmp_path / "permissive-agent.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "id": "permissive-agent",
                "type": "agent",
                "name": "Permissive Agent",
                "department": "testing",
                "description": "Unsafe production policy.",
                "skills": [],
                "validators": [],
                "policies": [],
                "allowed_actions": ["read"],
                "blocked_actions": [],
                "enforcement_mode": "permissive",
                "metadata": {"environment": "production"},
            }
        ),
        encoding="utf-8",
    )

    assert cmd_lint(argparse.Namespace(path=str(path))) == 1
    assert "Permissive enforcement is unsafe in production" in capsys.readouterr().out


def test_check_exit_codes_separate_denial_from_failure(
    compiled_bundle: Path, tmp_path: Path
):
    """A denied action and a broken deployment must not share an exit code.

    A CI gate that treats every non-zero exit as "policy denied" reads an
    unreadable bundle or a bad trust store as working governance.
    """
    allowed = argparse.Namespace(
        bundle=str(compiled_bundle), agent="test-agent", action="read_data"
    )
    denied = argparse.Namespace(
        bundle=str(compiled_bundle), agent="test-agent", action="delete_data"
    )
    missing = argparse.Namespace(
        bundle=str(tmp_path / "absent.json"), agent="test-agent", action="read_data"
    )

    assert cmd_check(allowed) == EXIT_ALLOWED
    assert cmd_check(denied) == EXIT_DENIED
    assert cmd_check(missing) == EXIT_ERROR
    assert EXIT_ALLOWED != EXIT_DENIED != EXIT_ERROR


def test_explain_uses_the_same_exit_code_contract(
    compiled_bundle: Path, tmp_path: Path
):
    """explain must agree with check so either can gate a pipeline."""
    allowed = argparse.Namespace(
        bundle=str(compiled_bundle),
        agent="test-agent",
        action="read_data",
        format="jsonl",
    )
    denied = argparse.Namespace(
        bundle=str(compiled_bundle),
        agent="test-agent",
        action="delete_data",
        format="jsonl",
    )
    missing = argparse.Namespace(
        bundle=str(tmp_path / "absent.json"),
        agent="test-agent",
        action="read_data",
        format="jsonl",
    )

    assert cmd_explain(allowed) == EXIT_ALLOWED
    assert cmd_explain(denied) == EXIT_DENIED
    assert cmd_explain(missing) == EXIT_ERROR


def test_unwritable_audit_log_is_an_error_not_a_denial(compiled_bundle: Path):
    """A failed audit write must not be reported as an allowed or denied action."""
    args = argparse.Namespace(
        bundle=str(compiled_bundle),
        agent="test-agent",
        action="read_data",
        audit_log="/proc/self/mem/decisions.jsonl",
    )

    assert cmd_check(args) == EXIT_ERROR


def test_every_validation_subcommand_is_dispatched(capsys: pytest.CaptureFixture):
    """The parser and the dispatch table must not drift apart.

    Validation commands used to be registered in two places: a table and a
    hand-written if-chain that repeated the same try/except/print block nine
    times. A command present in one and missing from the other failed silently
    by falling through to a bare `return 1`.
    """
    from hlinor_registry.cli import VALIDATION_COMMANDS, main

    for command in VALIDATION_COMMANDS:
        exit_code = main([command, "definitely-not-a-real-path.yaml"])
        captured = capsys.readouterr()
        assert exit_code == 1, f"{command} did not report a failure"
        assert "not found" in (captured.out + captured.err).lower(), (
            f"{command} produced no diagnostic: {captured.out!r} {captured.err!r}"
        )


def test_dispatch_has_no_unreachable_parser_defaults():
    """argparse defaults that nothing reads are dead weight.

    Four parsers set `func=` while main() dispatched on `args.command`, so the
    attribute was never called. Two dispatch mechanisms where one is inert is
    how a command ends up registered but unreachable.
    """
    from pathlib import Path

    source = Path("hlinor_registry/cli.py").read_text(encoding="utf-8")
    assert "set_defaults(func=" not in source
    assert "args.func" not in source


def test_no_subcommand_is_registered_twice():
    """Registering a subparser name twice must fail loudly on every version.

    Python 3.10 accepted a duplicate subparser silently; 3.11 raises
    ArgumentError. Moving commands into the dispatch table while leaving their
    old explicit add_parser calls in place produced exactly that, and it passed
    locally on 3.10 and broke on the three newer versions in CI.

    Count the names the parser actually registers rather than trusting argparse
    to complain, so the check does not depend on the interpreter.
    """
    import argparse
    from unittest.mock import patch

    registered: list[str] = []
    original = argparse._SubParsersAction.add_parser

    def recording_add_parser(self, name, **kwargs):
        registered.append(name)
        return original(self, name, **kwargs)

    with (
        patch.object(argparse._SubParsersAction, "add_parser", recording_add_parser),
        pytest.raises(SystemExit),
    ):
        main(["--help"])

    duplicates = sorted({n for n in registered if registered.count(n) > 1})
    assert not duplicates, f"subcommands registered more than once: {duplicates}"


def test_help_builds_the_parser_on_any_version():
    """Building the full parser must not raise. Smoke test for the above."""
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
