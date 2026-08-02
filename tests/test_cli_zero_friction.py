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
from hlinor_registry.enums import DecisionResult, ReasonCode


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
    assert (tmp_path / "refund-needs-approval.yaml").exists()

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
    assert "Denied by the block list entry 'send_email'" in captured.out
    assert "WHAT THIS MEANS:" in captured.out


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
    assert "Allowed by the allow list entry 'read_data'" in captured.out


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
    assert event["explanation"] == "Denied by the block list entry 'send_email'"
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

    registered: list[tuple[int, str]] = []
    original = argparse._SubParsersAction.add_parser

    def recording_add_parser(self, name, **kwargs):
        registered.append((id(self), name))
        return original(self, name, **kwargs)

    with (
        patch.object(argparse._SubParsersAction, "add_parser", recording_add_parser),
        pytest.raises(SystemExit),
    ):
        main(["--help"])

    duplicates = sorted(
        {
            name
            for parser_id, name in registered
            if registered.count((parser_id, name)) > 1
        }
    )
    assert not duplicates, f"subcommands registered more than once: {duplicates}"


def test_help_builds_the_parser_on_any_version():
    """Building the full parser must not raise. Smoke test for the above."""
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0


EVERYDAY_COMMANDS = {
    "init",
    "compile",
    "check",
    "explain",
    "lint",
    "test-policies",
    "contract",
    "verify-bundle",
    "inspect",
}


def _listed_subcommands(help_text: str) -> set[str]:
    """The subcommand names argparse prints, without the epilog.

    Entries in the listing are indented four spaces; the epilog uses two, so
    the two cannot be confused.
    """
    import re

    body = help_text.split("positional arguments:", 1)[1].split("options:", 1)[0]
    return set(re.findall(r"^ {4}([a-z][a-z-]+)", body, re.MULTILINE))


def test_help_lists_the_everyday_commands_and_not_the_schema_validators(
    capsys: pytest.CaptureFixture,
):
    """Twenty-eight subcommands in one alphabetical list answers no question.

    Nineteen of them validate a single file against a schema. Someone arriving
    from the README wants to know which command to run first, and the listing
    used to bury the nine that answer that among the nineteen that do not.
    """
    from hlinor_registry.cli import VALIDATION_COMMANDS

    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = capsys.readouterr().out

    listed = _listed_subcommands(help_text)
    assert listed == EVERYDAY_COMMANDS, (
        f"unexpected: {sorted(listed - EVERYDAY_COMMANDS)}, "
        f"missing: {sorted(EVERYDAY_COMMANDS - listed)}"
    )
    assert not listed & set(VALIDATION_COMMANDS)

    # argparse.SUPPRESS is the obvious way to hide a subparser and it does not
    # work: add_parser prints the sentinel as the help string. Omitting `help`
    # is what leaves the entry out. Asserted because the failure is cosmetic
    # enough to survive a casual review.
    assert "==SUPPRESS==" not in help_text
    assert "--list-validators" in help_text


def test_the_hidden_validators_are_listed_by_their_own_flag(
    capsys: pytest.CaptureFixture,
):
    """Hidden must mean hidden, not gone.

    That each one still runs is covered by
    test_every_validation_subcommand_is_dispatched; this covers whether a
    reader can find out they exist.
    """
    from hlinor_registry.cli import VALIDATION_COMMANDS

    assert main(["--list-validators"]) == 0
    printed = set(capsys.readouterr().out.split())
    assert printed == set(VALIDATION_COMMANDS)


def _lint_agent(tmp_path: Path, **overrides: object) -> argparse.Namespace:
    """Write a minimal valid agent policy and return lint's arguments."""
    config: dict[str, object] = {
        "id": "lint-agent",
        "type": "agent",
        "name": "Lint Agent",
        "department": "testing",
        "description": "Policy used for linter tests.",
        "skills": [],
        "validators": [],
        "policies": [],
        "allowed_actions": [],
        "blocked_actions": [],
    }
    config.update(overrides)
    path = tmp_path / "lint-agent.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return argparse.Namespace(path=str(path))


def test_lint_notes_when_only_the_block_list_narrows_a_wildcard(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """The greedy-'*' footgun, said out loud before it ships.

    'send:email:*' covers 'send:email:external:anyone' because '*' crosses
    ':'. The policy is safe only while the block entry stays. Deleting one
    line from blocked_actions silently widens the agent, and nothing in
    allowed_actions hints at that.

    Reported, but not as a failure. The syntax has no negation, so "all of
    this prefix except that" can only be written this way, and a linter that
    rejects the only available spelling of a common intent gets disabled.
    """
    args = _lint_agent(
        tmp_path,
        allowed_actions=["send:email:*"],
        blocked_actions=["send:email:external:*"],
    )

    assert cmd_lint(args) == 0
    output = capsys.readouterr().out
    assert "'send:email:*' also covers 'send:email:external:*'" in output
    assert "only 'blocked_actions' narrows it" in output


def test_lint_still_fails_when_a_real_warning_accompanies_a_note(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """A note must not soften a warning that shares the file with it."""
    args = _lint_agent(
        tmp_path,
        allowed_actions=["*", "send:email:*"],
        blocked_actions=["send:email:external:*"],
    )

    assert cmd_lint(args) == 1
    output = capsys.readouterr().out
    assert "only 'blocked_actions' narrows it" in output
    assert "permits every action" in output


def test_lint_accepts_a_wildcard_with_nothing_blocked_beneath_it(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """The warning must fire on the overlap, not on wildcards as such.

    A linter that complains about every '*' gets switched off, and then it
    protects nothing.
    """
    args = _lint_agent(
        tmp_path,
        allowed_actions=["read:report:*"],
        blocked_actions=["delete:report:*"],
    )

    assert cmd_lint(args) == 0
    assert "passed logical checks" in capsys.readouterr().out


def test_lint_rejects_an_allowlist_that_allows_everything(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """'*' in strict mode is permissive enforcement with a strict label."""
    args = _lint_agent(tmp_path, allowed_actions=["*"], blocked_actions=[])

    assert cmd_lint(args) == 1
    assert "permits every action" in capsys.readouterr().out


def test_lint_does_not_flag_an_identical_entry_on_both_lists_as_overlap(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """That case already has its own warning; two for one fact is noise."""
    args = _lint_agent(
        tmp_path,
        allowed_actions=["read:report:*"],
        blocked_actions=["read:report:*"],
    )

    assert cmd_lint(args) == 1
    output = capsys.readouterr().out
    assert "both allowed and blocked lists" in output
    assert "only 'blocked_actions' narrows it" not in output
    assert "Notes for" not in output


def _decision_bundle(tmp_path: Path) -> Path:
    """Compile an agent whose permission is scoped and policy-gated."""
    from tests.test_policy_checker import approval_policy, write_bundle

    return write_bundle(
        tmp_path,
        allowed_actions=["send:email:external:*"],
        policies=["needs-approval"],
        policy_files=[approval_policy()],
    )


def test_check_can_exercise_a_resource_scoped_permission(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Without --resource the CLI cannot reach a scoped allow list at all.

    It would report ACTION_NOT_ALLOWLISTED for an action the agent is in fact
    permitted to perform, which is the wrong answer to give a reviewer
    checking what a bundle does.
    """
    bundle = _decision_bundle(tmp_path)
    args = [
        "check",
        "--bundle",
        str(bundle),
        "--agent",
        "test-agent",
        "--action",
        "send",
        "--resource",
        "email:external:bob",
    ]

    assert main(args) == 1
    assert "POLICY_SIGNAL_MISSING" in capsys.readouterr().out


def test_check_reports_which_policy_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """A denial needing an approval must not look like a forbidden action."""
    bundle = _decision_bundle(tmp_path)
    main(
        [
            "check",
            "--bundle",
            str(bundle),
            "--agent",
            "test-agent",
            "--action",
            "send",
            "--resource",
            "email:external:bob",
        ]
    )
    output = capsys.readouterr().out
    assert "Policy: policy 'needs-approval'" in output


def test_check_accepts_signals_and_allows_a_satisfied_request(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bundle = _decision_bundle(tmp_path)
    signals_path = tmp_path / "signals.json"
    signals_path.write_text(
        json.dumps(
            {
                "approval": {
                    "approver_role": "security-lead",
                    "granted_for": "send:email:external:*",
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "check",
            "--bundle",
            str(bundle),
            "--agent",
            "test-agent",
            "--action",
            "send",
            "--resource",
            "email:external:bob",
            "--signals-file",
            str(signals_path),
        ]
    )

    assert exit_code == 0
    assert "[ALLOWED]" in capsys.readouterr().out


@pytest.mark.parametrize("content", ["not json", '"a string"', "[1, 2]"])
def test_an_unusable_signals_file_is_an_error_not_a_denial(
    tmp_path: Path, content: str
) -> None:
    """Exit 2, not 1.

    A caller that cannot tell "no decision was reached" from "the action is
    refused" reads a broken invocation as working governance.
    """
    bundle = _decision_bundle(tmp_path)
    signals_path = tmp_path / "signals.json"
    signals_path.write_text(content, encoding="utf-8")

    assert (
        main(
            [
                "check",
                "--bundle",
                str(bundle),
                "--agent",
                "test-agent",
                "--action",
                "send",
                "--resource",
                "email:external:bob",
                "--signals-file",
                str(signals_path),
            ]
        )
        == 2
    )


def test_a_missing_signals_file_is_an_error_not_a_denial(tmp_path: Path) -> None:
    bundle = _decision_bundle(tmp_path)
    assert (
        main(
            [
                "check",
                "--bundle",
                str(bundle),
                "--agent",
                "test-agent",
                "--action",
                "send",
                "--signals-file",
                str(tmp_path / "absent.json"),
            ]
        )
        == 2
    )


class TestExplanationCoversEveryReasonCode:
    """`explain` must describe the decision that happened, not the one it assumed.

    The original text knew two shapes: denials came from the action lists, and
    allowances were explicit. Typed policies, resource patterns and permissive
    mode broke both. In a governance tool wrong remediation advice is worse
    than none -- telling an operator denied for a missing approval to widen the
    allow list removes a control to work around a control that was working.
    """

    def explain(self, **fields: object):
        from hlinor_registry.cli import _decision_explanation
        from hlinor_registry.decision import PolicyDecision

        defaults: dict[str, object] = {
            "decision_id": "d",
            "agent_id": "a",
            "action": "act",
            "checked_at": "2026-07-27T12:00:00+00:00",
        }
        defaults.update(fields)
        return _decision_explanation(PolicyDecision(**defaults))

    #: Codes `evaluate()` can attach to a decision, and therefore the codes
    #: `explain` can be handed. The rest are raised while loading a bundle, so
    #: no decision carrying them ever exists.
    REACHABLE = (
        ReasonCode.EXPLICITLY_ALLOWED,
        ReasonCode.ALLOWED_NOT_BLOCKLISTED,
        ReasonCode.ACTION_BLOCKLISTED,
        ReasonCode.ACTION_NOT_ALLOWLISTED,
        ReasonCode.UNKNOWN_AGENT,
        ReasonCode.POLICY_SIGNAL_MISSING,
        ReasonCode.APPROVAL_REQUIRED,
        ReasonCode.EVIDENCE_REQUIRED,
        ReasonCode.FAILURE_THRESHOLD_REACHED,
    )

    def test_every_reachable_reason_code_has_its_own_branch(self):
        """No reachable code may fall through to the generic sentence.

        A code wired into evaluate() without a branch here would be described
        by whatever the fallback says, which is how a decision starts being
        explained wrongly rather than not at all.
        """
        summaries = set()
        for code in self.REACHABLE:
            allowed = code in (
                ReasonCode.EXPLICITLY_ALLOWED,
                ReasonCode.ALLOWED_NOT_BLOCKLISTED,
            )
            summary, _ = self.explain(
                result=DecisionResult.ALLOWED if allowed else DecisionResult.DENIED,
                reason_code=code,
            )
            assert summary, code
            assert not summary.startswith("Decision reported"), (
                f"{code} has no explanation branch"
            )
            summaries.add(summary)
        assert len(summaries) == len(self.REACHABLE), "two codes share one sentence"

    def test_the_reachable_set_matches_what_evaluate_can_produce(self):
        """Guard the list above against the enum growing past it."""
        load_time_only = {
            ReasonCode.BUNDLE_INTEGRITY_FAILED,
            ReasonCode.SIGNATURE_INVALID,
            ReasonCode.POLICY_EVALUATION_ERROR,
        }
        assert set(self.REACHABLE) | load_time_only == set(ReasonCode)

    def test_an_unhandled_code_still_produces_text_rather_than_raising(self):
        """The fallback exists for the load-time codes; it must not crash."""
        summary, _ = self.explain(
            result=DecisionResult.DENIED,
            reason_code=ReasonCode.BUNDLE_INTEGRITY_FAILED,
        )
        assert "BUNDLE_INTEGRITY_FAILED" in summary

    def test_a_missing_signal_never_advises_widening_the_allow_list(self):
        summary, remedy = self.explain(
            result=DecisionResult.DENIED,
            reason_code=ReasonCode.POLICY_SIGNAL_MISSING,
            matched_policy_ids=("needs-approval",),
            policy_detail="policy 'needs-approval' requires signals['approval']",
        )
        text = " ".join([summary, *remedy])
        assert "needs-approval" in text
        assert "will not help" in text
        assert "Add an entry to" not in text

    def test_a_blocklist_denial_names_the_pattern_that_refused(self):
        summary, remedy = self.explain(
            result=DecisionResult.DENIED,
            reason_code=ReasonCode.ACTION_BLOCKLISTED,
            matched_pattern="send:email:external:*",
        )
        assert "send:email:external:*" in summary
        assert any("block list always wins" in line for line in remedy)

    def test_a_scoped_allowance_names_the_matching_pattern(self):
        summary, _ = self.explain(
            result=DecisionResult.ALLOWED,
            reason_code=ReasonCode.EXPLICITLY_ALLOWED,
            matched_pattern="read:report:quarterly/*",
        )
        assert "read:report:quarterly/*" in summary

    def test_a_permissive_allowance_is_not_called_explicit(self):
        summary, remedy = self.explain(
            result=DecisionResult.ALLOWED,
            reason_code=ReasonCode.ALLOWED_NOT_BLOCKLISTED,
        )
        assert "explicit" not in summary.lower()
        assert "permissive" in summary.lower()
        assert any("strict mode" in line for line in remedy)

    def test_a_breaker_denial_does_not_suggest_raising_the_threshold(self):
        summary, remedy = self.explain(
            result=DecisionResult.DENIED,
            reason_code=ReasonCode.FAILURE_THRESHOLD_REACHED,
            matched_policy_ids=("payment-breaker",),
            policy_detail="payment-api reported 3 consecutive failures, limit is 3",
        )
        text = " ".join([summary, *remedy])
        assert "do not raise the" in text
        assert "payment-breaker" in text

    def test_text_and_jsonl_describe_the_same_decision(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """One source of truth, so the two outputs cannot disagree."""
        bundle = _decision_bundle(tmp_path)
        capsys.readouterr()  # discard the fixture's compile output
        base = [
            "explain",
            "--bundle",
            str(bundle),
            "--agent",
            "test-agent",
            "--action",
            "send",
            "--resource",
            "email:external:bob",
        ]

        main([*base, "--format", "jsonl"])
        event = json.loads(capsys.readouterr().out)

        main(base)
        text = capsys.readouterr().out

        assert event["explanation"] in text
        assert event["reason_code"] == "POLICY_SIGNAL_MISSING"


class TestInitTemplateFirstRun:
    """`init` then `compile` is the first thing a new user does.

    The starter template used to declare a policy, a validator and a skill that
    nothing evaluated, so `compile` -- the very next command -- warned about
    the file `init` had just written. The template taught the wrong model at
    the moment the user forms one, and the first output was a complaint about
    the tool's own output.
    """

    def init_and_compile(self, tmp_path: Path, monkeypatch, capsys) -> str:
        monkeypatch.chdir(tmp_path)
        assert cmd_init(argparse.Namespace()) == 0
        capsys.readouterr()
        assert (
            main(
                [
                    "compile",
                    "--manifest",
                    "registry.yaml",
                    "--output",
                    "bundle.json",
                ]
            )
            == 0
        )
        return capsys.readouterr().out

    def test_compiling_the_template_produces_no_unenforced_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        output = self.init_and_compile(tmp_path, monkeypatch, capsys)
        assert "does not enforce" not in output, output

    def test_the_template_demonstrates_an_enforced_policy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        """A first run should show the runtime doing something, not a warning."""
        output = self.init_and_compile(tmp_path, monkeypatch, capsys)
        assert "enforces: refund-needs-approval" in output

    def test_the_template_uses_the_current_syntax(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Otherwise a two-minute evaluation sees the tool as it was two releases ago."""
        monkeypatch.chdir(tmp_path)
        assert cmd_init(argparse.Namespace()) == 0

        agent = (tmp_path / "my_agent.yaml").read_text(encoding="utf-8")
        policy = (tmp_path / "refund-needs-approval.yaml").read_text(encoding="utf-8")

        assert "read_database:reports/*" in agent, "no resource pattern in the template"
        assert "kind: requires_approval" in policy, "no typed policy in the template"

    def test_the_generated_files_pass_the_tools_own_checks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert cmd_init(argparse.Namespace()) == 0
        capsys.readouterr()

        assert main(["validate-agent", "my_agent.yaml"]) == 0
        assert main(["validate-policy", "refund-needs-approval.yaml"]) == 0
        assert main(["lint", "my_agent.yaml"]) == 0

    def test_the_documented_first_decisions_behave_as_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        """The commands the quickstart tells a newcomer to run.

        Exit codes are the contract: 0 allowed, 1 denied. A quickstart whose
        printed commands do not do what the text says is worse than none.
        """
        self.init_and_compile(tmp_path, monkeypatch, capsys)
        base = ["check", "--bundle", "bundle.json", "--agent", "my-agent"]

        assert main([*base, "--action", "read_database"]) == 0
        assert main([*base, "--action", "send_external_email"]) == 1
        assert (
            main([*base, "--action", "read_database", "--resource", "reports/q1"]) == 0
        )
        assert (
            main([*base, "--action", "read_database", "--resource", "customers/pii"])
            == 1
        )
        assert (
            main([*base, "--action", "refund_payment", "--resource", "order/1234"]) == 1
        )
