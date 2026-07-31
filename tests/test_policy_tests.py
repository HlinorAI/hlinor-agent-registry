"""Tests for versioned, deterministic policy verification."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from hlinor_registry import ActionRequest, PolicyChecker
from hlinor_registry.cli import (
    EXIT_ALLOWED,
    EXIT_DENIED,
    EXIT_ERROR,
    cmd_compile,
    cmd_test_policies,
    main,
)
from hlinor_registry.policy_tests import (
    load_policy_test_suite,
    run_policy_tests,
)

FIXED_TIME = "2026-07-27T12:00:00Z"


def write_approval_bundle(tmp_path: Path) -> Path:
    agent = {
        "id": "refund-agent",
        "type": "agent",
        "name": "Refund Agent",
        "department": "support",
        "description": "Issues approved refunds.",
        "skills": [],
        "validators": [],
        "policies": ["refund-requires-approval"],
        "allowed_actions": ["refund_payment:ticket/*"],
        "blocked_actions": [],
        "enforcement_mode": "strict",
    }
    policy = {
        "id": "refund-requires-approval",
        "type": "policy",
        "name": "Refund Requires Approval",
        "description": "Requires a fresh support lead approval.",
        "enforcement": "Enforced by PolicyChecker.",
        "kind": "requires_approval",
        "trigger": ["refund_payment:*"],
        "requires": {
            "approver_role": "support-lead",
            "bind_to_request": True,
            "max_age_seconds": 900,
        },
    }
    manifest = {
        "schema_version": "1.0",
        "policies": [{"path": "agent.yaml"}, {"path": "policy.yaml"}],
        "metadata": {
            "environment": "test",
            "bundle_revision": 1,
            "policy_revision": "policy-tests",
        },
    }
    (tmp_path / "agent.yaml").write_text(
        yaml.safe_dump(agent, sort_keys=False),
        encoding="utf-8",
    )
    (tmp_path / "policy.yaml").write_text(
        yaml.safe_dump(policy, sort_keys=False),
        encoding="utf-8",
    )
    manifest_path = tmp_path / "registry.yaml"
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    bundle_path = tmp_path / "bundle.json"
    assert (
        cmd_compile(
            argparse.Namespace(
                manifest=str(manifest_path),
                output=str(bundle_path),
            )
        )
        == 0
    )
    return bundle_path


def policy_suite(*cases: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "fixed_time": FIXED_TIME,
        "cases": list(cases),
    }


def case(
    case_id: str,
    *,
    signals: dict[str, object],
    result: str,
    reason_code: str,
    matched_policy_ids: list[str],
) -> dict[str, object]:
    return {
        "id": case_id,
        "request": {
            "agent_id": "refund-agent",
            "action": "refund_payment",
            "resource": "ticket/1234",
            "signals": signals,
        },
        "expect": {
            "result": result,
            "reason_code": reason_code,
            "matched_policy_ids": matched_policy_ids,
        },
    }


def write_suite(path: Path, data: dict[str, object]) -> Path:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def fresh_approval() -> dict[str, object]:
    return {
        "approval": {
            "approver_role": "support-lead",
            "granted_for": "refund_payment:ticket/1234",
            "granted_at": "2026-07-27T11:55:00Z",
        }
    }


def test_suite_uses_one_fixed_clock_for_freshness(tmp_path: Path) -> None:
    bundle_path = write_approval_bundle(tmp_path)
    suite_path = write_suite(
        tmp_path / "policy-tests.yaml",
        policy_suite(
            case(
                "fresh-approval",
                signals=fresh_approval(),
                result="allowed",
                reason_code="EXPLICITLY_ALLOWED",
                matched_policy_ids=["refund-requires-approval"],
            ),
            case(
                "stale-approval",
                signals={
                    "approval": {
                        "approver_role": "support-lead",
                        "granted_for": "refund_payment:ticket/1234",
                        "granted_at": "2026-07-27T10:00:00Z",
                    }
                },
                result="denied",
                reason_code="APPROVAL_REQUIRED",
                matched_policy_ids=["refund-requires-approval"],
            ),
        ),
    )
    suite = load_policy_test_suite(suite_path)
    checker = PolicyChecker(str(bundle_path), clock=lambda: suite.fixed_time)

    report = run_policy_tests(checker, suite)

    assert report.passed
    assert report.passed_count == 2
    assert report.failed_count == 0
    assert suite.cases[0].request.request_id == "policy-test:fresh-approval"
    assert suite.cases[0].request.requested_at == "2026-07-27T12:00:00+00:00"


def test_text_command_reports_passes_and_failures(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    bundle_path = write_approval_bundle(tmp_path)
    capsys.readouterr()
    suite_path = write_suite(
        tmp_path / "policy-tests.yaml",
        policy_suite(
            case(
                "wrong-expectation",
                signals=fresh_approval(),
                result="denied",
                reason_code="APPROVAL_REQUIRED",
                matched_policy_ids=["refund-requires-approval"],
            )
        ),
    )

    status = cmd_test_policies(
        argparse.Namespace(
            bundle=str(bundle_path),
            tests=str(suite_path),
            format="text",
        )
    )

    assert status == EXIT_DENIED
    output = capsys.readouterr().out
    assert "[FAIL] wrong-expectation" in output
    assert "result: expected denied, got allowed" in output
    assert "reason_code: expected APPROVAL_REQUIRED, got EXPLICITLY_ALLOWED" in output
    assert "Policy tests: 0 passed, 1 failed, 1 total" in output


def test_json_command_emits_stable_machine_readable_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    bundle_path = write_approval_bundle(tmp_path)
    capsys.readouterr()
    suite_path = write_suite(
        tmp_path / "policy-tests.yaml",
        policy_suite(
            case(
                "missing-approval",
                signals={},
                result="denied",
                reason_code="POLICY_SIGNAL_MISSING",
                matched_policy_ids=["refund-requires-approval"],
            )
        ),
    )

    status = main(
        [
            "test-policies",
            "--bundle",
            str(bundle_path),
            "--tests",
            str(suite_path),
            "--format",
            "json",
        ]
    )

    assert status == EXIT_ALLOWED
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "passed"
    assert report["summary"] == {"total": 1, "passed": 1, "failed": 0}
    assert report["cases"][0]["actual"] == {
        "result": "denied",
        "reason_code": "POLICY_SIGNAL_MISSING",
        "matched_policy_ids": ["refund-requires-approval"],
    }
    assert "decision_id" not in report["cases"][0]
    assert "checked_at" not in report["cases"][0]


def test_invalid_suite_has_distinct_error_exit_and_json_shape(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    bundle_path = write_approval_bundle(tmp_path)
    capsys.readouterr()
    suite_path = write_suite(
        tmp_path / "invalid-tests.yaml",
        {
            "schema_version": "2.0",
            "fixed_time": FIXED_TIME,
            "cases": [],
        },
    )

    status = cmd_test_policies(
        argparse.Namespace(
            bundle=str(bundle_path),
            tests=str(suite_path),
            format="json",
        )
    )

    assert status == EXIT_ERROR
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "invalid"
    assert "Unsupported policy test schema" in report["error"]
    assert EXIT_ALLOWED != EXIT_DENIED != EXIT_ERROR


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda suite: suite.update({"unexpected": True}),
            "contains unknown fields",
        ),
        (
            lambda suite: suite.update({"fixed_time": "2026-07-27T12:00:00"}),
            "must include a timezone",
        ),
        (
            lambda suite: suite["cases"].append(suite["cases"][0]),
            "Duplicate policy test case ID",
        ),
        (
            lambda suite: suite["cases"][0]["expect"].update(
                {"reason_code": "EXPLICITLY_ALLOWED"}
            ),
            "denied result with an allowance reason",
        ),
    ],
)
def test_suite_validation_fails_closed(
    tmp_path: Path,
    mutate,
    message: str,
) -> None:
    suite = policy_suite(
        case(
            "missing-approval",
            signals={},
            result="denied",
            reason_code="POLICY_SIGNAL_MISSING",
            matched_policy_ids=["refund-requires-approval"],
        )
    )
    mutate(suite)
    suite_path = write_suite(tmp_path / "invalid.yaml", suite)

    with pytest.raises((TypeError, ValueError), match=message):
        load_policy_test_suite(suite_path)


def test_policy_checker_rejects_an_invalid_injected_clock(tmp_path: Path) -> None:
    bundle_path = write_approval_bundle(tmp_path)
    request = ActionRequest(
        agent_id="refund-agent",
        action="refund_payment",
        resource="ticket/1234",
        signals=fresh_approval(),
    )

    checker = PolicyChecker(str(bundle_path), clock=lambda: "not-a-datetime")
    with pytest.raises(TypeError, match="must return a datetime"):
        checker.evaluate(request)

    checker = PolicyChecker(
        str(bundle_path),
        # Deliberately naive: the checker must reject a test clock with no zone.
        clock=lambda: datetime(2026, 7, 27, 12, 0, 0),  # noqa: DTZ001
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        checker.evaluate(request)


def test_explicit_utc_clock_allows_the_fresh_request(tmp_path: Path) -> None:
    bundle_path = write_approval_bundle(tmp_path)
    checker = PolicyChecker(
        str(bundle_path),
        clock=lambda: datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc),
    )

    decision = checker.evaluate(
        ActionRequest(
            agent_id="refund-agent",
            action="refund_payment",
            resource="ticket/1234",
            signals=fresh_approval(),
        )
    )

    assert decision.allowed
