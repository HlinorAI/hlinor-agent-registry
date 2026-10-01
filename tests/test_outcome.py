"""Tests for the fail-closed task outcome and acceptance gate."""

import pytest

from hlinor_registry import (
    AcceptanceCriterion,
    EvidenceRecord,
    ExecutionState,
    OutcomeAcceptanceGate,
    OutcomeGateError,
    OutcomeReason,
    OutcomeStatus,
)


def gate() -> OutcomeAcceptanceGate:
    return OutcomeAcceptanceGate(
        task_id="task-1",
        criteria=(
            AcceptanceCriterion(
                criterion_id="checks_passed",
                required_evidence=("checks.json",),
            ),
            AcceptanceCriterion(
                criterion_id="artifact_verified",
                required_evidence=("artifact.sha256",),
            ),
        ),
    )


def test_completed_task_is_successful_only_with_verified_evidence():
    outcome = gate().evaluate(
        {
            "checks.json": EvidenceRecord("check-result", "checks.json", True),
            "artifact.sha256": EvidenceRecord(
                "artifact-digest", "artifact.sha256", True
            ),
        },
        execution_state=ExecutionState.COMPLETED,
    )

    assert outcome.status is OutcomeStatus.SUCCESS
    assert outcome.successful
    assert outcome.reason is OutcomeReason.ACCEPTANCE_VERIFIED
    assert outcome.missing_evidence_refs == ()
    assert outcome.as_receipt_fields()["outcome_status"] == "SUCCESS"


def test_completed_task_without_evidence_is_blocked_not_successful():
    outcome = gate().evaluate({}, execution_state="completed")

    assert outcome.status is OutcomeStatus.BLOCKED
    assert not outcome.successful
    assert outcome.reason is OutcomeReason.ACCEPTANCE_EVIDENCE_MISSING
    assert outcome.missing_evidence_refs == ("checks.json", "artifact.sha256")


@pytest.mark.parametrize(
    ("execution_state", "expected_status", "expected_reason"),
    [
        ("failed", OutcomeStatus.FAILED, OutcomeReason.EXECUTION_FAILED),
        ("timed_out", OutcomeStatus.FAILED, OutcomeReason.EXECUTION_FAILED),
        ("interrupted", OutcomeStatus.FAILED, OutcomeReason.EXECUTION_FAILED),
        ("blocked", OutcomeStatus.BLOCKED, OutcomeReason.EXECUTION_BLOCKED),
        (
            "awaiting_approval",
            OutcomeStatus.AWAITING_APPROVAL,
            OutcomeReason.APPROVAL_PENDING,
        ),
        ("partial", OutcomeStatus.PARTIAL, OutcomeReason.EXECUTION_PARTIAL),
    ],
)
def test_non_success_execution_states_never_become_success(
    execution_state, expected_status, expected_reason
):
    outcome = gate().evaluate(
        {
            "checks.json": EvidenceRecord("check-result", "checks.json", True),
            "artifact.sha256": EvidenceRecord(
                "artifact-digest", "artifact.sha256", True
            ),
        },
        execution_state=execution_state,
    )

    assert outcome.status is expected_status
    assert outcome.reason is expected_reason
    assert not outcome.successful


def test_criteria_require_evidence_and_unique_ids():
    with pytest.raises(OutcomeGateError, match="at least one evidence reference"):
        AcceptanceCriterion("no-proof", ())

    with pytest.raises(OutcomeGateError, match="criterion IDs must be unique"):
        OutcomeAcceptanceGate(
            task_id="task-1",
            criteria=(
                AcceptanceCriterion("same", ("evidence-1",)),
                AcceptanceCriterion("same", ("evidence-2",)),
            ),
        )


def test_evidence_key_must_match_its_declared_reference():
    with pytest.raises(OutcomeGateError, match="does not match"):
        gate().evaluate(
            {"check-result": EvidenceRecord("check-result", "other-ref", True)},
            execution_state="completed",
        )


def test_invalid_execution_state_is_fail_closed():
    with pytest.raises(OutcomeGateError, match="unsupported execution state"):
        gate().evaluate({}, execution_state="running")
