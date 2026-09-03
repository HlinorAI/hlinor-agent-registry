"""Fail-closed task outcome and acceptance evaluation.

This module is a portable local gate. It does not persist tasks, grant
authority, collect telemetry, or attest a deployment. It only decides whether
one task outcome is supported by its declared acceptance criteria and verified
evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any


class OutcomeGateError(ValueError):
    """Raised when an outcome gate cannot evaluate an invalid contract."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class OutcomeStatus(str, Enum):
    """Terminal status supported by the acceptance gate."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    PARTIAL = "PARTIAL"


class ExecutionState(str, Enum):
    """Observed execution state supplied by the runtime adapter."""

    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    PARTIAL = "partial"
    TIMED_OUT = "timed_out"
    INTERRUPTED = "interrupted"


class OutcomeReason(str, Enum):
    """Machine-readable reason for the terminal outcome."""

    ACCEPTANCE_VERIFIED = "ACCEPTANCE_VERIFIED"
    ACCEPTANCE_EVIDENCE_MISSING = "ACCEPTANCE_EVIDENCE_MISSING"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    EXECUTION_PARTIAL = "EXECUTION_PARTIAL"


@dataclass(frozen=True, slots=True)
class AcceptanceCriterion:
    """One mandatory criterion and the evidence needed to verify it."""

    criterion_id: str
    required_evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.criterion_id, "criterion_id")
        if not self.required_evidence:
            raise OutcomeGateError(
                "ACCEPTANCE_CONTRACT_INVALID",
                "every criterion must require at least one evidence reference",
            )
        for reference in self.required_evidence:
            _require_text(reference, "required_evidence")
        if len(set(self.required_evidence)) != len(self.required_evidence):
            raise OutcomeGateError(
                "ACCEPTANCE_CONTRACT_INVALID",
                "required evidence references must be unique per criterion",
            )


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Evidence supplied by an adapter and explicitly marked as verified."""

    evidence_id: str
    reference: str
    verified: bool

    def __post_init__(self) -> None:
        _require_text(self.evidence_id, "evidence_id")
        _require_text(self.reference, "reference")
        if not isinstance(self.verified, bool):
            raise OutcomeGateError(
                "EVIDENCE_INVALID", "verified must be a boolean"
            )


@dataclass(frozen=True, slots=True)
class TaskOutcome:
    """Immutable, receipt-friendly result of one acceptance evaluation."""

    task_id: str
    status: OutcomeStatus
    execution_state: ExecutionState
    acceptance_criteria: tuple[AcceptanceCriterion, ...]
    criterion_ids: tuple[str, ...]
    satisfied_criterion_ids: tuple[str, ...]
    verified_evidence_refs: tuple[str, ...]
    missing_evidence_refs: tuple[str, ...]
    reason: OutcomeReason

    @property
    def successful(self) -> bool:
        """Return true only for a fully evidenced successful outcome."""
        return self.status is OutcomeStatus.SUCCESS

    def as_receipt_fields(self) -> dict[str, Any]:
        """Return fields that can be embedded in a lifecycle receipt."""
        return {
            "outcome_status": self.status.value,
            "execution_state": self.execution_state.value,
            "acceptance_criteria": [
                {
                    "criterion_id": criterion.criterion_id,
                    "required_evidence": list(criterion.required_evidence),
                }
                for criterion in self.acceptance_criteria
            ],
            "satisfied_criterion_ids": list(self.satisfied_criterion_ids),
            "verified_evidence_refs": list(self.verified_evidence_refs),
            "missing_evidence_refs": list(self.missing_evidence_refs),
            "outcome_reason": self.reason.value,
        }


class OutcomeAcceptanceGate:
    """Evaluate one task without allowing caller claims to create success."""

    def __init__(
        self,
        *,
        task_id: str,
        criteria: Sequence[AcceptanceCriterion],
    ) -> None:
        _require_text(task_id, "task_id")
        if not criteria:
            raise OutcomeGateError(
                "ACCEPTANCE_CONTRACT_INVALID",
                "at least one acceptance criterion is required",
            )
        frozen_criteria = tuple(criteria)
        if any(not isinstance(item, AcceptanceCriterion) for item in frozen_criteria):
            raise OutcomeGateError(
                "ACCEPTANCE_CONTRACT_INVALID",
                "criteria must contain AcceptanceCriterion objects",
            )
        criterion_ids = [item.criterion_id for item in frozen_criteria]
        if len(set(criterion_ids)) != len(criterion_ids):
            raise OutcomeGateError(
                "ACCEPTANCE_CONTRACT_INVALID",
                "criterion IDs must be unique",
            )
        self.task_id = task_id
        self.criteria = frozen_criteria

    def evaluate(
        self,
        evidence: Mapping[str, EvidenceRecord],
        *,
        execution_state: ExecutionState | str,
    ) -> TaskOutcome:
        """Return a terminal outcome from observed state and verified evidence.

        Evidence is keyed by its declared reference. A caller cannot turn an
        unverified or missing record into success by merely claiming that the
        task completed.
        """
        state = _coerce_execution_state(execution_state)
        if not isinstance(evidence, Mapping):
            raise OutcomeGateError("EVIDENCE_INVALID", "evidence must be a mapping")
        for reference, record in evidence.items():
            _require_text(reference, "evidence reference")
            if not isinstance(record, EvidenceRecord):
                raise OutcomeGateError(
                    "EVIDENCE_INVALID",
                    "evidence values must be EvidenceRecord objects",
                )
            if record.reference != reference:
                raise OutcomeGateError(
                    "EVIDENCE_INVALID",
                    f"evidence key does not match record reference: {reference}",
                )

        satisfied: list[str] = []
        verified_refs: list[str] = []
        missing_refs: list[str] = []
        for criterion in self.criteria:
            criterion_missing = [
                reference
                for reference in criterion.required_evidence
                if reference not in evidence or not evidence[reference].verified
            ]
            if criterion_missing:
                missing_refs.extend(criterion_missing)
            else:
                satisfied.append(criterion.criterion_id)
                verified_refs.extend(criterion.required_evidence)

        missing_refs = list(dict.fromkeys(missing_refs))
        verified_refs = list(dict.fromkeys(verified_refs))
        status, reason = _status_for(state, bool(missing_refs))

        return TaskOutcome(
            task_id=self.task_id,
            status=status,
            execution_state=state,
            acceptance_criteria=self.criteria,
            criterion_ids=tuple(item.criterion_id for item in self.criteria),
            satisfied_criterion_ids=tuple(satisfied),
            verified_evidence_refs=tuple(verified_refs),
            missing_evidence_refs=tuple(missing_refs),
            reason=reason,
        )


def _require_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise OutcomeGateError(
            "OUTCOME_FIELD_INVALID", f"{field} must be a non-empty trimmed string"
        )


def _coerce_execution_state(value: ExecutionState | str) -> ExecutionState:
    try:
        return value if isinstance(value, ExecutionState) else ExecutionState(value)
    except (TypeError, ValueError) as exc:
        raise OutcomeGateError(
            "EXECUTION_STATE_INVALID", f"unsupported execution state: {value!r}"
        ) from exc


def _status_for(
    state: ExecutionState, evidence_missing: bool
) -> tuple[OutcomeStatus, OutcomeReason]:
    if state is ExecutionState.AWAITING_APPROVAL:
        return OutcomeStatus.AWAITING_APPROVAL, OutcomeReason.APPROVAL_PENDING
    if state in {
        ExecutionState.FAILED,
        ExecutionState.TIMED_OUT,
        ExecutionState.INTERRUPTED,
    }:
        return OutcomeStatus.FAILED, OutcomeReason.EXECUTION_FAILED
    if state is ExecutionState.BLOCKED:
        return OutcomeStatus.BLOCKED, OutcomeReason.EXECUTION_BLOCKED
    if state is ExecutionState.PARTIAL:
        return OutcomeStatus.PARTIAL, OutcomeReason.EXECUTION_PARTIAL
    if evidence_missing:
        return OutcomeStatus.BLOCKED, OutcomeReason.ACCEPTANCE_EVIDENCE_MISSING
    return OutcomeStatus.SUCCESS, OutcomeReason.ACCEPTANCE_VERIFIED


__all__ = [
    "AcceptanceCriterion",
    "EvidenceRecord",
    "ExecutionState",
    "OutcomeAcceptanceGate",
    "OutcomeGateError",
    "OutcomeReason",
    "OutcomeStatus",
    "TaskOutcome",
]
