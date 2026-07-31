"""Deterministic, versioned policy-test suites for compiled bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from ._limits import MAX_SOURCE_BYTES, read_text_capped
from .action_request import ActionRequest
from .enums import DecisionResult, ReasonCode
from .policy_checker import PolicyChecker

POLICY_TEST_SCHEMA_VERSION = "1.0"

_REQUEST_FIELDS = {
    "agent_id",
    "action",
    "actor_id",
    "tool_id",
    "resource",
    "arguments_digest",
    "attributes",
    "signals",
    "approval_id",
    "session_id",
    "tenant_id",
    "environment",
}
_OPTIONAL_STRING_REQUEST_FIELDS = _REQUEST_FIELDS - {
    "agent_id",
    "action",
    "attributes",
    "signals",
}
_ALLOWED_REASON_CODES = {
    ReasonCode.EXPLICITLY_ALLOWED,
    ReasonCode.ALLOWED_NOT_BLOCKLISTED,
}


@dataclass(frozen=True)
class PolicyTestExpectation:
    """The stable decision fields one test case expects."""

    result: DecisionResult
    reason_code: ReasonCode
    matched_policy_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": str(self.result),
            "reason_code": str(self.reason_code),
            "matched_policy_ids": list(self.matched_policy_ids),
        }


@dataclass(frozen=True)
class PolicyTestCase:
    """One deterministic request and its expected policy outcome."""

    case_id: str
    request: ActionRequest
    expected: PolicyTestExpectation


@dataclass(frozen=True)
class PolicyTestSuite:
    """A versioned collection evaluated against one fixed UTC instant."""

    schema_version: str
    fixed_time: datetime
    cases: tuple[PolicyTestCase, ...]


@dataclass(frozen=True)
class PolicyTestResult:
    """The comparison result for one case, excluding volatile audit fields."""

    case_id: str
    passed: bool
    expected: PolicyTestExpectation
    actual: PolicyTestExpectation
    mismatches: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.case_id,
            "passed": self.passed,
            "expected": self.expected.to_dict(),
            "actual": self.actual.to_dict(),
            "mismatches": list(self.mismatches),
        }


@dataclass(frozen=True)
class PolicyTestReport:
    """CI-friendly aggregate report for a policy-test suite."""

    schema_version: str
    fixed_time: str
    bundle_digest: str
    policy_revision: str
    results: tuple[PolicyTestResult, ...]

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)

    @property
    def passed_count(self) -> int:
        return sum(result.passed for result in self.results)

    @property
    def failed_count(self) -> int:
        return len(self.results) - self.passed_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "fixed_time": self.fixed_time,
            "bundle_digest": self.bundle_digest,
            "policy_revision": self.policy_revision,
            "status": "passed" if self.passed else "failed",
            "summary": {
                "total": len(self.results),
                "passed": self.passed_count,
                "failed": self.failed_count,
            },
            "cases": [result.to_dict() for result in self.results],
        }


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{location} must be an object")
    for key in value:
        if not isinstance(key, str):
            raise TypeError(f"{location} keys must be strings")
    return value


def _reject_unknown_fields(
    value: dict[str, Any],
    allowed: set[str],
    location: str,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{location} contains unknown fields: {unknown}")


def _required_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{location} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{location} cannot contain outer whitespace")
    return value


def _fixed_time(value: Any) -> datetime:
    text = _required_string(value, "fixed_time")
    normalized = f"{text[:-1]}+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError("fixed_time must be a valid ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError("fixed_time must include a timezone")
    return parsed


def _expected(value: Any, location: str) -> PolicyTestExpectation:
    data = _mapping(value, location)
    _reject_unknown_fields(
        data,
        {"result", "reason_code", "matched_policy_ids"},
        location,
    )
    try:
        result = DecisionResult(
            _required_string(data.get("result"), f"{location}.result")
        )
    except ValueError as error:
        raise ValueError(f"{location}.result must be 'allowed' or 'denied'") from error
    try:
        reason_code = ReasonCode(
            _required_string(data.get("reason_code"), f"{location}.reason_code")
        )
    except ValueError as error:
        raise ValueError(f"{location}.reason_code is not supported") from error

    raw_policy_ids = data.get("matched_policy_ids")
    if not isinstance(raw_policy_ids, list):
        raise TypeError(f"{location}.matched_policy_ids must be a list")
    policy_ids = tuple(
        _required_string(policy_id, f"{location}.matched_policy_ids[{index}]")
        for index, policy_id in enumerate(raw_policy_ids)
    )
    if len(set(policy_ids)) != len(policy_ids):
        raise ValueError(f"{location}.matched_policy_ids contains duplicates")

    if result is DecisionResult.ALLOWED and reason_code not in _ALLOWED_REASON_CODES:
        raise ValueError(f"{location} pairs an allowed result with a denial reason")
    if result is DecisionResult.DENIED and reason_code in _ALLOWED_REASON_CODES:
        raise ValueError(f"{location} pairs a denied result with an allowance reason")

    return PolicyTestExpectation(result, reason_code, policy_ids)


def _request(
    value: Any,
    *,
    case_id: str,
    fixed_time: datetime,
    location: str,
) -> ActionRequest:
    data = _mapping(value, location)
    _reject_unknown_fields(data, _REQUEST_FIELDS, location)

    for field_name in sorted(_OPTIONAL_STRING_REQUEST_FIELDS):
        if field_name in data and data[field_name] is not None:
            _required_string(data[field_name], f"{location}.{field_name}")
    for field_name in ("attributes", "signals"):
        field_value = data.get(field_name, {})
        if not isinstance(field_value, dict):
            raise TypeError(f"{location}.{field_name} must be an object")

    return ActionRequest(
        request_id=f"policy-test:{case_id}",
        agent_id=_required_string(data.get("agent_id"), f"{location}.agent_id"),
        action=_required_string(data.get("action"), f"{location}.action"),
        actor_id=data.get("actor_id"),
        tool_id=data.get("tool_id"),
        resource=data.get("resource"),
        arguments_digest=data.get("arguments_digest"),
        attributes=data.get("attributes", {}),
        signals=data.get("signals", {}),
        approval_id=data.get("approval_id"),
        session_id=data.get("session_id"),
        tenant_id=data.get("tenant_id"),
        environment=data.get("environment"),
        requested_at=fixed_time.isoformat(),
    )


def load_policy_test_suite(path: str | Path) -> PolicyTestSuite:
    """Load and strictly validate one policy-test YAML document."""
    suite_path = Path(path)
    raw = yaml.safe_load(
        read_text_capped(suite_path, MAX_SOURCE_BYTES, "Policy test suite")
    )
    data = _mapping(raw, "policy test suite")
    _reject_unknown_fields(
        data,
        {"schema_version", "fixed_time", "cases"},
        "policy test suite",
    )

    schema_version = _required_string(
        data.get("schema_version"),
        "schema_version",
    )
    major = schema_version.split(".", maxsplit=1)[0]
    supported_major = POLICY_TEST_SCHEMA_VERSION.split(".", maxsplit=1)[0]
    if not major.isdigit() or major != supported_major:
        raise ValueError(f"Unsupported policy test schema: {schema_version}")

    fixed_time = _fixed_time(data.get("fixed_time"))
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("cases must be a non-empty list")

    cases: list[PolicyTestCase] = []
    seen_ids: set[str] = set()
    for index, raw_case in enumerate(raw_cases):
        location = f"cases[{index}]"
        case_data = _mapping(raw_case, location)
        _reject_unknown_fields(case_data, {"id", "request", "expect"}, location)
        case_id = _required_string(case_data.get("id"), f"{location}.id")
        if case_id in seen_ids:
            raise ValueError(f"Duplicate policy test case ID: {case_id}")
        seen_ids.add(case_id)
        cases.append(
            PolicyTestCase(
                case_id=case_id,
                request=_request(
                    case_data.get("request"),
                    case_id=case_id,
                    fixed_time=fixed_time,
                    location=f"{location}.request",
                ),
                expected=_expected(case_data.get("expect"), f"{location}.expect"),
            )
        )

    return PolicyTestSuite(schema_version, fixed_time, tuple(cases))


def run_policy_tests(
    checker: PolicyChecker,
    suite: PolicyTestSuite,
) -> PolicyTestReport:
    """Evaluate all cases and compare only stable, governance-relevant fields."""
    results: list[PolicyTestResult] = []
    for case in suite.cases:
        decision = checker.evaluate(case.request)
        actual = PolicyTestExpectation(
            decision.result,
            decision.reason_code,
            decision.matched_policy_ids,
        )
        mismatches: list[str] = []
        if actual.result is not case.expected.result:
            mismatches.append(
                f"result: expected {case.expected.result}, got {actual.result}"
            )
        if actual.reason_code is not case.expected.reason_code:
            mismatches.append(
                "reason_code: expected "
                f"{case.expected.reason_code}, got {actual.reason_code}"
            )
        if actual.matched_policy_ids != case.expected.matched_policy_ids:
            mismatches.append(
                "matched_policy_ids: expected "
                f"{list(case.expected.matched_policy_ids)}, "
                f"got {list(actual.matched_policy_ids)}"
            )
        results.append(
            PolicyTestResult(
                case_id=case.case_id,
                passed=not mismatches,
                expected=case.expected,
                actual=actual,
                mismatches=tuple(mismatches),
            )
        )
    return PolicyTestReport(
        suite.schema_version,
        suite.fixed_time.isoformat(),
        checker.bundle_digest,
        checker.policy_revision,
        tuple(results),
    )
