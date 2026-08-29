"""Security tests for durable circuit-breaker state."""

from __future__ import annotations

import pytest
from test_runtime_binding import Checker, contract

from hlinor_registry import (
    CircuitBreakerError,
    CircuitOpenError,
    SQLiteCircuitBreaker,
    bind_tool,
)


def test_sqlite_breaker_persists_open_state_and_allows_one_probe(tmp_path) -> None:
    path = tmp_path / "breaker.sqlite3"
    first = SQLiteCircuitBreaker(path)
    second = SQLiteCircuitBreaker(path)
    fingerprint = "reader:records.read:record/123"

    assert first.before_dispatch(fingerprint, 2).state == "closed"
    assert first.record_failure(fingerprint, 2).current_count == 1
    assert second.before_dispatch(fingerprint, 2).state == "closed"
    opened = second.record_failure(fingerprint, 2)
    assert opened.state == "open"

    with pytest.raises(CircuitOpenError):
        first.before_dispatch(fingerprint, 2)
    with pytest.raises(CircuitOpenError):
        SQLiteCircuitBreaker(path).before_dispatch(fingerprint, 2)
    assert first.record_success(fingerprint).state == "open"

    probe_state = first.start_probe(fingerprint)
    assert probe_state.state == "half_open"
    assert second.before_dispatch(fingerprint, 2).next_action == "retry_probe"
    with pytest.raises(CircuitOpenError):
        first.before_dispatch(fingerprint, 2)
    assert second.record_success(fingerprint).state == "closed"
    assert first.before_dispatch(fingerprint, 2).current_count == 0


def test_breaker_rejects_threshold_changes(tmp_path) -> None:
    breaker = SQLiteCircuitBreaker(tmp_path / "breaker.sqlite3")
    breaker.before_dispatch("fingerprint", 2)
    with pytest.raises(CircuitBreakerError, match="BREAKER_THRESHOLD_MISMATCH"):
        breaker.before_dispatch("fingerprint", 3)


def test_bound_tool_opens_breaker_after_real_tool_failure(tmp_path) -> None:
    calls: list[str] = []

    def failing_tool(*, record_id: str) -> str:
        calls.append(record_id)
        raise RuntimeError("synthetic dependency failure")

    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=failing_tool,
    )
    breaker = SQLiteCircuitBreaker(tmp_path / "breaker.sqlite3")

    with pytest.raises(RuntimeError, match="synthetic dependency failure"):
        bound.invoke(
            Checker(),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            circuit_breaker=breaker,
            failure_threshold=1,
            kwargs={"record_id": "123"},
        )
    with pytest.raises(CircuitOpenError, match="CIRCUIT_OPEN"):
        bound.invoke(
            Checker(),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            circuit_breaker=SQLiteCircuitBreaker(tmp_path / "breaker.sqlite3"),
            failure_threshold=1,
            kwargs={"record_id": "123"},
        )
    assert calls == ["123"]
