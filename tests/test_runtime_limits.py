"""Security tests for shared runtime admission limits."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from test_runtime_binding import Checker, contract

from hlinor_registry import (
    KillSwitchActiveError,
    RateLimitExceededError,
    RuntimeLimitError,
    SQLiteRuntimeBudget,
    bind_tool,
)


def test_sqlite_runtime_budget_enforces_concurrency_across_workers(tmp_path) -> None:
    path = tmp_path / "runtime-limits.sqlite3"

    def acquire(index: int) -> str:
        try:
            SQLiteRuntimeBudget(path).acquire(
                "tenant-1:records.read",
                f"lease-{index}",
                max_concurrency=1,
                rate_limit=None,
                rate_window_seconds=None,
                lease_ttl_seconds=60,
            )
        except RuntimeLimitError as exc:
            return type(exc).__name__
        return "acquired"

    with ThreadPoolExecutor(max_workers=6) as executor:
        outcomes = list(executor.map(acquire, range(6)))
    assert outcomes.count("acquired") == 1
    assert outcomes.count("ConcurrencyLimitError") == 5

    guard = SQLiteRuntimeBudget(path)
    for index in range(6):
        guard.release(f"lease-{index}")
    guard.acquire(
        "tenant-1:records.read",
        "lease-after-release",
        max_concurrency=1,
        rate_limit=None,
        rate_window_seconds=None,
        lease_ttl_seconds=60,
    )


def test_sqlite_runtime_budget_keeps_rate_events_after_lease_release(tmp_path) -> None:
    guard = SQLiteRuntimeBudget(tmp_path / "runtime-limits.sqlite3")
    guard.acquire(
        "tenant-1:records.read",
        "lease-1",
        max_concurrency=1,
        rate_limit=1,
        rate_window_seconds=60,
        lease_ttl_seconds=60,
    )
    guard.release("lease-1")
    with pytest.raises(RateLimitExceededError, match="RATE_LIMIT_EXCEEDED"):
        guard.acquire(
            "tenant-1:records.read",
            "lease-2",
            max_concurrency=1,
            rate_limit=1,
            rate_window_seconds=60,
            lease_ttl_seconds=60,
        )


def test_kill_switch_is_shared_across_runtime_workers(tmp_path) -> None:
    path = tmp_path / "runtime-limits.sqlite3"
    controller = SQLiteRuntimeBudget(path)
    worker = SQLiteRuntimeBudget(path)
    controller.activate_kill_switch("synthetic incident")
    assert worker.is_kill_switch_active() is True
    with pytest.raises(KillSwitchActiveError, match="KILL_SWITCH_ACTIVE"):
        worker.acquire(
            "tenant-1:records.read",
            "lease-1",
            max_concurrency=1,
            rate_limit=None,
            rate_window_seconds=None,
            lease_ttl_seconds=60,
        )
    controller.deactivate_kill_switch()
    worker.acquire(
        "tenant-1:records.read",
        "lease-2",
        max_concurrency=1,
        rate_limit=None,
        rate_window_seconds=None,
        lease_ttl_seconds=60,
    )


def test_bound_tool_releases_runtime_lease_after_success_and_failure(tmp_path) -> None:
    guard = SQLiteRuntimeBudget(tmp_path / "runtime-limits.sqlite3")
    attempts: list[str] = []

    def read_record(*, record_id: str) -> dict[str, str]:
        attempts.append(record_id)
        if len(attempts) == 1:
            raise RuntimeError("synthetic tool failure")
        return {"record_id": record_id}

    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=read_record,
    )
    with pytest.raises(RuntimeError, match="synthetic tool failure"):
        bound.invoke(
            Checker(),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            runtime_budget=guard,
            budget_scope="tenant-1:records.read",
            max_concurrency=1,
            kwargs={"record_id": "123"},
        )
    assert bound.invoke(
        Checker(),  # type: ignore[arg-type]
        agent_id="reader",
        resource="record/123",
        runtime_budget=guard,
        budget_scope="tenant-1:records.read",
        max_concurrency=1,
        kwargs={"record_id": "123"},
    ) == {"record_id": "123"}
    assert attempts == ["123", "123"]


def test_bound_tool_checks_kill_switch_before_dispatch(tmp_path) -> None:
    guard = SQLiteRuntimeBudget(tmp_path / "runtime-limits.sqlite3")
    calls: list[str] = []
    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=lambda *, record_id: calls.append(record_id),
    )
    guard.activate_kill_switch("synthetic incident")
    with pytest.raises(KillSwitchActiveError, match="KILL_SWITCH_ACTIVE"):
        bound.invoke(
            Checker(),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            runtime_budget=guard,
            budget_scope="tenant-1:records.read",
            max_concurrency=1,
            kwargs={"record_id": "123"},
        )
    assert calls == []
