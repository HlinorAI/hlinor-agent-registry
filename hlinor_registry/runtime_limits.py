"""Shared runtime limits for fail-closed dispatch boundaries.

The SQLite implementation makes each admission decision visible to all workers
and restarts. It is a small coordination primitive, not a distributed control
plane: activation and deactivation of the kill switch must be protected by the
deployment that owns this store.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


class RuntimeLimitError(RuntimeError):
    """Raised when runtime admission cannot safely continue."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class KillSwitchActiveError(RuntimeLimitError):
    """Raised when the shared kill switch is active."""


class RateLimitExceededError(RuntimeLimitError):
    """Raised when the configured event window is exhausted."""


class ConcurrencyLimitError(RuntimeLimitError):
    """Raised when no concurrency lease is available."""


@dataclass(frozen=True, slots=True)
class RuntimeLimitSnapshot:
    """Admission state returned after an atomic lease reservation."""

    scope: str
    lease_id: str
    active_leases: int
    rate_events: int
    kill_switch_active: bool


class RuntimeBudgetGuard(Protocol):
    """Admission and release contract for a governed dispatch."""

    def acquire(
        self,
        scope: str,
        lease_id: str,
        *,
        max_concurrency: int | None,
        rate_limit: int | None,
        rate_window_seconds: int | None,
        lease_ttl_seconds: int,
    ) -> RuntimeLimitSnapshot:
        """Atomically check the kill switch and reserve one dispatch lease."""

    def release(self, lease_id: str) -> None:
        """Release a previously reserved lease; repeated release is safe."""


def _validate_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise RuntimeLimitError(
            "RUNTIME_LIMIT_INPUT_INVALID",
            f"{field} must be a non-empty string",
        )


def _validate_positive(value: int | None, field: str) -> None:
    if value is not None and (
        not isinstance(value, int) or isinstance(value, bool) or value < 1
    ):
        raise RuntimeLimitError(
            "RUNTIME_LIMIT_CONFIG_INVALID",
            f"{field} must be a positive integer when set",
        )


class SQLiteRuntimeBudget:
    """Cross-worker rate, concurrency, and kill-switch state in SQLite."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS runtime_kill_switch ("
                    "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                    "active INTEGER NOT NULL CHECK (active IN (0, 1)), "
                    "reason TEXT NOT NULL, updated_at REAL NOT NULL)"
                )
                connection.execute(
                    "INSERT OR IGNORE INTO runtime_kill_switch "
                    "(singleton, active, reason, updated_at) VALUES (1, 0, '', 0)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS runtime_leases ("
                    "lease_id TEXT PRIMARY KEY, scope TEXT NOT NULL, "
                    "expires_at REAL NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS runtime_rate_events ("
                    "event_id TEXT PRIMARY KEY, scope TEXT NOT NULL, "
                    "occurred_at REAL NOT NULL)"
                )
        except sqlite3.Error as exc:
            raise RuntimeLimitError(
                "RUNTIME_LIMIT_STORE_UNAVAILABLE",
                "unable to initialize runtime limit store",
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def acquire(
        self,
        scope: str,
        lease_id: str,
        *,
        max_concurrency: int | None,
        rate_limit: int | None,
        rate_window_seconds: int | None,
        lease_ttl_seconds: int,
    ) -> RuntimeLimitSnapshot:
        _validate_text(scope, "scope")
        _validate_text(lease_id, "lease_id")
        _validate_positive(max_concurrency, "max_concurrency")
        _validate_positive(rate_limit, "rate_limit")
        _validate_positive(rate_window_seconds, "rate_window_seconds")
        _validate_positive(lease_ttl_seconds, "lease_ttl_seconds")
        if rate_limit is not None and rate_window_seconds is None:
            raise RuntimeLimitError(
                "RUNTIME_LIMIT_CONFIG_INVALID",
                "rate_window_seconds is required with rate_limit",
            )
        if rate_limit is None and rate_window_seconds is not None:
            raise RuntimeLimitError(
                "RUNTIME_LIMIT_CONFIG_INVALID",
                "rate_limit is required with rate_window_seconds",
            )
        if max_concurrency is None and rate_limit is None:
            raise RuntimeLimitError(
                "RUNTIME_LIMIT_CONFIG_INVALID",
                "at least one runtime limit is required",
            )
        now = datetime.now(timezone.utc).timestamp()
        expires_at = now + lease_ttl_seconds
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                switch = connection.execute(
                    "SELECT active FROM runtime_kill_switch WHERE singleton = 1"
                ).fetchone()
                if switch is None:
                    connection.execute("ROLLBACK")
                    raise RuntimeLimitError(
                        "RUNTIME_LIMIT_STORE_INVALID",
                        "kill-switch state is missing",
                    )
                if bool(switch[0]):
                    connection.execute("ROLLBACK")
                    raise KillSwitchActiveError(
                        "KILL_SWITCH_ACTIVE",
                        "runtime kill switch is active",
                    )
                connection.execute(
                    "DELETE FROM runtime_leases WHERE expires_at <= ?",
                    (now,),
                )
                if rate_window_seconds is not None:
                    connection.execute(
                        "DELETE FROM runtime_rate_events WHERE occurred_at < ?",
                        (now - rate_window_seconds,),
                    )
                active_row = connection.execute(
                    "SELECT COUNT(*) FROM runtime_leases WHERE scope = ?",
                    (scope,),
                ).fetchone()
                assert active_row is not None
                active_leases = int(active_row[0])
                if max_concurrency is not None and active_leases >= max_concurrency:
                    connection.execute("ROLLBACK")
                    raise ConcurrencyLimitError(
                        "CONCURRENCY_LIMIT_EXCEEDED",
                        "runtime concurrency limit was reached",
                    )
                rate_events = 0
                if rate_window_seconds is not None:
                    rate_row = connection.execute(
                        "SELECT COUNT(*) FROM runtime_rate_events WHERE scope = ?",
                        (scope,),
                    ).fetchone()
                    assert rate_row is not None
                    rate_events = int(rate_row[0])
                    assert rate_limit is not None
                    if rate_events >= rate_limit:
                        connection.execute("ROLLBACK")
                        raise RateLimitExceededError(
                            "RATE_LIMIT_EXCEEDED",
                            "runtime rate limit was reached",
                        )
                try:
                    connection.execute(
                        "INSERT INTO runtime_leases(lease_id, scope, expires_at) "
                        "VALUES (?, ?, ?)",
                        (lease_id, scope, expires_at),
                    )
                except sqlite3.IntegrityError as exc:
                    connection.execute("ROLLBACK")
                    raise RuntimeLimitError(
                        "RUNTIME_LEASE_CONFLICT",
                        "lease_id is already in use",
                    ) from exc
                connection.execute(
                    "INSERT INTO runtime_rate_events(event_id, scope, occurred_at) "
                    "VALUES (?, ?, ?)",
                    (str(uuid.uuid4()), scope, now),
                )
                connection.execute("COMMIT")
                return RuntimeLimitSnapshot(
                    scope=scope,
                    lease_id=lease_id,
                    active_leases=active_leases + 1,
                    rate_events=rate_events + 1,
                    kill_switch_active=False,
                )
        except RuntimeLimitError:
            raise
        except sqlite3.Error as exc:
            raise RuntimeLimitError(
                "RUNTIME_LIMIT_STORE_UNAVAILABLE",
                "unable to reserve runtime limit lease",
            ) from exc

    def release(self, lease_id: str) -> None:
        _validate_text(lease_id, "lease_id")
        try:
            with self._connect() as connection:
                connection.execute(
                    "DELETE FROM runtime_leases WHERE lease_id = ?",
                    (lease_id,),
                )
        except sqlite3.Error as exc:
            raise RuntimeLimitError(
                "RUNTIME_LIMIT_STORE_UNAVAILABLE",
                "unable to release runtime limit lease",
            ) from exc

    def activate_kill_switch(self, reason: str) -> None:
        _validate_text(reason, "reason")
        self._set_kill_switch(True, reason)

    def deactivate_kill_switch(self) -> None:
        self._set_kill_switch(False, "")

    def is_kill_switch_active(self) -> bool:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT active FROM runtime_kill_switch WHERE singleton = 1"
                ).fetchone()
                if row is None:
                    raise RuntimeLimitError(
                        "RUNTIME_LIMIT_STORE_INVALID",
                        "kill-switch state is missing",
                    )
                return bool(row[0])
        except RuntimeLimitError:
            raise
        except sqlite3.Error as exc:
            raise RuntimeLimitError(
                "RUNTIME_LIMIT_STORE_UNAVAILABLE",
                "unable to read kill-switch state",
            ) from exc

    def _set_kill_switch(self, active: bool, reason: str) -> None:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE runtime_kill_switch SET active = ?, reason = ?, "
                    "updated_at = ? WHERE singleton = 1",
                    (int(active), reason, datetime.now(timezone.utc).timestamp()),
                )
                connection.execute("COMMIT")
        except sqlite3.Error as exc:
            raise RuntimeLimitError(
                "RUNTIME_LIMIT_STORE_UNAVAILABLE",
                "unable to update kill-switch state",
            ) from exc


__all__ = [
    "ConcurrencyLimitError",
    "KillSwitchActiveError",
    "RateLimitExceededError",
    "RuntimeBudgetGuard",
    "RuntimeLimitError",
    "RuntimeLimitSnapshot",
    "SQLiteRuntimeBudget",
]
