"""Durable, fail-closed circuit breaker state for governed dispatch."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


class CircuitBreakerError(RuntimeError):
    """Raised when breaker state cannot be read or safely updated."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class BreakerSnapshot:
    """The durable breaker state observed by one operation."""

    failure_fingerprint: str
    threshold: int
    current_count: int
    state: str
    next_action: str
    updated_at: str


class CircuitBreaker(Protocol):
    """Stateful gate used immediately before and after dispatch."""

    def before_dispatch(
        self, failure_fingerprint: str, threshold: int
    ) -> BreakerSnapshot:
        """Allow a normal call or a single half-open probe."""

    def record_success(self, failure_fingerprint: str) -> BreakerSnapshot:
        """Close the breaker after an observed successful call or probe."""

    def record_failure(
        self, failure_fingerprint: str, threshold: int
    ) -> BreakerSnapshot:
        """Record one observed failure and open at the threshold."""

    def start_probe(self, failure_fingerprint: str) -> BreakerSnapshot:
        """Move an open breaker to half-open for one probe."""


class CircuitOpenError(CircuitBreakerError):
    """Raised when a breaker prevents another dispatch."""

    def __init__(self, snapshot: BreakerSnapshot) -> None:
        self.snapshot = snapshot
        super().__init__(
            "CIRCUIT_OPEN",
            f"breaker for {snapshot.failure_fingerprint!r} is {snapshot.state}",
        )


class SQLiteCircuitBreaker:
    """Cross-worker circuit breaker using SQLite transactions for atomicity."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local_lock = threading.Lock()
        try:
            with self._connect() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS circuit_breakers ("
                    "failure_fingerprint TEXT PRIMARY KEY, threshold INTEGER NOT NULL, "
                    "current_count INTEGER NOT NULL, state TEXT NOT NULL, "
                    "next_action TEXT NOT NULL, probe_claimed INTEGER NOT NULL, "
                    "updated_at REAL NOT NULL)"
                )
        except sqlite3.Error as exc:
            raise CircuitBreakerError(
                "BREAKER_STORE_UNAVAILABLE",
                f"unable to initialize circuit breaker store: {exc}",
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _validate_fingerprint(failure_fingerprint: str) -> None:
        if not isinstance(failure_fingerprint, str) or not failure_fingerprint.strip():
            raise ValueError("failure_fingerprint must be a non-empty string")

    @staticmethod
    def _validate_threshold(threshold: int) -> None:
        if (
            not isinstance(threshold, int)
            or isinstance(threshold, bool)
            or threshold < 1
        ):
            raise ValueError("threshold must be a positive integer")

    @staticmethod
    def _timestamp() -> float:
        return datetime.now(timezone.utc).timestamp()

    @staticmethod
    def _iso_timestamp(value: float) -> str:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()

    @classmethod
    def _snapshot(cls, row: tuple[object, ...]) -> BreakerSnapshot:
        (
            fingerprint,
            threshold,
            count,
            state,
            next_action,
            _probe_claimed,
            updated_at,
        ) = row
        if not isinstance(threshold, int) or not isinstance(count, int):
            raise CircuitBreakerError(
                "BREAKER_STORE_UNAVAILABLE", "breaker counters are invalid"
            )
        if not isinstance(updated_at, (int, float)):
            raise CircuitBreakerError(
                "BREAKER_STORE_UNAVAILABLE", "breaker timestamp is invalid"
            )
        return BreakerSnapshot(
            failure_fingerprint=str(fingerprint),
            threshold=threshold,
            current_count=count,
            state=str(state),
            next_action=str(next_action),
            updated_at=cls._iso_timestamp(updated_at),
        )

    @staticmethod
    def _read(
        connection: sqlite3.Connection, fingerprint: str
    ) -> tuple[object, ...] | None:
        row = connection.execute(
            "SELECT failure_fingerprint, threshold, current_count, state, next_action, "
            "probe_claimed, updated_at FROM circuit_breakers WHERE failure_fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        return row

    @classmethod
    def _require_row(
        cls,
        connection: sqlite3.Connection,
        fingerprint: str,
        threshold: int,
    ) -> tuple[object, ...]:
        row = cls._read(connection, fingerprint)
        if row is None:
            now = cls._timestamp()
            connection.execute(
                "INSERT INTO circuit_breakers VALUES (?, ?, 0, 'closed', 'continue', 0, ?)",
                (fingerprint, threshold, now),
            )
            row = cls._read(connection, fingerprint)
        if row is None:  # pragma: no cover - SQLite invariant
            raise CircuitBreakerError(
                "BREAKER_STORE_UNAVAILABLE", "breaker row disappeared"
            )
        if not isinstance(row[1], int):
            raise CircuitBreakerError(
                "BREAKER_STORE_UNAVAILABLE", "breaker threshold is invalid"
            )
        if row[1] != threshold:
            raise CircuitBreakerError(
                "BREAKER_THRESHOLD_MISMATCH",
                f"stored threshold is {row[1]}, requested threshold is {threshold}",
            )
        return row

    def before_dispatch(
        self, failure_fingerprint: str, threshold: int
    ) -> BreakerSnapshot:
        self._validate_fingerprint(failure_fingerprint)
        self._validate_threshold(threshold)
        try:
            with self._local_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = self._require_row(connection, failure_fingerprint, threshold)
                state = str(row[3])
                if state == "open":
                    connection.execute("ROLLBACK")
                    raise CircuitOpenError(self._snapshot(row))
                if state == "half_open":
                    if bool(row[5]):
                        connection.execute("ROLLBACK")
                        raise CircuitOpenError(self._snapshot(row))
                    now = self._timestamp()
                    connection.execute(
                        "UPDATE circuit_breakers SET probe_claimed = 1, next_action = 'retry_probe', updated_at = ? WHERE failure_fingerprint = ?",
                        (now, failure_fingerprint),
                    )
                    connection.execute("COMMIT")
                    updated = self._read(connection, failure_fingerprint)
                    if updated is None:  # pragma: no cover
                        raise CircuitBreakerError(
                            "BREAKER_STORE_UNAVAILABLE", "breaker row disappeared"
                        )
                    return self._snapshot(updated)
                connection.execute("COMMIT")
                return self._snapshot(row)
        except CircuitBreakerError:
            raise
        except sqlite3.Error as exc:
            raise CircuitBreakerError(
                "BREAKER_STORE_UNAVAILABLE",
                f"unable to authorize dispatch: {exc}",
            ) from exc

    def record_failure(
        self, failure_fingerprint: str, threshold: int
    ) -> BreakerSnapshot:
        self._validate_fingerprint(failure_fingerprint)
        self._validate_threshold(threshold)
        try:
            with self._local_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = self._require_row(connection, failure_fingerprint, threshold)
                if not isinstance(row[2], int):
                    raise CircuitBreakerError(
                        "BREAKER_STORE_UNAVAILABLE", "breaker count is invalid"
                    )
                count = row[2] + 1
                state = "open" if count >= threshold else "closed"
                next_action = "stop" if state == "open" else "continue"
                now = self._timestamp()
                connection.execute(
                    "UPDATE circuit_breakers SET current_count = ?, state = ?, next_action = ?, "
                    "probe_claimed = 0, updated_at = ? WHERE failure_fingerprint = ?",
                    (count, state, next_action, now, failure_fingerprint),
                )
                connection.execute("COMMIT")
                updated = self._read(connection, failure_fingerprint)
                if updated is None:  # pragma: no cover
                    raise CircuitBreakerError(
                        "BREAKER_STORE_UNAVAILABLE", "breaker row disappeared"
                    )
                return self._snapshot(updated)
        except CircuitBreakerError:
            raise
        except sqlite3.Error as exc:
            raise CircuitBreakerError(
                "BREAKER_STORE_UNAVAILABLE",
                f"unable to record failure: {exc}",
            ) from exc

    def record_success(self, failure_fingerprint: str) -> BreakerSnapshot:
        self._validate_fingerprint(failure_fingerprint)
        try:
            with self._local_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = self._read(connection, failure_fingerprint)
                if row is None:
                    raise CircuitBreakerError(
                        "BREAKER_UNKNOWN", "no breaker exists for fingerprint"
                    )
                if str(row[3]) == "open":
                    # A normal call may have started before another worker
                    # opened the breaker. Its late success is not evidence that
                    # the already-triggered stop condition is safe to clear.
                    connection.execute("COMMIT")
                    return self._snapshot(row)
                now = self._timestamp()
                connection.execute(
                    "UPDATE circuit_breakers SET current_count = 0, state = 'closed', next_action = 'continue', "
                    "probe_claimed = 0, updated_at = ? WHERE failure_fingerprint = ?",
                    (now, failure_fingerprint),
                )
                connection.execute("COMMIT")
                updated = self._read(connection, failure_fingerprint)
                if updated is None:  # pragma: no cover
                    raise CircuitBreakerError(
                        "BREAKER_STORE_UNAVAILABLE", "breaker row disappeared"
                    )
                return self._snapshot(updated)
        except CircuitBreakerError:
            raise
        except sqlite3.Error as exc:
            raise CircuitBreakerError(
                "BREAKER_STORE_UNAVAILABLE",
                f"unable to record success: {exc}",
            ) from exc

    def start_probe(self, failure_fingerprint: str) -> BreakerSnapshot:
        self._validate_fingerprint(failure_fingerprint)
        try:
            with self._local_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = self._read(connection, failure_fingerprint)
                if row is None:
                    raise CircuitBreakerError(
                        "BREAKER_UNKNOWN", "no breaker exists for fingerprint"
                    )
                if str(row[3]) != "open":
                    raise CircuitBreakerError(
                        "BREAKER_NOT_OPEN", "only an open breaker can start a probe"
                    )
                now = self._timestamp()
                connection.execute(
                    "UPDATE circuit_breakers SET state = 'half_open', next_action = 'retry_probe', "
                    "probe_claimed = 0, updated_at = ? WHERE failure_fingerprint = ?",
                    (now, failure_fingerprint),
                )
                connection.execute("COMMIT")
                updated = self._read(connection, failure_fingerprint)
                if updated is None:  # pragma: no cover
                    raise CircuitBreakerError(
                        "BREAKER_STORE_UNAVAILABLE", "breaker row disappeared"
                    )
                return self._snapshot(updated)
        except CircuitBreakerError:
            raise
        except sqlite3.Error as exc:
            raise CircuitBreakerError(
                "BREAKER_STORE_UNAVAILABLE",
                f"unable to start probe: {exc}",
            ) from exc


__all__ = [
    "BreakerSnapshot",
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitOpenError",
    "SQLiteCircuitBreaker",
]
