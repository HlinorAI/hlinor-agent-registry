"""Durable project/workspace-scoped state and message storage."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .execution_scope import ExecutionScope

_MAX_TEXT_LENGTH = 256
_MAX_JSON_BYTES = 1_048_576


class ScopedStoreError(ValueError):
    """Raised when scoped state cannot be validated or persisted safely."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class WorkspaceRecord:
    """One JSON record addressed by an explicit project/workspace scope."""

    scope: ExecutionScope
    key: str
    value: object
    revision: int
    updated_at: str


@dataclass(frozen=True, slots=True)
class ScopedMessage:
    """One ordinary message delivered only inside its explicit scope."""

    message_id: str
    scope: ExecutionScope
    sender_agent_id: str
    recipient_agent_id: str
    body: object
    sequence: int
    created_at: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScopedStoreError(
            "SCOPED_STORE_INPUT_INVALID", f"{field} must be non-empty"
        )
    if value != value.strip():
        raise ScopedStoreError(
            "SCOPED_STORE_INPUT_INVALID",
            f"{field} cannot contain outer whitespace",
        )
    if len(value) > _MAX_TEXT_LENGTH:
        raise ScopedStoreError(
            "SCOPED_STORE_INPUT_INVALID",
            f"{field} exceeds the maximum length",
        )
    return value


def _json_bytes(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ScopedStoreError(
            "SCOPED_STORE_VALUE_INVALID",
            "value must be finite, JSON-serializable data",
        ) from exc
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ScopedStoreError(
            "SCOPED_STORE_VALUE_INVALID",
            "value exceeds the maximum JSON size",
        )
    return encoded


def _rollback(connection: sqlite3.Connection) -> None:
    try:
        connection.execute("ROLLBACK")
    except sqlite3.Error:
        pass


class SQLiteScopedWorkspaceStore:
    """SQLite store whose every read/write requires one exact execution scope.

    The store deliberately has no project-global listing method. File names,
    package metadata, and message content are stored as data and never become
    an authority source for selecting a scope.
    """

    def __init__(self, path: str | Path) -> None:
        self._lock = threading.RLock()
        self._closed = False
        try:
            self._connection = sqlite3.connect(
                str(path),
                check_same_thread=False,
                isolation_level=None,
            )
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._initialize()
        except ScopedStoreError:
            raise
        except sqlite3.Error as exc:
            raise ScopedStoreError(
                "SCOPED_STORE_UNAVAILABLE",
                "unable to initialize scoped SQLite storage",
            ) from exc

    def _initialize(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS workspace_records (
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                record_key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                revision INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (project_id, workspace_id, record_key)
            );
            CREATE TABLE IF NOT EXISTS scoped_messages (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                sender_agent_id TEXT NOT NULL,
                recipient_agent_id TEXT NOT NULL,
                body_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS scoped_messages_recipient_idx
                ON scoped_messages (
                    project_id,
                    workspace_id,
                    recipient_agent_id,
                    sequence
                );
            """
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise ScopedStoreError("SCOPED_STORE_CLOSED", "scoped store is closed")

    @staticmethod
    def _scope_values(scope: ExecutionScope) -> tuple[str, str]:
        if not isinstance(scope, ExecutionScope):
            raise ScopedStoreError(
                "SCOPED_STORE_SCOPE_INVALID",
                "scope must be an ExecutionScope instance",
            )
        return scope.project_id, scope.workspace_id

    @staticmethod
    def _record(row: tuple[object, ...]) -> WorkspaceRecord:
        project_id, workspace_id, key, value_json, revision, updated_at = row
        if not all(
            isinstance(value, str)
            for value in (project_id, workspace_id, key, value_json, updated_at)
        ) or not isinstance(revision, int):
            raise ScopedStoreError(
                "SCOPED_STORE_CORRUPT", "stored workspace record has invalid shape"
            )
        assert isinstance(project_id, str)
        assert isinstance(workspace_id, str)
        assert isinstance(key, str)
        assert isinstance(value_json, str)
        assert isinstance(updated_at, str)
        try:
            value = json.loads(value_json)
        except json.JSONDecodeError as exc:  # pragma: no cover - corruption guard
            raise ScopedStoreError(
                "SCOPED_STORE_CORRUPT",
                "stored workspace value is not valid JSON",
            ) from exc
        return WorkspaceRecord(
            scope=ExecutionScope(project_id, workspace_id),
            key=key,
            value=value,
            revision=revision,
            updated_at=updated_at,
        )

    def put(self, scope: ExecutionScope, key: str, value: object) -> WorkspaceRecord:
        """Atomically upsert one record inside exactly one scope."""
        project_id, workspace_id = self._scope_values(scope)
        record_key = _text(key, "key")
        encoded = _json_bytes(value)
        updated_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """
                    INSERT INTO workspace_records (
                        project_id, workspace_id, record_key, value_json,
                        revision, updated_at
                    ) VALUES (?, ?, ?, ?, 1, ?)
                    ON CONFLICT(project_id, workspace_id, record_key)
                    DO UPDATE SET
                        value_json = excluded.value_json,
                        revision = workspace_records.revision + 1,
                        updated_at = excluded.updated_at
                    """,
                    (project_id, workspace_id, record_key, encoded, updated_at),
                )
                row = self._connection.execute(
                    """
                    SELECT project_id, workspace_id, record_key, value_json,
                           revision, updated_at
                    FROM workspace_records
                    WHERE project_id = ? AND workspace_id = ? AND record_key = ?
                    """,
                    (project_id, workspace_id, record_key),
                ).fetchone()
                self._connection.execute("COMMIT")
            except sqlite3.Error as exc:
                _rollback(self._connection)
                raise ScopedStoreError(
                    "SCOPED_STORE_WRITE_FAILED",
                    "unable to write workspace record",
                ) from exc
        if row is None:  # pragma: no cover - database invariant guard
            raise ScopedStoreError("SCOPED_STORE_CORRUPT", "written record disappeared")
        return self._record(row)

    def get(self, scope: ExecutionScope, key: str) -> WorkspaceRecord | None:
        """Read one record; a different project/workspace cannot match it."""
        project_id, workspace_id = self._scope_values(scope)
        record_key = _text(key, "key")
        with self._lock:
            self._ensure_open()
            try:
                row = self._connection.execute(
                    """
                    SELECT project_id, workspace_id, record_key, value_json,
                           revision, updated_at
                    FROM workspace_records
                    WHERE project_id = ? AND workspace_id = ? AND record_key = ?
                    """,
                    (project_id, workspace_id, record_key),
                ).fetchone()
            except sqlite3.Error as exc:
                raise ScopedStoreError(
                    "SCOPED_STORE_READ_FAILED",
                    "unable to read workspace record",
                ) from exc
        return None if row is None else self._record(row)

    def list(
        self, scope: ExecutionScope, *, key_prefix: str | None = None
    ) -> tuple[WorkspaceRecord, ...]:
        """List records inside one scope only; no cross-scope enumeration exists."""
        project_id, workspace_id = self._scope_values(scope)
        prefix = None if key_prefix is None else _text(key_prefix, "key_prefix")
        with self._lock:
            self._ensure_open()
            try:
                if prefix is None:
                    rows = self._connection.execute(
                        """
                        SELECT project_id, workspace_id, record_key, value_json,
                               revision, updated_at
                        FROM workspace_records
                        WHERE project_id = ? AND workspace_id = ?
                        ORDER BY record_key
                        """,
                        (project_id, workspace_id),
                    ).fetchall()
                else:
                    rows = self._connection.execute(
                        """
                        SELECT project_id, workspace_id, record_key, value_json,
                               revision, updated_at
                        FROM workspace_records
                        WHERE project_id = ? AND workspace_id = ?
                          AND record_key LIKE ? ESCAPE '\\'
                        ORDER BY record_key
                        """,
                        (
                            project_id,
                            workspace_id,
                            prefix.replace("\\", "\\\\")
                            .replace("%", "\\%")
                            .replace("_", "\\_")
                            + "%",
                        ),
                    ).fetchall()
            except sqlite3.Error as exc:
                raise ScopedStoreError(
                    "SCOPED_STORE_READ_FAILED",
                    "unable to list workspace records",
                ) from exc
        return tuple(self._record(row) for row in rows)

    def send_message(
        self,
        scope: ExecutionScope,
        *,
        sender_agent_id: str,
        recipient_agent_id: str,
        body: object,
        message_id: str | None = None,
    ) -> ScopedMessage:
        """Persist one message in a scope without interpreting its natural language."""
        project_id, workspace_id = self._scope_values(scope)
        sender = _text(sender_agent_id, "sender_agent_id")
        recipient = _text(recipient_agent_id, "recipient_agent_id")
        effective_message_id = _text(message_id or str(uuid.uuid4()), "message_id")
        encoded = _json_bytes(body)
        created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """
                    INSERT INTO scoped_messages (
                        message_id, project_id, workspace_id, sender_agent_id,
                        recipient_agent_id, body_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        effective_message_id,
                        project_id,
                        workspace_id,
                        sender,
                        recipient,
                        encoded,
                        created_at,
                    ),
                )
                row = self._connection.execute(
                    """
                    SELECT message_id, project_id, workspace_id,
                           sender_agent_id, recipient_agent_id, body_json,
                           sequence, created_at
                    FROM scoped_messages
                    WHERE message_id = ?
                    """,
                    (effective_message_id,),
                ).fetchone()
                self._connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                _rollback(self._connection)
                raise ScopedStoreError(
                    "SCOPED_STORE_MESSAGE_CONFLICT",
                    "message_id is already stored",
                ) from exc
            except sqlite3.Error as exc:
                _rollback(self._connection)
                raise ScopedStoreError(
                    "SCOPED_STORE_WRITE_FAILED",
                    "unable to write scoped message",
                ) from exc
        if row is None:  # pragma: no cover - database invariant guard
            raise ScopedStoreError(
                "SCOPED_STORE_CORRUPT", "written message disappeared"
            )
        return self._message(row)

    @staticmethod
    def _message(row: tuple[object, ...]) -> ScopedMessage:
        (
            message_id,
            project_id,
            workspace_id,
            sender,
            recipient,
            body_json,
            sequence,
            created_at,
        ) = row
        if not all(
            isinstance(value, str)
            for value in (
                message_id,
                project_id,
                workspace_id,
                sender,
                recipient,
                body_json,
                created_at,
            )
        ):
            raise ScopedStoreError(
                "SCOPED_STORE_CORRUPT", "stored message has invalid shape"
            )
        if not isinstance(sequence, int):
            raise ScopedStoreError(
                "SCOPED_STORE_CORRUPT", "stored message sequence is invalid"
            )
        assert isinstance(message_id, str)
        assert isinstance(project_id, str)
        assert isinstance(workspace_id, str)
        assert isinstance(sender, str)
        assert isinstance(recipient, str)
        assert isinstance(body_json, str)
        assert isinstance(created_at, str)
        try:
            body = json.loads(body_json)
        except json.JSONDecodeError as exc:  # pragma: no cover - corruption guard
            raise ScopedStoreError(
                "SCOPED_STORE_CORRUPT", "stored message is not valid JSON"
            ) from exc
        return ScopedMessage(
            message_id=message_id,
            scope=ExecutionScope(project_id, workspace_id),
            sender_agent_id=sender,
            recipient_agent_id=recipient,
            body=body,
            sequence=sequence,
            created_at=created_at,
        )

    def list_messages(
        self,
        scope: ExecutionScope,
        *,
        recipient_agent_id: str,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> tuple[ScopedMessage, ...]:
        """Read messages for one recipient inside one exact scope."""
        project_id, workspace_id = self._scope_values(scope)
        recipient = _text(recipient_agent_id, "recipient_agent_id")
        if not isinstance(after_sequence, int) or after_sequence < 0:
            raise ScopedStoreError(
                "SCOPED_STORE_INPUT_INVALID",
                "after_sequence must be a non-negative integer",
            )
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ScopedStoreError(
                "SCOPED_STORE_INPUT_INVALID",
                "limit must be between 1 and 1000",
            )
        with self._lock:
            self._ensure_open()
            try:
                rows = self._connection.execute(
                    """
                    SELECT message_id, project_id, workspace_id,
                           sender_agent_id, recipient_agent_id, body_json,
                           sequence, created_at
                    FROM scoped_messages
                    WHERE project_id = ? AND workspace_id = ?
                      AND recipient_agent_id = ? AND sequence > ?
                    ORDER BY sequence
                    LIMIT ?
                    """,
                    (project_id, workspace_id, recipient, after_sequence, limit),
                ).fetchall()
            except sqlite3.Error as exc:
                raise ScopedStoreError(
                    "SCOPED_STORE_READ_FAILED",
                    "unable to read scoped messages",
                ) from exc
        return tuple(self._message(row) for row in rows)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self):
        self._ensure_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


__all__ = [
    "SQLiteScopedWorkspaceStore",
    "ScopedMessage",
    "ScopedStoreError",
    "WorkspaceRecord",
]
