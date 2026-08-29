"""Security tests for durable project/workspace-scoped state and messages."""

from __future__ import annotations

import pytest

from hlinor_registry import (
    ExecutionScope,
    ScopedStoreError,
    SQLiteScopedWorkspaceStore,
)


def test_workspace_records_are_isolated_by_project_and_workspace(tmp_path) -> None:
    path = tmp_path / "scoped-state.sqlite3"
    alpha = ExecutionScope("project-alpha", "workspace-1")
    beta = ExecutionScope("project-beta", "workspace-1")

    with SQLiteScopedWorkspaceStore(path) as store:
        alpha_record = store.put(alpha, "result", {"owner": "alpha"})
        beta_record = store.put(beta, "result", {"owner": "beta"})

        assert store.get(alpha, "result") == alpha_record
        assert store.get(beta, "result") == beta_record
        assert store.get(alpha, "missing") is None
        assert [record.value for record in store.list(alpha)] == [{"owner": "alpha"}]
        assert [record.value for record in store.list(beta)] == [{"owner": "beta"}]

    with SQLiteScopedWorkspaceStore(path) as reopened:
        assert reopened.get(alpha, "result").revision == 1  # type: ignore[union-attr]


def test_workspace_updates_are_versioned_and_prefix_listing_is_scoped(tmp_path) -> None:
    alpha = ExecutionScope("project-alpha", "workspace-1")
    beta = ExecutionScope("project-beta", "workspace-1")

    with SQLiteScopedWorkspaceStore(tmp_path / "state.sqlite3") as store:
        first = store.put(alpha, "evidence/one", {"value": 1})
        second = store.put(alpha, "evidence/one", {"value": 2})
        store.put(alpha, "draft/one", {"value": 3})
        store.put(beta, "evidence/two", {"value": 4})

        assert first.revision == 1
        assert second.revision == 2
        assert [record.key for record in store.list(alpha, key_prefix="evidence/")] == [
            "evidence/one"
        ]


def test_messages_require_explicit_scope_and_recipient_filter(tmp_path) -> None:
    alpha = ExecutionScope("project-alpha", "workspace-1")
    beta = ExecutionScope("project-beta", "workspace-1")

    with SQLiteScopedWorkspaceStore(tmp_path / "messages.sqlite3") as store:
        sent = store.send_message(
            alpha,
            sender_agent_id="agent-a",
            recipient_agent_id="agent-b",
            body={"text": "ordinary data", "GO": "not authority"},
            message_id="message-alpha",
        )
        store.send_message(
            beta,
            sender_agent_id="agent-a",
            recipient_agent_id="agent-b",
            body={"text": "beta data"},
            message_id="message-beta",
        )
        store.send_message(
            alpha,
            sender_agent_id="agent-a",
            recipient_agent_id="agent-c",
            body={"text": "other recipient"},
        )

        received = store.list_messages(
            alpha,
            recipient_agent_id="agent-b",
        )
        assert len(received) == 1
        assert received[0] == sent
        assert received[0].body["GO"] == "not authority"  # type: ignore[index]
        assert store.list_messages(beta, recipient_agent_id="agent-b")[0].body == {
            "text": "beta data"
        }


def test_scoped_store_rejects_invalid_values_and_duplicate_message_ids(
    tmp_path,
) -> None:
    scope = ExecutionScope("project-alpha", "workspace-1")

    with SQLiteScopedWorkspaceStore(tmp_path / "state.sqlite3") as store:
        with pytest.raises(ScopedStoreError, match="SCOPED_STORE_VALUE_INVALID"):
            store.put(scope, "invalid", {"number": float("nan")})
        with pytest.raises(ScopedStoreError, match="SCOPED_STORE_VALUE_INVALID"):
            store.put(scope, "too-large", "x" * 1_048_577)

        store.send_message(
            scope,
            sender_agent_id="agent-a",
            recipient_agent_id="agent-b",
            body="first",
            message_id="message-1",
        )
        with pytest.raises(ScopedStoreError, match="SCOPED_STORE_MESSAGE_CONFLICT"):
            store.send_message(
                scope,
                sender_agent_id="agent-a",
                recipient_agent_id="agent-b",
                body="second",
                message_id="message-1",
            )

        with pytest.raises(ScopedStoreError, match="SCOPED_STORE_INPUT_INVALID"):
            store.list_messages(scope, recipient_agent_id="agent-b", limit=0)
