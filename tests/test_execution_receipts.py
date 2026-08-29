"""Security tests for signed approvals and execution receipts."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_runtime_binding import Checker, contract

from hlinor_registry import (
    ApprovalVerificationError,
    ExecutionScope,
    FailClosedReceiptSink,
    HashChainedReceiptSink,
    InMemoryReplayGuard,
    JsonlReceiptSink,
    ReceiptError,
    SQLiteReplayGuard,
    TrustedKey,
    bind_tool,
    compute_arguments_digest,
    execution_receipts,
    sign_approval_token,
    verify_approval_token,
    verify_receipt_chain,
)


def _keys() -> tuple[Ed25519PrivateKey, dict[str, TrustedKey]]:
    private_key = Ed25519PrivateKey.generate()
    trusted = {
        "approvals-1": TrustedKey(
            key_id="approvals-1",
            public_key=private_key.public_key(),
            issuer="synthetic-approver",
        )
    }
    return private_key, trusted


def _token(
    private_key: Ed25519PrivateKey,
    *,
    arguments_digest: str,
    project_id: str | None = None,
    workspace_id: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return sign_approval_token(
        private_key=private_key,
        key_id="approvals-1",
        issuer="synthetic-approver",
        subject_agent_id="reader",
        action="read_record",
        tool_id="records.read",
        resource="record/123",
        arguments_digest=arguments_digest,
        session_id="session-1",
        project_id=project_id,
        workspace_id=workspace_id,
        nonce="nonce-1",
        approver_role="reviewer",
        issued_at=(now - timedelta(seconds=1)).isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )


def test_signed_approval_is_bound_to_target_and_single_use() -> None:
    private_key, trusted = _keys()
    token = _token(private_key, arguments_digest="sha256:args")
    replay_guard = InMemoryReplayGuard()

    verified = verify_approval_token(
        token,
        trusted_keys=trusted,
        expected_agent_id="reader",
        expected_action="read_record",
        expected_tool_id="records.read",
        expected_resource="record/123",
        expected_arguments_digest="sha256:args",
        expected_session_id="session-1",
        replay_guard=replay_guard,
    )

    assert verified.token_id == token["token_id"]
    assert verified.as_policy_signal()["verified"] is True
    with pytest.raises(ApprovalVerificationError, match="APPROVAL_REPLAYED"):
        verify_approval_token(
            token,
            trusted_keys=trusted,
            expected_agent_id="reader",
            expected_action="read_record",
            expected_tool_id="records.read",
            expected_resource="record/123",
            expected_arguments_digest="sha256:args",
            expected_session_id="session-1",
            replay_guard=replay_guard,
        )


def test_sqlite_replay_guard_is_durable_and_supports_revocation(tmp_path) -> None:
    private_key, trusted = _keys()
    token = _token(private_key, arguments_digest="sha256:args")
    path = tmp_path / "replay.sqlite3"
    first = SQLiteReplayGuard(path)
    second = SQLiteReplayGuard(path)

    verify_approval_token(
        token,
        trusted_keys=trusted,
        expected_agent_id="reader",
        expected_action="read_record",
        expected_tool_id="records.read",
        expected_resource="record/123",
        expected_arguments_digest="sha256:args",
        expected_session_id="session-1",
        replay_guard=first,
    )
    with pytest.raises(ApprovalVerificationError, match="APPROVAL_REPLAYED"):
        verify_approval_token(
            token,
            trusted_keys=trusted,
            expected_agent_id="reader",
            expected_action="read_record",
            expected_tool_id="records.read",
            expected_resource="record/123",
            expected_arguments_digest="sha256:args",
            expected_session_id="session-1",
            replay_guard=second,
        )

    revoked = _token(private_key, arguments_digest="sha256:other")
    second.revoke(revoked["token_id"])
    with pytest.raises(ApprovalVerificationError, match="APPROVAL_REVOKED"):
        verify_approval_token(
            revoked,
            trusted_keys=trusted,
            expected_agent_id="reader",
            expected_action="read_record",
            expected_tool_id="records.read",
            expected_resource="record/123",
            expected_arguments_digest="sha256:other",
            expected_session_id="session-1",
            replay_guard=first,
        )


def test_sqlite_replay_guard_allows_only_one_cross_worker_claim(tmp_path) -> None:
    private_key, trusted = _keys()
    token = _token(private_key, arguments_digest="sha256:args")
    path = tmp_path / "replay.sqlite3"

    def claim() -> str:
        try:
            verify_approval_token(
                token,
                trusted_keys=trusted,
                expected_agent_id="reader",
                expected_action="read_record",
                expected_tool_id="records.read",
                expected_resource="record/123",
                expected_arguments_digest="sha256:args",
                expected_session_id="session-1",
                replay_guard=SQLiteReplayGuard(path),
            )
        except ApprovalVerificationError as exc:
            return exc.code
        return "claimed"

    with ThreadPoolExecutor(max_workers=6) as executor:
        outcomes = list(executor.map(lambda _index: claim(), range(6)))
    assert outcomes.count("claimed") == 1
    assert outcomes.count("APPROVAL_REPLAYED") == 5


def test_tampered_approval_and_target_mismatch_fail_closed() -> None:
    private_key, trusted = _keys()
    token = _token(private_key, arguments_digest="sha256:args")
    tampered = dict(token)
    tampered["resource"] = "record/999"

    with pytest.raises(ApprovalVerificationError, match="APPROVAL_SIGNATURE_INVALID"):
        verify_approval_token(
            tampered,
            trusted_keys=trusted,
            expected_agent_id="reader",
            expected_action="read_record",
            expected_tool_id="records.read",
            expected_resource="record/999",
            expected_arguments_digest="sha256:args",
            expected_session_id="session-1",
            replay_guard=InMemoryReplayGuard(),
        )


def test_signed_approval_is_bound_to_project_and_workspace() -> None:
    private_key, trusted = _keys()
    token = _token(
        private_key,
        arguments_digest="sha256:args",
        project_id="project-1",
        workspace_id="workspace-1",
    )

    verified = verify_approval_token(
        token,
        trusted_keys=trusted,
        expected_agent_id="reader",
        expected_action="read_record",
        expected_tool_id="records.read",
        expected_resource="record/123",
        expected_arguments_digest="sha256:args",
        expected_session_id="session-1",
        expected_project_id="project-1",
        expected_workspace_id="workspace-1",
        replay_guard=InMemoryReplayGuard(),
    )
    assert verified.project_id == "project-1"
    assert verified.workspace_id == "workspace-1"

    with pytest.raises(ApprovalVerificationError, match="APPROVAL_TARGET_MISMATCH"):
        verify_approval_token(
            token,
            trusted_keys=trusted,
            expected_agent_id="reader",
            expected_action="read_record",
            expected_tool_id="records.read",
            expected_resource="record/123",
            expected_arguments_digest="sha256:args",
            expected_session_id="session-1",
            expected_project_id="project-2",
            expected_workspace_id="workspace-1",
            replay_guard=InMemoryReplayGuard(),
        )

    with pytest.raises(ApprovalVerificationError, match="APPROVAL_TARGET_MISMATCH"):
        verify_approval_token(
            token,
            trusted_keys=trusted,
            expected_agent_id="reader",
            expected_action="read_record",
            expected_tool_id="records.read",
            expected_resource="record/999",
            expected_arguments_digest="sha256:args",
            expected_session_id="session-1",
            replay_guard=InMemoryReplayGuard(),
        )


def test_bound_tool_emits_signed_chain_before_and_after_dispatch() -> None:
    approval_key, trusted = _keys()
    receipt_key = Ed25519PrivateKey.generate()
    receipt_trust = {
        "receipts-1": TrustedKey(
            key_id="receipts-1",
            public_key=receipt_key.public_key(),
            issuer="synthetic-runtime",
        )
    }
    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=lambda *, record_id: {"record_id": record_id},
    )
    # Obtain the exact digest from the same normalized object used by dispatch.
    normalized = bound.normalize_arguments(record_id="123")
    arguments_digest = compute_arguments_digest(normalized)
    token = _token(
        approval_key,
        arguments_digest=arguments_digest,
        project_id="project-1",
        workspace_id="workspace-1",
    )
    sink = HashChainedReceiptSink(
        private_key=receipt_key,
        key_id="receipts-1",
        issuer="synthetic-runtime",
    )

    result = bound.invoke(
        Checker(),  # type: ignore[arg-type]
        agent_id="reader",
        resource="record/123",
        session_id="session-1",
        execution_scope=ExecutionScope("project-1", "workspace-1"),
        approval_token=token,
        approval_trusted_keys=trusted,
        replay_guard=InMemoryReplayGuard(),
        receipt_sink=sink,
        kwargs={"record_id": "123"},
    )

    assert result == {"record_id": "123"}
    assert len(sink.records) == 2
    assert sink.records[0]["phase"] == "pre_dispatch"
    assert sink.records[1]["phase"] == "completed"
    assert sink.records[0]["matched_approved_binding"] is True
    assert sink.records[0]["project_id"] == "project-1"
    assert sink.records[0]["workspace_id"] == "workspace-1"
    verify_receipt_chain(sink.records, trusted_keys=receipt_trust)

    tampered = list(sink.records)
    tampered[1]["reason"] = "rewritten"
    with pytest.raises(ReceiptError, match="receipt hash verification failed"):
        verify_receipt_chain(tampered, trusted_keys=receipt_trust)


def test_denial_emits_blocked_receipt_and_does_not_dispatch() -> None:
    calls: list[str] = []
    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=lambda *, record_id: calls.append(record_id),
    )
    sink = HashChainedReceiptSink()

    with pytest.raises(PermissionError):
        bound.invoke(
            Checker(denied=True),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            receipt_sink=sink,
            kwargs={"record_id": "123"},
        )

    assert calls == []
    assert len(sink.records) == 1
    assert sink.records[0]["authorization_result"] == "denied"
    assert sink.records[0]["side_effect_state"] == "blocked_before_side_effect"


def test_jsonl_sink_commits_only_after_durable_write(tmp_path) -> None:
    path = tmp_path / "receipts.jsonl"
    checkpoint = tmp_path / "receipts.checkpoint.json"
    sink = JsonlReceiptSink(path, checkpoint_path=checkpoint)
    stored = sink.append(
        {
            "receipt_id": "receipt-1",
            "session_id": "session-1",
            "binding_id": "binding-1",
            "check_id": "check-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": "reader",
            "requested_tool_name": "records.read",
            "authorization_result": "denied",
            "side_effect_state": "blocked_before_side_effect",
            "matched_approved_binding": False,
            "registry_version": 1,
            "policy_bundle_digest": "sha256:bundle",
            "tool_descriptor_digest": "sha256:tool",
            "normalized_argument_digest": "sha256:args",
            "target_resource_scope": {"resource": "record/123"},
            "approval_id_or_lease_id": "",
        }
    )

    assert json.loads(path.read_text(encoding="utf-8").splitlines()[0]) == stored
    assert json.loads(checkpoint.read_text(encoding="utf-8")) == {
        "schema_version": "1.0",
        "last_sequence": 1,
        "last_receipt_hash": stored["receipt_hash"],
    }
    verify_receipt_chain(sink.records)


def test_jsonl_sink_resumes_only_after_chain_and_checkpoint_verification(
    tmp_path,
) -> None:
    path = tmp_path / "receipts.jsonl"
    checkpoint = tmp_path / "receipts.checkpoint.json"
    first = JsonlReceiptSink(path, checkpoint_path=checkpoint)
    first.append(
        {
            "receipt_id": "receipt-1",
            "session_id": "session-1",
            "binding_id": "binding-1",
            "check_id": "check-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": "reader",
            "requested_tool_name": "records.read",
            "authorization_result": "denied",
            "side_effect_state": "blocked_before_side_effect",
            "matched_approved_binding": False,
            "registry_version": 1,
            "policy_bundle_digest": "sha256:bundle",
            "tool_descriptor_digest": "sha256:tool",
            "normalized_argument_digest": "sha256:args",
            "target_resource_scope": {"resource": "record/123"},
            "approval_id_or_lease_id": "",
        }
    )

    resumed = JsonlReceiptSink(
        path,
        resume=True,
        checkpoint_path=checkpoint,
    )
    stored = resumed.append(
        {
            "receipt_id": "receipt-2",
            "session_id": "session-1",
            "binding_id": "binding-1",
            "check_id": "check-2",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": "reader",
            "requested_tool_name": "records.read",
            "authorization_result": "denied",
            "side_effect_state": "blocked_before_side_effect",
            "matched_approved_binding": False,
            "registry_version": 1,
            "policy_bundle_digest": "sha256:bundle",
            "tool_descriptor_digest": "sha256:tool",
            "normalized_argument_digest": "sha256:args",
            "target_resource_scope": {"resource": "record/123"},
            "approval_id_or_lease_id": "",
        }
    )

    assert len(resumed.records) == 2
    assert stored["sequence"] == 2
    verify_receipt_chain(resumed.records)


def test_jsonl_sink_rejects_tampered_checkpoint_and_chain(tmp_path) -> None:
    path = tmp_path / "receipts.jsonl"
    checkpoint = tmp_path / "receipts.checkpoint.json"
    sink = JsonlReceiptSink(path, checkpoint_path=checkpoint)
    sink.append(
        {
            "receipt_id": "receipt-1",
            "session_id": "session-1",
            "binding_id": "binding-1",
            "check_id": "check-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": "reader",
            "requested_tool_name": "records.read",
            "authorization_result": "denied",
            "side_effect_state": "blocked_before_side_effect",
            "matched_approved_binding": False,
            "registry_version": 1,
            "policy_bundle_digest": "sha256:bundle",
            "tool_descriptor_digest": "sha256:tool",
            "normalized_argument_digest": "sha256:args",
            "target_resource_scope": {"resource": "record/123"},
            "approval_id_or_lease_id": "",
        }
    )

    checkpoint.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "last_sequence": 1,
                "last_receipt_hash": "sha256:tampered",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReceiptError, match="checkpoint does not match"):
        JsonlReceiptSink(path, resume=True, checkpoint_path=checkpoint)

    checkpoint.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "last_sequence": 1,
                "last_receipt_hash": json.loads(path.read_text(encoding="utf-8"))[
                    "receipt_hash"
                ],
            }
        ),
        encoding="utf-8",
    )
    tampered_record = json.loads(path.read_text(encoding="utf-8"))
    tampered_record["actor"] = "tampered"
    path.write_text(json.dumps(tampered_record) + "\n", encoding="utf-8")
    with pytest.raises(ReceiptError, match="receipt hash verification failed"):
        JsonlReceiptSink(path, resume=True, checkpoint_path=checkpoint)


def test_jsonl_sink_fails_closed_after_checkpoint_write_failure(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "receipts.jsonl"
    checkpoint = tmp_path / "receipts.checkpoint.json"
    sink = JsonlReceiptSink(path, checkpoint_path=checkpoint)

    def fail_replace(_source: str, _destination: Path) -> None:
        raise OSError("synthetic checkpoint outage")

    monkeypatch.setattr(execution_receipts.os, "replace", fail_replace)
    receipt = {
        "receipt_id": "receipt-1",
        "session_id": "session-1",
        "binding_id": "binding-1",
        "check_id": "check-1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": "reader",
        "requested_tool_name": "records.read",
        "authorization_result": "denied",
        "side_effect_state": "blocked_before_side_effect",
        "matched_approved_binding": False,
        "registry_version": 1,
        "policy_bundle_digest": "sha256:bundle",
        "tool_descriptor_digest": "sha256:tool",
        "normalized_argument_digest": "sha256:args",
        "target_resource_scope": {"resource": "record/123"},
        "approval_id_or_lease_id": "",
    }
    with pytest.raises(ReceiptError, match="unable to persist receipt checkpoint"):
        sink.append(receipt)
    assert sink.records == ()
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1
    with pytest.raises(ReceiptError, match="sink is broken"):
        sink.append(receipt)


def test_fail_closed_collector_blocks_pre_dispatch() -> None:
    calls: list[str] = []

    class UnavailableCollector:
        def append(self, receipt: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("collector details must not escape")

    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=lambda *, record_id: calls.append(record_id),
    )
    with pytest.raises(ReceiptError, match="external receipt collector unavailable"):
        bound.invoke(
            Checker(),  # type: ignore[arg-type]
            agent_id="reader",
            receipt_sink=FailClosedReceiptSink(UnavailableCollector()),  # type: ignore[arg-type]
            kwargs={"record_id": "123"},
        )
    assert calls == []
