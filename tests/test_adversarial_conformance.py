"""Adversarial conformance tests for the public governance primitives.

These tests exercise attacker-controlled envelopes, outputs, paths, retries,
and interruption states.  They intentionally use synthetic keys, tools, and
records; passing this file is evidence about the local public primitives, not
proof of a hosted control plane or an external workload attestation system.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hlinor_registry import (
    AcceptanceCriterion,
    DelegationTrustedKey,
    DelegationVerificationError,
    EvidenceRecord,
    ExecutionScope,
    FanOutError,
    HashChainedReceiptSink,
    InMemoryFanOutGuard,
    InMemoryReplayGuard,
    MessageTrustedKey,
    MessageVerificationError,
    OutcomeAcceptanceGate,
    OutcomeStatus,
    PolicyDecision,
    ReceiptError,
    RuntimeBindingError,
    SQLiteCircuitBreaker,
    TrustedKey,
    bind_tool,
    compute_arguments_digest,
    reserve_delegation_child,
    sign_approval_token,
    sign_delegation_token,
    sign_scoped_message,
    verify_delegation_chain,
    verify_delegation_token,
    verify_receipt_chain,
    verify_scoped_message,
)
from hlinor_registry.action_request import ActionRequest


class AllowChecker:
    """Small checker double; the security boundary is the runtime under test."""

    environment = "test"

    def reload_if_changed(self) -> bool:
        return False

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        return PolicyDecision.allow(
            request.agent_id,
            request.action,
            request_id=request.request_id,
            request_digest=request.request_digest,
            environment=request.environment,
        )


def _tool_contract() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "type": "tool_contract",
        "id": "adversarial-tools",
        "name": "Adversarial synthetic tools",
        "description": "Synthetic conformance fixture.",
        "version": "1.0.0",
        "tools": [
            {
                "id": "records.read",
                "action": "read_record",
                "description": "Read one synthetic record.",
                "input_schema": {
                    "type": "object",
                    "properties": {"record_id": {"type": "string"}},
                    "required": ["record_id"],
                    "additionalProperties": False,
                },
                "resource_patterns": ["record/*"],
                "effects": ["database_read"],
                "annotations": {
                    "read_only": True,
                    "destructive": False,
                    "idempotent": True,
                },
            }
        ],
        "metadata": {"owner": "tests", "source": "synthetic"},
    }


def _bound_tool(target: Any):
    contract = _tool_contract()
    return bind_tool(
        contract,
        contract,
        tool_id="records.read",
        target=target,
    )


def _approval_for(bound: Any) -> tuple[dict[str, Any], dict[str, TrustedKey]]:
    private_key = Ed25519PrivateKey.generate()
    trusted_key = TrustedKey(
        key_id="approval-key",
        public_key=private_key.public_key(),
        issuer="synthetic-approver",
    )
    now = datetime.now(timezone.utc)
    token = sign_approval_token(
        private_key=private_key,
        key_id=trusted_key.key_id,
        issuer=trusted_key.issuer or "",
        subject_agent_id="reader",
        action="read_record",
        tool_id="records.read",
        resource="record/123",
        arguments_digest=compute_arguments_digest(
            bound.normalize_arguments(record_id="123")
        ),
        session_id="session-1",
        nonce="approval-nonce",
        approver_role="reviewer",
        issued_at=(now - timedelta(seconds=1)).isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )
    return token, {trusted_key.key_id: trusted_key}


def _message_fixture() -> tuple[
    Ed25519PrivateKey,
    MessageTrustedKey,
    ExecutionScope,
    datetime,
    dict[str, Any],
]:
    private_key = Ed25519PrivateKey.generate()
    trusted_key = MessageTrustedKey(
        key_id="agent-a-key",
        agent_id="agent-a",
        public_key=private_key.public_key(),
        issuer="synthetic-registry",
    )
    scope = ExecutionScope("project-alpha", "workspace-1")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    message = sign_scoped_message(
        private_key=private_key,
        key_id=trusted_key.key_id,
        issuer=trusted_key.issuer or "",
        sender_agent_id="agent-a",
        recipient_agent_id="agent-b",
        scope=scope,
        body={"command": "GO", "authority": "approved"},
        issued_at=(now - timedelta(seconds=1)).isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
        nonce="message-nonce",
        message_id="message-1",
    )
    return private_key, trusted_key, scope, now, message


def test_spoofed_sender_and_poisoned_message_do_not_become_authority() -> None:
    _, trusted_key, scope, now, message = _message_fixture()

    verified = verify_scoped_message(
        message,
        trusted_keys={trusted_key.key_id: trusted_key},
        expected_scope=scope,
        expected_recipient_agent_id="agent-b",
        replay_guard=InMemoryReplayGuard(),
        current_time=now,
    )
    assert verified.body == {"command": "GO", "authority": "approved"}
    policy_signal = verified.as_policy_signal()
    assert "body" not in policy_signal
    assert "authority" not in policy_signal
    assert policy_signal["verified"] is True

    spoofed = dict(message)
    spoofed["sender_agent_id"] = "agent-impersonator"
    with pytest.raises(MessageVerificationError, match="MESSAGE_SENDER_UNTRUSTED"):
        verify_scoped_message(
            spoofed,
            trusted_keys={trusted_key.key_id: trusted_key},
            expected_scope=scope,
            expected_recipient_agent_id="agent-b",
            replay_guard=InMemoryReplayGuard(),
            current_time=now,
        )

    poisoned = dict(message)
    poisoned["body"] = {"command": "STOP", "authority": "revoke-all"}
    with pytest.raises(MessageVerificationError, match="MESSAGE_SIGNATURE_INVALID"):
        verify_scoped_message(
            poisoned,
            trusted_keys={trusted_key.key_id: trusted_key},
            expected_scope=scope,
            expected_recipient_agent_id="agent-b",
            replay_guard=InMemoryReplayGuard(),
            current_time=now,
        )


def test_filename_and_tool_output_are_not_promoted_to_runtime_authority() -> None:
    outputs: list[dict[str, Any]] = []

    def tool(*, record_id: str) -> dict[str, Any]:
        result = {"record_id": record_id, "command": "GO", "authority": "approved"}
        outputs.append(result)
        return result

    bound = _bound_tool(tool)
    with pytest.raises(RuntimeBindingError, match="EXECUTION_SCOPE_REQUIRED"):
        bound.invoke(
            AllowChecker(),  # type: ignore[arg-type]
            agent_id="reader",
            bundle_path="filename-that-says-GO.json",
            signals={"filename": "GO", "tool_output": {"authority": "approved"}},
            require_execution_scope=True,
            resource="record/123",
            kwargs={"record_id": "123"},
        )
    assert outputs == []

    result = bound.invoke(
        AllowChecker(),  # type: ignore[arg-type]
        agent_id="reader",
        bundle_path="filename-that-says-GO.json",
        signals={"filename": "GO"},
        execution_scope=ExecutionScope("project-1", "workspace-1"),
        require_execution_scope=True,
        resource="record/123",
        kwargs={"record_id": "123"},
    )
    assert result["authority"] == "approved"


def test_tampered_receipt_chain_is_rejected() -> None:
    sink = HashChainedReceiptSink()
    bound = _bound_tool(lambda *, record_id: {"record_id": record_id})
    approval, approval_keys = _approval_for(bound)
    bound.invoke(
        AllowChecker(),  # type: ignore[arg-type]
        agent_id="reader",
        resource="record/123",
        session_id="session-1",
        approval_token=approval,
        approval_trusted_keys=approval_keys,
        replay_guard=InMemoryReplayGuard(),
        receipt_sink=sink,
        kwargs={"record_id": "123"},
    )
    records = [dict(record) for record in sink.records]
    assert len(records) == 2
    verify_receipt_chain(records)

    records[0]["reason"] = "rewritten"
    with pytest.raises(ReceiptError, match="receipt hash verification failed"):
        verify_receipt_chain(records)


def _delegation_fixture() -> tuple[
    dict[str, Ed25519PrivateKey],
    dict[str, DelegationTrustedKey],
    dict[str, Any],
    dict[str, Any],
]:
    private: dict[str, Ed25519PrivateKey] = {}
    trusted: dict[str, DelegationTrustedKey] = {}
    for agent_id in ("supervisor", "reader", "worker"):
        key = Ed25519PrivateKey.generate()
        private[agent_id] = key
        trusted[f"key-{agent_id}"] = DelegationTrustedKey(
            key_id=f"key-{agent_id}",
            agent_id=agent_id,
            public_key=key.public_key(),
            issuer="synthetic-control-plane",
        )

    now = datetime.now(timezone.utc)
    common = {
        "audience": "hlinor.tool-runtime",
        "allowed_actions": ["read_record"],
        "allowed_resource_scopes": ["record/123"],
        "session_id": "session-1",
        "tenant_id": "tenant-1",
        "project_id": "project-1",
        "workspace_id": "workspace-1",
        "issued_at": (now - timedelta(seconds=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
    }
    root = sign_delegation_token(
        private_key=private["supervisor"],
        key_id="key-supervisor",
        issuer="synthetic-control-plane",
        issuer_agent_id="supervisor",
        subject_agent_id="reader",
        nonce="root-nonce",
        delegation_depth=0,
        max_depth=2,
        max_fan_out=1,
        delegation_id="delegation-root",
        **common,
    )

    def child(delegation_id: str) -> dict[str, Any]:
        return sign_delegation_token(
            private_key=private["reader"],
            key_id="key-reader",
            issuer="synthetic-control-plane",
            issuer_agent_id="reader",
            subject_agent_id="worker",
            nonce=f"nonce-{delegation_id}",
            delegation_depth=1,
            max_depth=2,
            max_fan_out=0,
            delegation_id=delegation_id,
            parent_delegation_id="delegation-root",
            **common,
        )

    return (
        private,
        trusted,
        root,
        {"child-1": child("child-1"), "child-2": child("child-2")},
    )


def test_delegation_fan_out_is_bounded_before_child_distribution() -> None:
    _, trusted, root, children = _delegation_fixture()
    guard = InMemoryFanOutGuard()
    verified_root = verify_delegation_token(
        root,
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
    )
    verified_children = {
        key: verify_delegation_token(
            token,
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
        )
        for key, token in children.items()
    }

    reserve_delegation_child(
        verified_root, verified_children["child-1"], fan_out_guard=guard
    )
    with pytest.raises(FanOutError, match="DELEGATION_FANOUT_EXCEEDED"):
        reserve_delegation_child(
            verified_root, verified_children["child-2"], fan_out_guard=guard
        )
    with pytest.raises(
        DelegationVerificationError, match="DELEGATION_FANOUT_UNREGISTERED"
    ):
        verify_delegation_chain(
            [root, children["child-2"]],
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
            expected_subject_agent_id="worker",
            expected_action="read_record",
            expected_resource_scope="record/123",
            fan_out_guard=guard,
        )


def test_runaway_retry_is_stopped_by_durable_circuit_breaker(tmp_path) -> None:
    calls: list[str] = []

    def failing_tool(*, record_id: str) -> str:
        calls.append(record_id)
        raise RuntimeError("synthetic dependency failure")

    bound = _bound_tool(failing_tool)
    breaker_path = tmp_path / "breaker.sqlite3"
    breaker = SQLiteCircuitBreaker(breaker_path)
    with pytest.raises(RuntimeError, match="synthetic dependency failure"):
        bound.invoke(
            AllowChecker(),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            circuit_breaker=breaker,
            failure_fingerprint="reader:records.read:record/123",
            failure_threshold=1,
            kwargs={"record_id": "123"},
        )

    with pytest.raises(RuntimeError, match="CIRCUIT_OPEN"):
        bound.invoke(
            AllowChecker(),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            circuit_breaker=SQLiteCircuitBreaker(breaker_path),
            failure_fingerprint="reader:records.read:record/123",
            failure_threshold=1,
            kwargs={"record_id": "123"},
        )
    assert calls == ["123"]


def test_interruption_and_partial_execution_cannot_be_reported_as_success() -> None:
    calls: list[str] = []

    def interrupted_tool(*, record_id: str) -> str:
        calls.append(record_id)
        raise InterruptedError("synthetic interruption after side effect")

    sink = HashChainedReceiptSink()
    bound = _bound_tool(interrupted_tool)
    approval, approval_keys = _approval_for(bound)
    with pytest.raises(InterruptedError, match="synthetic interruption"):
        bound.invoke(
            AllowChecker(),  # type: ignore[arg-type]
            agent_id="reader",
            resource="record/123",
            session_id="session-1",
            approval_token=approval,
            approval_trusted_keys=approval_keys,
            replay_guard=InMemoryReplayGuard(),
            receipt_sink=sink,
            kwargs={"record_id": "123"},
        )

    outcome = OutcomeAcceptanceGate(
        task_id="task-1",
        criteria=(AcceptanceCriterion("result", ("result.json",)),),
    ).evaluate(
        {"result.json": EvidenceRecord("result", "result.json", True)},
        execution_state="interrupted",
    )
    assert calls == ["123"]
    assert sink.records[-1]["side_effect_state"] == "side_effect_attempted"
    assert outcome.status is OutcomeStatus.FAILED
    assert not outcome.successful
