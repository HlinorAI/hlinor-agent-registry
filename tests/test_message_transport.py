"""Security tests for signed, scope-bound agent messages."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hlinor_registry import (
    ExecutionScope,
    InMemoryReplayGuard,
    MessageTrustedKey,
    MessageVerificationError,
    sign_scoped_message,
    verify_scoped_message,
)


def _message_fixture() -> tuple[
    Ed25519PrivateKey,
    dict[str, MessageTrustedKey],
    ExecutionScope,
    datetime,
    dict[str, object],
]:
    private_key = Ed25519PrivateKey.generate()
    trusted_key = MessageTrustedKey(
        key_id="agent-a-key-1",
        agent_id="agent-a",
        public_key=private_key.public_key(),
        issuer="synthetic-registry",
    )
    scope = ExecutionScope("project-alpha", "workspace-1")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    message = sign_scoped_message(
        private_key=private_key,
        key_id=trusted_key.key_id,
        issuer="synthetic-registry",
        sender_agent_id="agent-a",
        recipient_agent_id="agent-b",
        scope=scope,
        body={"kind": "status", "text": "ordinary synthetic message"},
        issued_at=(now - timedelta(seconds=1)).isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
        nonce="nonce-1",
        message_id="message-1",
    )
    return private_key, {trusted_key.key_id: trusted_key}, scope, now, message


def test_signed_message_binds_sender_recipient_scope_and_replay_state() -> None:
    _, trusted_keys, scope, now, message = _message_fixture()
    replay_guard = InMemoryReplayGuard()

    verified = verify_scoped_message(
        message,
        trusted_keys=trusted_keys,
        expected_scope=scope,
        expected_recipient_agent_id="agent-b",
        replay_guard=replay_guard,
        current_time=now,
    )

    assert verified.sender_agent_id == "agent-a"
    assert verified.recipient_agent_id == "agent-b"
    assert verified.scope == scope
    assert verified.as_policy_signal()["verified"] is True
    assert verified.body_digest.startswith("sha256:")

    with pytest.raises(MessageVerificationError, match="MESSAGE_REPLAYED"):
        verify_scoped_message(
            message,
            trusted_keys=trusted_keys,
            expected_scope=scope,
            expected_recipient_agent_id="agent-b",
            replay_guard=replay_guard,
            current_time=now,
        )


def test_message_rejects_tampering_and_context_mismatch() -> None:
    _, trusted_keys, scope, now, message = _message_fixture()

    tampered = dict(message)
    tampered["body"] = {"kind": "status", "text": "changed"}
    with pytest.raises(MessageVerificationError, match="MESSAGE_SIGNATURE_INVALID"):
        verify_scoped_message(
            tampered,
            trusted_keys=trusted_keys,
            expected_scope=scope,
            expected_recipient_agent_id="agent-b",
            replay_guard=InMemoryReplayGuard(),
            current_time=now,
        )

    with pytest.raises(MessageVerificationError, match="MESSAGE_SCOPE_MISMATCH"):
        verify_scoped_message(
            message,
            trusted_keys=trusted_keys,
            expected_scope=ExecutionScope("project-alpha", "other-workspace"),
            expected_recipient_agent_id="agent-b",
            replay_guard=InMemoryReplayGuard(),
            current_time=now,
        )

    with pytest.raises(MessageVerificationError, match="MESSAGE_RECIPIENT_MISMATCH"):
        verify_scoped_message(
            message,
            trusted_keys=trusted_keys,
            expected_scope=scope,
            expected_recipient_agent_id="agent-c",
            replay_guard=InMemoryReplayGuard(),
            current_time=now,
        )


def test_message_requires_trusted_sender_and_replay_guard() -> None:
    _, trusted_keys, scope, now, message = _message_fixture()

    with pytest.raises(MessageVerificationError, match="MESSAGE_SENDER_UNTRUSTED"):
        verify_scoped_message(
            message,
            trusted_keys={"different-key": trusted_keys["agent-a-key-1"]},
            expected_scope=scope,
            expected_recipient_agent_id="agent-b",
            replay_guard=InMemoryReplayGuard(),
            current_time=now,
        )

    with pytest.raises(MessageVerificationError, match="MESSAGE_REPLAY_GUARD_REQUIRED"):
        verify_scoped_message(
            message,
            trusted_keys=trusted_keys,
            expected_scope=scope,
            expected_recipient_agent_id="agent-b",
            replay_guard=None,
            current_time=now,
        )


def test_message_rejects_missing_fields_and_oversized_body() -> None:
    private_key, trusted_keys, scope, now, message = _message_fixture()
    missing_body = dict(message)
    del missing_body["body"]

    with pytest.raises(MessageVerificationError, match="MESSAGE_INVALID"):
        verify_scoped_message(
            missing_body,
            trusted_keys=trusted_keys,
            expected_scope=scope,
            expected_recipient_agent_id="agent-b",
            replay_guard=InMemoryReplayGuard(),
            current_time=now,
        )

    with pytest.raises(MessageVerificationError, match="MESSAGE_PAYLOAD_INVALID"):
        sign_scoped_message(
            private_key=private_key,
            key_id="agent-a-key-1",
            issuer="synthetic-registry",
            sender_agent_id="agent-a",
            recipient_agent_id="agent-b",
            scope=scope,
            body={"payload": "x" * (1_048_576 + 1)},
            issued_at=(now - timedelta(seconds=1)).isoformat(),
            expires_at=(now + timedelta(minutes=5)).isoformat(),
            nonce="nonce-oversized",
        )
