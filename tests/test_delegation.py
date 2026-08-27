"""Security tests for authenticated delegation and bounded fan-out."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_runtime_binding import Checker, contract

from hlinor_registry import (
    DelegationTrustedKey,
    DelegationVerificationError,
    FanOutError,
    InMemoryFanOutGuard,
    SQLiteFanOutGuard,
    SQLiteReplayGuard,
    bind_tool,
    reserve_delegation_child,
    sign_delegation_token,
    sign_delegation_transport,
    verify_delegation_chain,
    verify_delegation_token,
    verify_delegation_transport,
)


def _keys(
    *, identity_bound: bool = False
) -> tuple[dict[str, Ed25519PrivateKey], dict[str, DelegationTrustedKey]]:
    private: dict[str, Ed25519PrivateKey] = {}
    trusted: dict[str, DelegationTrustedKey] = {}
    for agent_id in ("supervisor", "reader", "worker"):
        key = Ed25519PrivateKey.generate()
        key_id = f"key-{agent_id}"
        private[agent_id] = key
        trusted[key_id] = DelegationTrustedKey(
            key_id=key_id,
            agent_id=agent_id,
            public_key=key.public_key(),
            issuer="synthetic-control-plane",
            deployment_identity=(f"oci:sha256:{agent_id}" if identity_bound else None),
            workload_identity=(f"workload:{agent_id}" if identity_bound else None),
        )
    return private, trusted


def _times() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    return (now - timedelta(seconds=1)).isoformat(), (
        now + timedelta(minutes=5)
    ).isoformat()


def _root_token(
    private_key: Ed25519PrivateKey,
    *,
    max_fan_out: int = 2,
    delegation_id: str = "delegation-root",
    identity_bound: bool = False,
) -> dict[str, Any]:
    issued_at, expires_at = _times()
    return sign_delegation_token(
        private_key=private_key,
        key_id="key-supervisor",
        issuer="synthetic-control-plane",
        issuer_agent_id="supervisor",
        subject_agent_id="reader",
        audience="hlinor.tool-runtime",
        allowed_actions=["read_record"],
        allowed_resource_scopes=["record/123"],
        session_id="session-1",
        tenant_id="tenant-1",
        project_id="project-1",
        workspace_id="workspace-1",
        issued_at=issued_at,
        expires_at=expires_at,
        nonce="root-nonce",
        delegation_depth=0,
        max_depth=2,
        max_fan_out=max_fan_out,
        delegation_id=delegation_id,
        issuer_deployment_identity=(
            "oci:sha256:supervisor" if identity_bound else None
        ),
        issuer_workload_identity=("workload:supervisor" if identity_bound else None),
    )


def _child_token(
    private_key: Ed25519PrivateKey,
    *,
    parent_delegation_id: str = "delegation-root",
    delegation_id: str = "delegation-child",
    subject_agent_id: str = "worker",
    allowed_actions: list[str] | None = None,
    allowed_resource_scopes: list[str] | None = None,
    max_depth: int = 2,
    identity_bound: bool = False,
) -> dict[str, Any]:
    issued_at, expires_at = _times()
    return sign_delegation_token(
        private_key=private_key,
        key_id="key-reader",
        issuer="synthetic-control-plane",
        issuer_agent_id="reader",
        subject_agent_id=subject_agent_id,
        audience="hlinor.tool-runtime",
        allowed_actions=allowed_actions or ["read_record"],
        allowed_resource_scopes=allowed_resource_scopes or ["record/123"],
        session_id="session-1",
        tenant_id="tenant-1",
        project_id="project-1",
        workspace_id="workspace-1",
        parent_delegation_id=parent_delegation_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=f"nonce-{delegation_id}",
        delegation_depth=1,
        max_depth=max_depth,
        max_fan_out=0,
        delegation_id=delegation_id,
        issuer_deployment_identity=("oci:sha256:reader" if identity_bound else None),
        issuer_workload_identity=("workload:reader" if identity_bound else None),
    )


def _verified_pair(
    private: dict[str, Ed25519PrivateKey],
    trusted: dict[str, DelegationTrustedKey],
    guard: InMemoryFanOutGuard | SQLiteFanOutGuard,
) -> tuple[dict[str, Any], dict[str, Any]]:
    root = _root_token(private["supervisor"])
    child = _child_token(private["reader"])
    verified_root = verify_delegation_token(
        root,
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
    )
    verified_child = verify_delegation_token(
        child,
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
    )
    reserve_delegation_child(
        verified_root,
        verified_child,
        fan_out_guard=guard,
    )
    return root, child


def test_delegation_chain_binds_key_identity_context_and_attenuates_scope() -> None:
    private, trusted = _keys()
    guard = InMemoryFanOutGuard()
    root, child = _verified_pair(private, trusted, guard)

    verified = verify_delegation_chain(
        [root, child],
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
        expected_subject_agent_id="worker",
        expected_action="read_record",
        expected_resource_scope="record/123",
        expected_session_id="session-1",
        expected_tenant_id="tenant-1",
        fan_out_guard=guard,
    )

    assert [item.subject_agent_id for item in verified] == ["reader", "worker"]
    assert verified[-1].as_policy_signal()["verified"] is True


def test_delegation_rejects_key_agent_mismatch_and_scope_escalation() -> None:
    private, trusted = _keys()
    root = _root_token(private["supervisor"])
    forged_identity = dict(root)
    forged_identity["issuer_agent_id"] = "worker"
    with pytest.raises(DelegationVerificationError, match="DELEGATION_ISSUER_UNBOUND"):
        verify_delegation_token(
            forged_identity,
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
        )

    child = _child_token(
        private["reader"],
        allowed_resource_scopes=["record/999"],
    )
    verified_root = verify_delegation_token(
        root,
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
    )
    verified_child = verify_delegation_token(
        child,
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
    )
    with pytest.raises(
        DelegationVerificationError, match="DELEGATION_SCOPE_ESCALATION"
    ):
        reserve_delegation_child(
            verified_root,
            verified_child,
            fan_out_guard=InMemoryFanOutGuard(),
        )


def test_sqlite_fan_out_guard_allows_only_the_configured_number_of_children(
    tmp_path,
) -> None:
    private, trusted = _keys()
    root = _root_token(private["supervisor"], max_fan_out=2)
    verified_root = verify_delegation_token(
        root,
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
    )
    children = [
        verify_delegation_token(
            _child_token(private["reader"], delegation_id=f"child-{index}"),
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
        )
        for index in range(6)
    ]
    guard_path = tmp_path / "fanout.sqlite3"

    def reserve(child: Any) -> str:
        try:
            reserve_delegation_child(
                verified_root,
                child,
                fan_out_guard=SQLiteFanOutGuard(guard_path),
            )
        except FanOutError as exc:
            return exc.code
        return "reserved"

    with ThreadPoolExecutor(max_workers=6) as executor:
        outcomes = list(executor.map(reserve, children))
    assert outcomes.count("reserved") == 2
    assert outcomes.count("DELEGATION_FANOUT_EXCEEDED") == 4


def test_revoked_delegation_is_rejected_and_child_requires_registration() -> None:
    private, trusted = _keys()
    guard = InMemoryFanOutGuard()
    root = _root_token(private["supervisor"])
    child = _child_token(private["reader"])
    guard.revoke(root["delegation_id"])
    with pytest.raises(DelegationVerificationError, match="DELEGATION_REVOKED"):
        verify_delegation_chain(
            [root, child],
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
            expected_subject_agent_id="worker",
            fan_out_guard=guard,
        )

    fresh_guard = InMemoryFanOutGuard()
    with pytest.raises(
        DelegationVerificationError, match="DELEGATION_FANOUT_UNREGISTERED"
    ):
        verify_delegation_chain(
            [root, child],
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
            expected_subject_agent_id="worker",
            fan_out_guard=fresh_guard,
        )


def test_bound_tool_checks_delegation_before_policy_and_dispatch() -> None:
    private, trusted = _keys()
    root = _root_token(private["supervisor"], max_fan_out=0)
    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=lambda *, record_id: {"record_id": record_id},
    )
    result = bound.invoke(
        Checker(),  # type: ignore[arg-type]
        agent_id="reader",
        resource="record/123",
        session_id="session-1",
        delegation_chain=[root],
        delegation_trusted_keys=trusted,
        delegation_audience="hlinor.tool-runtime",
        kwargs={"record_id": "123"},
    )
    assert result == {"record_id": "123"}


def _strict_transport_fixture(
    private: dict[str, Ed25519PrivateKey],
    trusted: dict[str, DelegationTrustedKey],
) -> tuple[dict[str, Any], dict[str, Any], InMemoryFanOutGuard]:
    root = _root_token(private["supervisor"], identity_bound=True)
    child = _child_token(private["reader"], identity_bound=True)
    guard = InMemoryFanOutGuard()
    verified_root = verify_delegation_token(
        root,
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
        require_identity_binding=True,
    )
    verified_child = verify_delegation_token(
        child,
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
        require_identity_binding=True,
    )
    reserve_delegation_child(
        verified_root,
        verified_child,
        fan_out_guard=guard,
    )
    return root, child, guard


def _transport(
    private: dict[str, Ed25519PrivateKey],
    chain: list[dict[str, Any]],
    *,
    sender_workload_identity: str = "workload:worker",
) -> dict[str, Any]:
    issued_at, expires_at = _times()
    return sign_delegation_transport(
        private_key=private["worker"],
        key_id="key-worker",
        issuer="synthetic-control-plane",
        transport_id="transport-1",
        audience="hlinor.tool-runtime",
        sender_agent_id="worker",
        sender_deployment_identity="oci:sha256:worker",
        sender_workload_identity=sender_workload_identity,
        receiver_deployment_identity="oci:sha256:tool-runtime",
        receiver_workload_identity="workload:tool-runtime",
        delegation_chain=chain,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce="transport-nonce-1",
    )


def test_identity_bound_transport_verifies_sender_receiver_and_chain(tmp_path) -> None:
    private, trusted = _keys(identity_bound=True)
    root, child, fan_out_guard = _strict_transport_fixture(private, trusted)
    verified = verify_delegation_transport(
        _transport(private, [root, child]),
        trusted_keys=trusted,
        expected_audience="hlinor.tool-runtime",
        expected_sender_agent_id="worker",
        expected_sender_deployment_identity="oci:sha256:worker",
        expected_sender_workload_identity="workload:worker",
        expected_receiver_deployment_identity="oci:sha256:tool-runtime",
        expected_receiver_workload_identity="workload:tool-runtime",
        expected_action="read_record",
        expected_resource_scope="record/123",
        expected_session_id="session-1",
        expected_tenant_id="tenant-1",
        fan_out_guard=fan_out_guard,
        replay_guard=SQLiteReplayGuard(tmp_path / "transport-replay.sqlite3"),
    )
    assert verified.sender_agent_id == "worker"
    assert verified.sender_workload_identity == "workload:worker"
    assert verified.delegation_chain[-1].subject_agent_id == "worker"


def test_transport_rejects_tampering_and_requires_replay_guard(tmp_path) -> None:
    private, trusted = _keys(identity_bound=True)
    root, child, fan_out_guard = _strict_transport_fixture(private, trusted)
    envelope = _transport(private, [root, child])
    tampered = dict(envelope)
    tampered_chain = [dict(root), dict(child)]
    tampered_chain[1]["allowed_actions"] = ["delete_record"]
    tampered["delegation_chain"] = tampered_chain
    with pytest.raises(
        DelegationVerificationError,
        match="DELEGATION_TRANSPORT_SIGNATURE_INVALID",
    ):
        verify_delegation_transport(
            tampered,
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
            expected_sender_agent_id="worker",
            expected_sender_deployment_identity="oci:sha256:worker",
            expected_sender_workload_identity="workload:worker",
            expected_receiver_deployment_identity="oci:sha256:tool-runtime",
            expected_receiver_workload_identity="workload:tool-runtime",
            fan_out_guard=fan_out_guard,
            replay_guard=SQLiteReplayGuard(tmp_path / "transport-replay.sqlite3"),
        )
    with pytest.raises(
        DelegationVerificationError,
        match="DELEGATION_TRANSPORT_REPLAY_GUARD_REQUIRED",
    ):
        verify_delegation_transport(
            envelope,
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
            expected_sender_agent_id="worker",
            expected_sender_deployment_identity="oci:sha256:worker",
            expected_sender_workload_identity="workload:worker",
            expected_receiver_deployment_identity="oci:sha256:tool-runtime",
            expected_receiver_workload_identity="workload:tool-runtime",
            fan_out_guard=fan_out_guard,
        )


def test_transport_rejects_context_mismatch_and_replay(tmp_path) -> None:
    private, trusted = _keys(identity_bound=True)
    root, child, fan_out_guard = _strict_transport_fixture(private, trusted)
    envelope = _transport(
        private,
        [root, child],
        sender_workload_identity="workload:other",
    )
    with pytest.raises(
        DelegationVerificationError, match="DELEGATION_TRANSPORT_CONTEXT_MISMATCH"
    ):
        verify_delegation_transport(
            envelope,
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
            expected_sender_agent_id="worker",
            expected_sender_deployment_identity="oci:sha256:worker",
            expected_sender_workload_identity="workload:worker",
            expected_receiver_deployment_identity="oci:sha256:tool-runtime",
            expected_receiver_workload_identity="workload:tool-runtime",
            fan_out_guard=fan_out_guard,
            replay_guard=SQLiteReplayGuard(tmp_path / "transport-replay.sqlite3"),
        )

    envelope = _transport(private, [root, child])
    replay_guard = SQLiteReplayGuard(tmp_path / "transport-replay.sqlite3")
    verification_args = {
        "trusted_keys": trusted,
        "expected_audience": "hlinor.tool-runtime",
        "expected_sender_agent_id": "worker",
        "expected_sender_deployment_identity": "oci:sha256:worker",
        "expected_sender_workload_identity": "workload:worker",
        "expected_receiver_deployment_identity": "oci:sha256:tool-runtime",
        "expected_receiver_workload_identity": "workload:tool-runtime",
        "fan_out_guard": fan_out_guard,
        "replay_guard": replay_guard,
    }
    verify_delegation_transport(envelope, **verification_args)
    with pytest.raises(
        DelegationVerificationError, match="DELEGATION_TRANSPORT_REPLAYED"
    ):
        verify_delegation_transport(envelope, **verification_args)


def test_strict_transport_rejects_keys_without_identity_binding(tmp_path) -> None:
    private, trusted = _keys()
    root, child, fan_out_guard = _strict_transport_fixture(*_keys(identity_bound=True))
    envelope = _transport(private, [root, child])
    with pytest.raises(
        DelegationVerificationError, match="DELEGATION_IDENTITY_UNBOUND"
    ):
        verify_delegation_transport(
            envelope,
            trusted_keys=trusted,
            expected_audience="hlinor.tool-runtime",
            expected_sender_agent_id="worker",
            expected_sender_deployment_identity="oci:sha256:worker",
            expected_sender_workload_identity="workload:worker",
            expected_receiver_deployment_identity="oci:sha256:tool-runtime",
            expected_receiver_workload_identity="workload:tool-runtime",
            fan_out_guard=fan_out_guard,
            replay_guard=SQLiteReplayGuard(tmp_path / "transport-replay.sqlite3"),
        )


def test_bound_tool_accepts_identity_bound_transport(tmp_path) -> None:
    private, trusted = _keys(identity_bound=True)
    root, child, fan_out_guard = _strict_transport_fixture(private, trusted)
    bound = bind_tool(
        contract(),
        contract(),
        tool_id="records.read",
        target=lambda *, record_id: {"record_id": record_id},
    )
    result = bound.invoke(
        Checker(),  # type: ignore[arg-type]
        agent_id="worker",
        resource="record/123",
        session_id="session-1",
        delegation_transport=_transport(private, [root, child]),
        delegation_trusted_keys=trusted,
        delegation_audience="hlinor.tool-runtime",
        delegation_fan_out_guard=fan_out_guard,
        delegation_expected_sender_deployment_identity="oci:sha256:worker",
        delegation_expected_sender_workload_identity="workload:worker",
        delegation_receiver_deployment_identity="oci:sha256:tool-runtime",
        delegation_receiver_workload_identity="workload:tool-runtime",
        delegation_transport_replay_guard=SQLiteReplayGuard(
            tmp_path / "transport-replay.sqlite3"
        ),
        kwargs={"record_id": "123"},
    )
    assert result == {"record_id": "123"}
