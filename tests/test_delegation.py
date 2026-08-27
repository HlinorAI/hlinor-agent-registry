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
    bind_tool,
    reserve_delegation_child,
    sign_delegation_token,
    verify_delegation_chain,
    verify_delegation_token,
)


def _keys() -> tuple[dict[str, Ed25519PrivateKey], dict[str, DelegationTrustedKey]]:
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
