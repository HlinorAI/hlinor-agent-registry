"""Tests for immutable, canonical policy evaluation requests."""

from dataclasses import FrozenInstanceError

import pytest

from hlinor_registry import ActionRequest


def request_with_attributes(attributes: dict) -> ActionRequest:
    return ActionRequest(
        request_id="req-stable",
        agent_id="finance-agent",
        action="initiate_transfer",
        attributes=attributes,
        requested_at="2026-07-26T05:00:00+00:00",
    )


def test_request_digest_is_stable_across_mapping_order() -> None:
    first = request_with_attributes({"currency": "USD", "amount": 15})
    second = request_with_attributes({"amount": 15, "currency": "USD"})

    assert first.request_digest == second.request_digest


def test_request_deeply_freezes_attributes() -> None:
    request = request_with_attributes(
        {"recipient": {"status": "approved"}, "scopes": ["read", "transfer"]}
    )

    with pytest.raises(TypeError):
        request.attributes["recipient"] = {}  # type: ignore[index]
    with pytest.raises(TypeError):
        request.attributes["recipient"]["status"] = "new"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        request.action = "delete"  # type: ignore[misc]
    assert request.to_dict()["attributes"]["scopes"] == ["read", "transfer"]


def test_request_rejects_non_json_attributes() -> None:
    with pytest.raises(TypeError, match="Unsupported ActionRequest"):
        request_with_attributes({"unsupported": object()})

    with pytest.raises(ValueError, match="non-finite"):
        request_with_attributes({"amount": float("nan")})


def test_request_rejects_ambiguous_identifiers() -> None:
    with pytest.raises(ValueError, match="outer whitespace"):
        ActionRequest(agent_id=" finance-agent", action="read")

    with pytest.raises(ValueError, match="non-empty"):
        ActionRequest(agent_id="finance-agent", action="")
