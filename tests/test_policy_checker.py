"""Tests for PolicyChecker with fail-closed enforcement."""

from pathlib import Path

import pytest

from hlinor_registry import PolicyChecker


def test_blocklist_has_priority(tmp_path: Path) -> None:
    """Blocklist always wins, even if action is in allowlist."""
    (tmp_path / "agent.yaml").write_text(
        "id: finance\nallowed_actions: [read]\nblocked_actions: [read]\n",
        encoding="utf-8",
    )
    decision = PolicyChecker(str(tmp_path)).check_action("finance", "read")
    assert decision.denied
    assert decision.reason_code == "ACTION_BLOCKLISTED"


def test_allowlist_denies_unspecified_action(tmp_path: Path) -> None:
    """In strict mode, actions not in allowlist are denied."""
    (tmp_path / "agent.yaml").write_text(
        "id: researcher\nallowed_actions: [search]\n", encoding="utf-8"
    )
    checker = PolicyChecker(str(tmp_path))
    decision = checker.check_action("researcher", "search")
    assert decision.allowed
    decision2 = checker.check_action("researcher", "delete")
    assert decision2.denied
    assert decision2.reason_code == "ACTION_NOT_ALLOWLISTED"


def test_strict_mode_is_default(tmp_path: Path) -> None:
    """By default, agents without allowlist are denied (fail-closed)."""
    (tmp_path / "agent.yaml").write_text("id: open-agent\n", encoding="utf-8")
    decision = PolicyChecker(str(tmp_path)).check_action("open-agent", "read")
    assert decision.denied
    assert decision.reason_code == "ACTION_NOT_ALLOWLISTED"


def test_permissive_mode_allows_by_default(tmp_path: Path) -> None:
    """In permissive mode, actions are allowed unless blocked."""
    (tmp_path / "agent.yaml").write_text(
        "id: open-agent\nenforcement_mode: permissive\n", encoding="utf-8"
    )
    decision = PolicyChecker(str(tmp_path)).check_action("open-agent", "read")
    assert decision.allowed


def test_unknown_agent_is_denied(tmp_path: Path) -> None:
    """Unknown agents are always denied (fail-closed)."""
    decision = PolicyChecker(str(tmp_path)).check_action("missing", "read")
    assert decision.denied
    assert decision.reason_code == "UNKNOWN_AGENT"


def test_duplicate_agent_id_raises(tmp_path: Path) -> None:
    """Duplicate agent IDs should raise ValueError."""
    (tmp_path / "a.yaml").write_text("id: agent1\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("id: agent1\n", encoding="utf-8")
    
    with pytest.raises(ValueError, match="Duplicate agent ID"):
        PolicyChecker(str(tmp_path))


def test_policy_decision_has_required_fields(tmp_path: Path) -> None:
    """PolicyDecision should have all required fields."""
    (tmp_path / "agent.yaml").write_text(
        "id: test-agent\nallowed_actions: [read]\n", encoding="utf-8"
    )
    decision = PolicyChecker(str(tmp_path)).check_action("test-agent", "read")
    
    assert decision.decision_id
    assert decision.agent_id == "test-agent"
    assert decision.action == "read"
    assert decision.result == "allowed"
    assert decision.reason_code == "EXPLICITLY_ALLOWED"
    assert decision.checked_at