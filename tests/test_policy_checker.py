from hlinor_registry import PolicyChecker


def test_blocklist_has_priority(tmp_path):
    (tmp_path / "agent.yaml").write_text(
        "id: finance\nallowed_actions: [read]\nblocked_actions: [read]\n",
        encoding="utf-8",
    )
    allowed, reason = PolicyChecker(str(tmp_path)).check_action("finance", "read")
    assert not allowed
    assert "Blocklist" in reason


def test_allowlist_denies_unspecified_action(tmp_path):
    (tmp_path / "agent.yaml").write_text(
        "id: researcher\nallowed_actions: [search]\n", encoding="utf-8"
    )
    checker = PolicyChecker(str(tmp_path))
    assert checker.check_action("researcher", "search")[0]
    assert not checker.check_action("researcher", "send_email")[0]


def test_no_lists_are_permissive(tmp_path):
    (tmp_path / "agent.yaml").write_text("id: open-agent\n", encoding="utf-8")
    assert PolicyChecker(str(tmp_path)).check_action("open-agent", "read")[0]


def test_unknown_agent_is_denied(tmp_path):
    allowed, reason = PolicyChecker(str(tmp_path)).check_action("missing", "read")
    assert not allowed
    assert "not found" in reason


def test_examples_are_loaded():
    checker = PolicyChecker(".")
    assert {"financial-audit-agent", "web-research-agent"} <= set(checker.agents)
