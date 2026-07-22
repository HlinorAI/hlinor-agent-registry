from hlinor_registry.integrations.langchain import GovernedAgent, GovernedTool


class FakeTool:
    name = "search"

    def __init__(self):
        self.calls = []

    def run(self, value):
        self.calls.append(value)
        return f"result: {value}"


class FakeAgent:
    def __init__(self, tools):
        self.tools = tools


class FakeExecutor:
    def __init__(self, tools):
        self.agent = FakeAgent(tools)
        self.invocations = []

    def invoke(self, value):
        self.invocations.append(value)
        return value


def write_agent(tmp_path, allowed_actions, blocked_actions=()):
    blocked = ", ".join(blocked_actions)
    allowed = ", ".join(allowed_actions)
    path = tmp_path / "agent.yaml"
    path.write_text(
        f"id: test-agent\nallowed_actions: [{allowed}]\nblocked_actions: [{blocked}]\n",
        encoding="utf-8",
    )
    return tmp_path


def test_governed_tool_allows_and_delegates(tmp_path):
    tool = FakeTool()
    wrapper = GovernedTool(tool, "test-agent", str(write_agent(tmp_path, ["search"])))

    assert wrapper.run("query") == "result: query"
    assert tool.calls == ["query"]


def test_governed_tool_blocks_before_delegation(tmp_path):
    tool = FakeTool()
    wrapper = GovernedTool(
        tool,
        "test-agent",
        str(write_agent(tmp_path, ["search"], ["send_email"])),
        action_name="send_email",
    )

    result = wrapper.run("message")

    assert result.startswith("Action blocked by governance policy:")
    assert tool.calls == []


def test_governed_agent_wraps_nested_tools(tmp_path):
    executor = FakeExecutor([FakeTool(), FakeTool()])
    wrapper = GovernedAgent(
        executor,
        "test-agent",
        str(write_agent(tmp_path, ["search"])),
    )

    assert wrapper.wrapped_tool_count == 2
    assert all(isinstance(tool, GovernedTool) for tool in executor.agent.tools)
    assert wrapper.invoke("request") == "request"
