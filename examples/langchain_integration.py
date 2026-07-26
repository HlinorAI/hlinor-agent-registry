"""Wrap current LangChain BaseTool instances with Hlinor governance.

Prerequisites:
    pip install "hlinor-registry[langchain]"

Compile the checked-in policy bundle before running this example:
    hlinor-registry compile --manifest registry.yaml --output dist/policy-bundle.json
"""

from langchain_core.tools import StructuredTool

from hlinor_registry import GovernanceDeniedError, PolicyDecision
from hlinor_registry.integrations.langchain import GovernedTool


def search_web(query: str) -> str:
    """Search a controlled public index."""
    return f"Search results for: {query}"


search_tool = StructuredTool.from_function(
    func=search_web,
    name="search",
    description="Search a controlled public index",
)


def record_decision(decision: PolicyDecision) -> None:
    """Send the decision to application observability in production."""
    print(
        f"decision={decision.decision_id} "
        f"request={decision.request_id} result={decision.result}"
    )


governed_search = GovernedTool(
    tool=search_tool,
    agent_id="web-research-agent",
    action_name="search",
    bundle_path="./dist/policy-bundle.json",
    decision_sink=record_decision,
)

governed_login = GovernedTool(
    tool=search_tool,
    agent_id="web-research-agent",
    action_name="login_to_website",
    bundle_path="./dist/policy-bundle.json",
    decision_sink=record_decision,
)


if __name__ == "__main__":
    print(governed_search.invoke({"query": "AI agent governance"}))

    try:
        governed_login.invoke({"query": "https://example.com"})
    except GovernanceDeniedError as error:
        print(f"Blocked before execution: {error.decision.reason_code}")
