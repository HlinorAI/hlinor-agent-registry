"""Example integration between Hlinor Registry and LangChain.

Prerequisites:
    pip install langchain langchain-openai hlinor-registry

This example exits cleanly when optional LangChain dependencies are not
installed, which keeps the base Hlinor package dependency-free.

Compile the checked-in policy bundle before running this example:
    hlinor-registry compile --manifest registry.yaml --output dist/policy-bundle.json
"""

import os

from hlinor_registry.integrations.langchain import GovernedAgent, GovernedTool


def example_governed_tool() -> None:
    """Wrap a single LangChain tool with Hlinor policy enforcement."""
    try:
        from langchain.tools import Tool
    except ImportError:
        print("LangChain is not installed. Run: pip install langchain")
        return

    def search_web(query: str) -> str:
        return f"Search results for: {query}"

    search_tool = Tool(
        name="search",
        func=search_web,
        description="Search the web for information",
    )

    governed_search = GovernedTool(
        tool=search_tool,
        agent_id="web-research-agent",
        bundle_path="./dist/policy-bundle.json",
    )
    print("\n--- Allowed action ---")
    print(governed_search.run("AI agent governance"))

    governed_login = GovernedTool(
        tool=search_tool,
        agent_id="web-research-agent",
        bundle_path="./dist/policy-bundle.json",
        action_name="login_to_website",
    )
    print("\n--- Blocked action ---")
    print(governed_login.run("https://example.com"))


def example_governed_agent() -> None:
    """Wrap a full LangChain agent executor with Hlinor policy enforcement."""
    try:
        from langchain.agents import AgentType, initialize_agent
        from langchain.tools import Tool
        from langchain_openai import ChatOpenAI
    except ImportError:
        print("LangChain is not installed. Run: pip install langchain langchain-openai")
        return

    if not os.getenv("OPENAI_API_KEY"):
        print("Set the OPENAI_API_KEY environment variable to run this example.")
        return

    search_tool = Tool(
        name="search",
        func=lambda query: f"Search results for: {query}",
        description="Search the web",
    )
    email_tool = Tool(
        name="send_email",
        func=lambda message: f"Email sent: {message}",
        description="Send an email",
    )

    agent = initialize_agent(
        tools=[search_tool, email_tool],
        llm=ChatOpenAI(temperature=0),
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True,
    )
    governed_agent = GovernedAgent(
        agent_executor=agent,
        agent_id="financial-audit-agent",
        bundle_path="./dist/policy-bundle.json",
    )
    print("\n--- Governed agent ---")
    print(governed_agent.invoke("Search for recent financial reports"))


if __name__ == "__main__":
    print("Hlinor Agent Registry + LangChain Integration Examples")
    example_governed_tool()
    example_governed_agent()
