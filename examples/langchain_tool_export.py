"""Export a LangChain tool as a reviewed Hlinor Tool Contract."""

from langchain_core.tools import StructuredTool

from hlinor_registry import ToolGovernance, write_tool_contract
from hlinor_registry.integrations.langchain import (
    export_langchain_tool_contract,
)


def search_web(query: str, limit: int = 10) -> list[str]:
    """Search an approved public web index."""
    return [f"Synthetic result for {query}"][:limit]


search_tool = StructuredTool.from_function(
    func=search_web,
    name="search_web",
    description="Search an approved public web index.",
)

contract = export_langchain_tool_contract(
    [search_tool],
    contract_id="research-langchain-tools",
    name="Research LangChain Tools",
    description="Tools exposed to the example research agent.",
    version="1.0.0",
    owner="Example Research Platform Team",
    governance={
        "search_web": ToolGovernance(
            read_only=True,
            destructive=False,
            idempotent=True,
            resource_patterns=("public-web/*",),
            effects=("network_read",),
        )
    },
)

write_tool_contract(contract, "dist/langchain-tools.yaml")
