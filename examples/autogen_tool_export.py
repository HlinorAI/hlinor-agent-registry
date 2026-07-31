"""Export a Microsoft AutoGen tool as a reviewed Hlinor Tool Contract."""

from autogen_core.tools import FunctionTool

from hlinor_registry import ToolGovernance, write_tool_contract
from hlinor_registry.integrations.autogen import export_autogen_tool_contract


async def search_web(query: str, limit: int = 10) -> list[str]:
    """Search an approved public web index."""
    return [f"Synthetic result for {query}"][:limit]


search_tool = FunctionTool(
    search_web,
    name="search_web",
    description="Search an approved public web index.",
)

contract = export_autogen_tool_contract(
    [search_tool],
    contract_id="research-autogen-tools",
    name="Research AutoGen Tools",
    description="Tools exposed to the example AutoGen research agent.",
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

write_tool_contract(contract, "dist/autogen-tools.yaml")
