"""Export a CrewAI tool as a reviewed Hlinor Tool Contract."""

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from hlinor_registry import ToolGovernance, write_tool_contract
from hlinor_registry.integrations.crewai import export_crewai_tool_contract


class SearchInput(BaseModel):
    query: str = Field(description="Public web search query")
    limit: int = Field(default=10, ge=1, le=50)


class SearchTool(BaseTool):
    name: str = "search_web"
    description: str = "Search an approved public web index."
    args_schema: type[BaseModel] = SearchInput

    def _run(self, query: str, limit: int = 10) -> list[str]:
        return [f"Synthetic result for {query}"][:limit]


contract = export_crewai_tool_contract(
    [SearchTool()],
    contract_id="research-crewai-tools",
    name="Research CrewAI Tools",
    description="Tools exposed to the example research crew.",
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

write_tool_contract(contract, "dist/crewai-tools.yaml")
