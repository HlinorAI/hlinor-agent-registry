"""Export a custom Python tool as a reviewed Hlinor Tool Contract."""

from hlinor_registry import (
    CustomToolDescriptor,
    ToolGovernance,
    write_tool_contract,
)
from hlinor_registry.integrations.custom import export_custom_tool_contract


def search_web(query: str, limit: int = 10) -> list[str]:
    """Search an approved public web index."""
    return [f"Synthetic result for {query}"][:limit]


contract = export_custom_tool_contract(
    [
        CustomToolDescriptor(
            callable=search_web,
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        )
    ],
    contract_id="research-custom-tools",
    name="Research Custom Tools",
    description="Custom Python tools exposed to the example research agent.",
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

write_tool_contract(contract, "dist/custom-tools.yaml")
