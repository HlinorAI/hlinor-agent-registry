# Framework Tool Exporters

Hlinor can export LangChain and CrewAI tools into the framework-neutral Tool
Contract format. Exporters read tool metadata and argument schemas. They never
invoke a tool.

Frameworks know the technical interface of a tool, but they do not reliably
know its security impact. Every tool therefore requires explicit
`ToolGovernance`. Hlinor will not guess that an unknown operation is read-only,
non-destructive, or safe.

## LangChain

Install the optional integration:

```bash
pip install "hlinor-registry[langchain]"
```

Export the same `BaseTool` objects supplied to the agent:

```python
from hlinor_registry import ToolGovernance, write_tool_contract
from hlinor_registry.integrations.langchain import (
    export_langchain_tool_contract,
)

contract = export_langchain_tool_contract(
    [search_tool, send_message_tool],
    contract_id="support-runtime-tools",
    name="Support Runtime Tools",
    description="Tools exposed to the production support agent.",
    version="1.0.0",
    owner="Support Platform Team",
    governance={
        "search_customers": ToolGovernance(
            read_only=True,
            destructive=False,
            idempotent=True,
            action="read_customer",
            resource_patterns=("customer/*",),
            effects=("database_read", "personal_data_access"),
        ),
        "send_message": ToolGovernance(
            read_only=False,
            destructive=False,
            idempotent=False,
            action="send_ticket_reply",
            resource_patterns=("ticket/*",),
            effects=("message_send", "external_system_change"),
        ),
    },
    revision="git-commit-or-build-id",
)

write_tool_contract(contract, "dist/exported-tools.yaml")
```

The exporter reads `name`, `description`, and `args_schema`. If `args_schema`
is absent, it uses LangChain's `get_input_schema()` contract.

## CrewAI

Install the optional integration:

```bash
pip install "hlinor-registry[crewai]"
```

```python
from hlinor_registry import ToolGovernance, write_tool_contract
from hlinor_registry.integrations.crewai import export_crewai_tool_contract

contract = export_crewai_tool_contract(
    [search_tool],
    contract_id="research-runtime-tools",
    name="Research Runtime Tools",
    description="Tools exposed to the research crew.",
    version="1.0.0",
    owner="Research Platform Team",
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

write_tool_contract(contract, "dist/exported-tools.json")
```

CrewAI input schemas are read from each `BaseTool.args_schema`.

## CI drift gate

Commit the reviewed contract and export a fresh observed contract in CI:

```bash
hlinor-registry contract diff \
  --expected registry/tool-contract.yaml \
  --observed dist/exported-tools.yaml

hlinor-registry contract check \
  --agent registry/agent.yaml \
  --tools dist/exported-tools.yaml
```

The first command detects framework tool changes. The second detects
permissions that no longer match the exported runtime.

## Fail-closed behavior

Export fails when:

- any framework tool lacks explicit governance metadata;
- governance metadata references a tool that is no longer present;
- tool names are duplicated;
- a name, description, action, or input schema is missing or unusable;
- an exported action or tool ID is not a valid Hlinor identifier;
- the final object fails Tool Contract validation.

JSON Schema defaults are preserved. If a framework schema omits
`additionalProperties`, the exporter writes `true`, matching the JSON Schema
default instead of silently claiming a stricter runtime interface.

`write_tool_contract` validates before writing and atomically replaces the
target. Supported outputs are `.yaml`, `.yml`, and `.json`.

## Security boundary

Export proves that a reviewed contract matches the framework objects passed to
the exporter. It does not prove that those are the only tools reachable by the
process. Applications must export the same collection supplied to the agent
runtime and must still place `PolicyChecker` or a governed wrapper before every
side effect.
