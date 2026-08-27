# Integration Compatibility

Hlinor integrations share one invocation contract:

1. Build one immutable `ActionRequest`.
2. Reload the persistent checker only when its bundle changes.
3. Evaluate the request exactly once.
4. Deliver the resulting `PolicyDecision` to the optional decision sink once.
5. Raise `GovernanceDeniedError` on denial without calling the wrapped tool.
6. Execute the wrapped sync or async tool only after an allowed decision.

## Tested framework versions

| Integration | Tested version | Python in CI | Contract |
| --- | --- | --- | --- |
| LangChain Core | 1.4.9 | 3.11 | `BaseTool`, sync/async, args schema, metadata, callbacks, Tool Contract export |
| CrewAI | 1.15.6 | 3.11 | `BaseTool`, sync/async, Pydantic lifecycle, args schema, Tool Contract export |
| Microsoft AutoGen Core | 0.7.5 | 3.11 | Public `BaseTool.schema` Tool Contract export |
| Custom Python | Standard library | 3.10–3.13 | Explicit JSON Schema Tool Contract export without invocation |
| Pydantic | 2.12.5 (CrewAI), 2.13.4 (LangChain) | 3.11 | Framework model lifecycle and private adapter state |
| Python decorator | Standard library | 3.10–3.13 | Native sync/async wrapper and checker injection |

The package metadata supports LangChain Core `>=1.4,<2.0` and CrewAI
`>=1.15,<2.0`, and AutoGen Core `>=0.7,<0.8`. CI pins the versions above so
compatibility does not drift when new framework releases appear.

## Shared adapter options

Every adapter supports:

- `checker`: inject a configured `PolicyChecker`, including production trust
  store and issuer requirements;
- `decision_sink`: receive the one decision created for each invocation;
- `request_factory`: create an application-specific `ActionRequest`;
- a persistent checker that calls `reload_if_changed()` before evaluation.

The shared gate also accepts an explicit `ExecutionScope` (static or derived
from trusted invocation context) and `require_execution_scope=True`. This is
implemented by the decorator, LangChain, and CrewAI governed wrappers. AutoGen
execution wrapping is not yet part of the supported compatibility contract.

`request_factory` receives an immutable `InvocationContext` containing the
agent, action, tool ID, environment, positional arguments, and keyword
arguments. Hlinor does not serialize arbitrary arguments automatically because
they may contain credentials, PII, non-deterministic objects, or unsupported
types. Applications that need argument-bound authorization should create a
safe digest or selected attributes explicitly.

The returned request must preserve the governed `agent_id`, `action`, and
`tool_id`. Changing any of those fields is rejected before policy evaluation.

## Denial behavior

All integrations raise the same `GovernanceDeniedError`. The exception includes
the exact `PolicyDecision`, request ID, request digest, bundle digest, reason
code, and decision ID.

`PolicyViolationError` remains available as a compatibility alias for
`GovernanceDeniedError`.

## LangChain

`GovernedTool` is a real `langchain_core.tools.BaseTool`. It preserves the
wrapped tool's input schema, name, description, tags, metadata, return behavior,
and callback flow. Wrap tools before passing them to a modern LangChain agent:

```python
from hlinor_registry.integrations.langchain import GovernedTool

safe_search = GovernedTool(
    tool=search_tool,
    agent_id="research-agent",
    action_name="search",
    bundle_path="bundle.json",
)
```

`GovernedAgent` remains as a compatibility helper for legacy executors exposing
a mutable `tools` collection. New applications should wrap each `BaseTool`
explicitly before agent construction.

`export_langchain_tool_contract` reads the same `BaseTool` objects without
invoking them and produces a validated Tool Contract. Governance properties
that LangChain cannot know must be supplied explicitly with `ToolGovernance`.

## CrewAI

Pass the complete CrewAI `BaseTool` when possible so Hlinor can preserve its
Pydantic input and result schemas:

```python
from hlinor_registry.integrations.crewai import GovernedCrewTool

safe_search = GovernedCrewTool(
    executor=search_tool,
    agent_id="research-agent",
    action_name="search",
    bundle_path="bundle.json",
)
```

Plain sync and async callables remain supported when callers provide `name` and
`description`.

`export_crewai_tool_contract` reads each `BaseTool.args_schema` without
invoking the tool. Governance properties that CrewAI cannot know must be
supplied explicitly with `ToolGovernance`.

See [Framework Tool Exporters](framework-exporters.md) for complete examples.

## Decorator

The decorator preserves whether the wrapped function is synchronous or
asynchronous:

```python
from hlinor_registry.integrations.decorators import governed


@governed("research-agent", "search", "bundle.json")
async def search(query: str) -> str: ...
```

Checker and decision-sink failures propagate before tool execution. This is
intentional fail-closed behavior.

## AutoGen and custom Python export

AutoGen `BaseTool` instances and explicit `CustomToolDescriptor` objects can be
exported to validated Tool Contracts without invoking them. These integrations
provide contract synchronization only. They are not execution wrappers and do
not create a runtime authorization boundary on their own.

See [Framework Tool Exporters](framework-exporters.md) for complete examples.
