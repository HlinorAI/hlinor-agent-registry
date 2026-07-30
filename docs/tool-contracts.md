# Tool Contracts

A Tool Contract is a framework-neutral description of the tools an agent
runtime can invoke. It gives governance review and future drift detection one
stable input instead of asking every integration to invent its own descriptor.

The contract is declarative. It does not import agent code, execute tools, or
grant permission. Agent action lists and compiled policies remain the runtime
authorization source.

## Validate a contract

Tool Contracts may be written as YAML or JSON:

```bash
hlinor-registry validate-tool-contract \
  examples/tool-contracts/customer-support-tools.yaml
```

Python applications that need a fail-closed loader can use:

```python
from hlinor_registry import load_tool_contract

contract = load_tool_contract("tool-contract.yaml")
```

`load_tool_contract` raises `ToolContractValidationError` rather than returning
partially usable data.

The canonical JSON Schema is distributed with the package at
`hlinor_registry/schemas/tool-contract.schema.json`. It uses JSON Schema Draft
2020-12.

## Contract shape

```yaml
schema_version: "1.0"
type: tool_contract
id: support-tools
name: Support Tools
description: Tools exposed to the support agent runtime.
version: "1.0.0"

tools:
  - id: customer.lookup
    action: read_customer
    description: Read one customer profile.
    input_schema:
      type: object
      properties:
        customer_id:
          type: string
      required:
        - customer_id
      additionalProperties: false
    resource_patterns:
      - "customer/*"
    effects:
      - database_read
      - personal_data_access
    annotations:
      read_only: true
      destructive: false
      idempotent: true

metadata:
  owner: Support Platform Team
  source: manual
```

### Root fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Version of the Hlinor Tool Contract format |
| `id` | Stable identity of this contract |
| `version` | Semantic version of the described tool set |
| `tools` | Complete tool descriptors exported by the runtime |
| `metadata.owner` | Team accountable for keeping the contract current |
| `metadata.source` | Exporter or manual source that produced the contract |

When present, `metadata.repository` must be an HTTPS URL. Local paths and
credentials do not belong in a portable contract.

### Tool fields

| Field | Meaning |
| --- | --- |
| `id` | Stable implementation-facing tool identity |
| `action` | Concrete Hlinor action supplied to `ActionRequest` |
| `input_schema` | Draft 2020-12 JSON Schema for tool arguments |
| `resource_patterns` | Resource scopes the tool may address; empty means unscoped |
| `effects` | Observable data access or side effects |
| `annotations` | Explicit read-only, destructive, and idempotency claims |

Action names are concrete identifiers. Wildcards belong in an agent's
`allowed_actions` or `blocked_actions`, not in `action`.

Every input schema must explicitly declare `properties`, `required`, and
`additionalProperties`. This prevents an omitted JSON Schema default from
silently making undeclared arguments acceptable.

## Fail-closed rules

Validation rejects:

- unknown fields;
- unsupported schema versions;
- duplicate or case-colliding tool IDs;
- case-colliding action names;
- wildcard action names;
- malformed resource patterns;
- invalid nested JSON Schemas;
- required arguments absent from `properties`;
- YAML-only values such as dates, NaN, or infinity;
- `read_only: true` combined with a mutating effect;
- destructive tools without a declared mutating effect.

These checks make a malformed descriptor unusable rather than allowing drift
analysis to proceed with missing or ambiguous information.

## Runtime status

Tool Contracts are an authoring and synchronization contract in this release.
`PolicyChecker` does not read them and they do not change an agent's
permissions.

The next package adds deterministic comparison between a Tool Contract and an
agent declaration. Framework exporters for LangChain and CrewAI follow after
that comparison contract is stable.
