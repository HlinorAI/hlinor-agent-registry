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

## Detect agent-to-tool drift

Check a reviewed agent declaration against the tools exposed by its runtime:

```bash
hlinor-registry contract check \
  --agent examples/tool-contracts/customer-support-agent.yaml \
  --tools examples/tool-contracts/customer-support-tools.yaml
```

The command reports:

- `UNDECLARED_TOOL_SCOPE` when a tool exposes an action or resource scope the
  agent neither allows nor explicitly blocks;
- `STALE_ALLOW_PERMISSION` when an allowed pattern no longer overlaps any
  exported tool;
- `STALE_BLOCK_PERMISSION` when a blocked pattern no longer overlaps any
  exported tool.

An agent may deliberately grant a narrower resource scope than the tool can
technically address. That is least privilege, not drift. A tool that is only
covered by `blocked_actions` is also explicitly governed and does not produce
a finding.

Use JSON output in automation:

```bash
hlinor-registry contract check \
  --agent agent.yaml \
  --tools exported-tools.yaml \
  --format json
```

## Compare reviewed and observed contracts

Framework exporters can write the current runtime descriptor to a temporary
file. Compare it with the reviewed contract before merge or deployment:

```bash
hlinor-registry contract diff \
  --expected tool-contract.yaml \
  --observed exported-tool-contract.yaml
```

The comparison is keyed by stable tool ID and detects added or removed tools,
changed actions, input schemas, resource scopes, effects, annotations, contract
identity, and contract version. Tool order and order-insensitive sets such as
`required`, `effects`, and `resource_patterns` do not create false drift.
Descriptions and metadata remain documentation and do not affect the
governance comparison.

Both commands use CI-friendly exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Contracts are aligned |
| `1` | Valid inputs contain drift |
| `2` | An input is missing, unreadable, or invalid |

Treat exit `2` as a broken check, not as proof that governance denied anything.

## Runtime status

Tool Contracts are an authoring and synchronization contract in this release.
`PolicyChecker` does not read them and they do not change an agent's
permissions.

Framework exporters for LangChain and CrewAI can now target this stable
comparison format without coupling the drift engine to either framework.

See [Framework Tool Exporters](framework-exporters.md) for complete export and
CI drift-check examples.
