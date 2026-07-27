# Registry

This is where registry entries live. The five directories are not a taxonomy to
admire — they are the shape of a working set of contracts, and each one holds a
small entry you can copy.

The entries cross-reference each other on purpose. Read them in this order and
the model explains itself:

| File | What it establishes |
| --- | --- |
| `departments/support.yaml` | A department, its agents, and the controls they all inherit |
| `agents/ticket-triage-agent.yaml` | One agent, its action boundary, and what it declares |
| `skills/classify-ticket.yaml` | A capability the agent may use, with inputs and required permissions |
| `validators/ticket-input-validator.yaml` | Checks an input must pass before the agent acts on it |
| `policies/no-customer-pii-in-logs.yaml` | A named constraint and how it is meant to be enforced |

## What is enforced and what is not

Only `allowed_actions` and `blocked_actions` on an agent are evaluated at
runtime by `PolicyChecker`. Skills, validators and the `policies` list are
authoring contracts: validated when you compile, useful as a shared vocabulary
for review, and read by no decision.

This is stated at length in
[What is enforced at runtime](../README.md#what-is-enforced-at-runtime). It is
repeated here because this directory is where someone would most reasonably
assume otherwise.

## Adding your own

Validate anything you add before compiling it:

```bash
hlinor-registry validate-agent registry/agents/your-agent.yaml
hlinor-registry validate-department registry/departments/your-department.yaml
hlinor-registry validate-skill registry/skills/your-skill.yaml
hlinor-registry validate-validator registry/validators/your-validator.yaml
hlinor-registry validate-policy registry/policies/your-policy.yaml
```

An entry is not compiled because it sits in this directory. A bundle contains
exactly what its manifest lists, and nothing else:

```yaml
# registry.yaml
policies:
  - path: "registry/agents/ticket-triage-agent.yaml"
```

## Relationship to `examples/`

`examples/` holds larger, scenario-shaped files illustrating a pattern from
`docs/patterns/`: control loops, execution contexts, receipts. They are read,
not adopted.

The entries here are the opposite — minimal, generic, meant to be copied and
edited. Every one is validated in CI, so if a schema changes and these stop
being correct, the build says so.

## Schemas

`schema/` holds the YAML schema for every contract type. They document the
shape of an entry. Validation is implemented in `hlinor_registry/validator.py`
rather than driven by these files, so treat them as reference rather than as
the enforcing artifact.
