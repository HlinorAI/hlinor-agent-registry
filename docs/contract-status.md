# Contract status

Every schema in `registry/schema/` carries one of four statuses. The point of
this table is to remove a specific misreading: that a schema existing, or a
`validate-*` command existing, means the contract is checked somewhere in your
pipeline. For most of them it does not.

| Status | What it means |
| :--- | :--- |
| **enforced** | Participates in a `PolicyChecker` decision at runtime. |
| **compile-validated** | Read and validated by `hlinor-registry compile` when the manifest names the file. |
| **command-validated** | Has a `validate-*` CLI command. Never read by `compile`; checked only when you run that command yourself. |
| **reference-only** | No CLI command, not read by `compile`. Vocabulary for reviewers and for your own tooling. |

`compile` accepts three entity types from the manifest — `agent`, `policy` and
`capability`. Nothing else reaches it. See `hlinor_registry/cli.py`, the
`entity_type` branch in `cmd_compile`.

## The table

| Schema | Status | CLI command |
| :--- | :--- | :--- |
| `agent.yaml` | enforced + compile-validated | `validate-agent`, `validate` |
| `policy.yaml` | enforced + compile-validated | `validate-policy` |
| `capability.yaml` | compile-validated | `validate-capability-registration` |
| `action-preflight.yaml` | command-validated | `validate-action-preflight` |
| `capability-verification.yaml` | command-validated | `validate-capability` |
| `department.yaml` | command-validated | `validate-department` |
| `evidence-claim-binding.yaml` | command-validated | `validate-evidence-claim` |
| `execution-context.yaml` | command-validated | `validate-execution-context` |
| `failure-circuit-breaker.yaml` | command-validated | `validate-circuit-breaker` |
| `lifecycle-mode.schema.yaml` | command-validated | `validate-lifecycle-schema` |
| `lifecycle-receipt.schema.yaml` | command-validated | `validate-lifecycle-receipt` |
| `lifecycle-transition.schema.yaml` | command-validated | `validate-lifecycle-map` |
| `production-action-boundary.yaml` | command-validated | `validate-production-action-boundary-example` |
| `protected-resource-boundary.yaml` | command-validated | `validate-protected-resource-boundary` |
| `skill.yaml` | command-validated | `validate-skill` |
| `validator.yaml` | command-validated | `validate-validator` |
| `audit-event.yaml` | reference-only | — |
| `execution-receipt.yaml` | reference-only | — |
| `handoff.yaml` | reference-only | — |
| `pre-dispatch-authorization-check.yaml` | reference-only | — |
| `runtime-policy-session-binding.yaml` | reference-only | — |
| `task-workspace.yaml` | reference-only | — |

Two of twenty-two are enforced. Three reach `compile`. Six have no command at
all.

One contract is deliberately absent from this table. The Tool Contract is the
only one with a packaged JSON Schema — `hlinor_registry/schemas/tool-contract.schema.json`
rather than a reference YAML under `registry/schema/` — and it is validated by
`validate-tool-contract` and compared by `contract check` and `contract diff`.
It is a reviewed description of a tool surface, not a runtime boundary; see
SECURITY.md.

## Where enforcement actually happens

`enforced` above means something narrow, and the README's runtime table is the
authority on it. `PolicyChecker.evaluate()` answers two questions: whether the
action on that resource is permitted by the agent's allow and block lists, and
whether the typed policies triggered by it are satisfied for that specific
request. A `capability.yaml` file compiles into the bundle as inventory; no
decision reads it.

## Known naming inconsistencies

The command names do not map cleanly onto the schema names, and that is a
usability defect rather than a deliberate design:

- `validate-capability` validates **capability verification**, not
  `capability.yaml`. The one that validates `capability.yaml` is
  `validate-capability-registration`.
- `validate-production-action-boundary-example` and `validate-runtime-example`
  validate example documents rather than the contract shape.
- `validate` is an alias for `validate-agent`.

Renaming these is a breaking change to the CLI surface and is deferred to the
next major version. Until then, this table is the mapping.

## Why several contracts stop at reference-only

`execution-receipt`, `pre-dispatch-authorization-check` and
`runtime-policy-session-binding` describe a chain that binds an authorization
decision to the dispatch that follows it. That chain is proposed in
`docs/rfcs/0001-trusted-tool-contract-runtime-binding.md` and is **not
implemented**. The schemas exist so the proposal has a concrete shape to argue
about, not because anything reads them.

Listing a schema here as reference-only is the honest state, not a roadmap
promise.
