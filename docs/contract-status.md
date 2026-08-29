# Contract status

Every schema in `registry/schema/` carries one of five statuses. The point of
this table is to remove a specific misreading: that a schema existing, or a
`validate-*` command existing, means the contract is checked somewhere in your
pipeline. For most of them it does not.

| Status | What it means |
| :--- | :--- |
| **enforced** | Participates in a `PolicyChecker` decision at runtime. |
| **compile-validated** | Read and validated by `hlinor-registry compile` when the manifest names the file. |
| **command-validated** | Has a `validate-*` CLI command. Never read by `compile`; checked only when you run that command yourself. |
| **runtime-emitted** | Produced by a runtime API and validated at its runtime boundary, but not loaded by `compile`. |
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
| `approval-token.yaml` | reference-only | — |
| `agent-delegation.yaml` | reference-only | — |
| `delegation-transport.yaml` | reference-only | — |
| `audit-event.yaml` | reference-only | — |
| `execution-receipt.yaml` | runtime-emitted + runtime shape-validated | — |
| `handoff.yaml` | reference-only | — |
| `pre-dispatch-authorization-check.yaml` | reference-only | — |
| `runtime-policy-session-binding.yaml` | reference-only | — |
| `task-workspace.yaml` | reference-only | — |

Two of twenty-five are enforced. Three reach `compile`. One is runtime-emitted
by the binding API with runtime shape validation, but no compile or standalone
CLI loading. Six have no command at all.

One contract is deliberately absent from this table. The Tool Contract is the
only one with a packaged JSON Schema — `hlinor_registry/schemas/tool-contract.schema.json`
rather than a reference YAML under `registry/schema/` — and it is validated by
`validate-tool-contract` and compared by `contract check` and `contract diff`.
It is validated by `validate-tool-contract`, compared by the drift commands,
and can be connected to an exact in-process callable through the binding MVP in
[`docs/runtime-binding.md`](runtime-binding.md). It is not independently
authenticated deployment provenance, a signed approval, or a tamper-evident
execution receipt; see SECURITY.md.

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

`pre-dispatch-authorization-check` and
`runtime-policy-session-binding` describe the signed/evidentiary part of the
chain that binds an authorization decision to the dispatch that follows it.
The in-process exact-object and argument-validation subset plus signed approval
and receipt primitives are implemented in `BoundTool`; deployment attestation
and independent receipt collection remain proposed in
`docs/rfcs/0001-trusted-tool-contract-runtime-binding.md`.
The schemas exist so the remaining proposal has a concrete shape to argue
about, not because those schemas are directly enforced by `PolicyChecker`.

Listing a schema here as reference-only is the honest state, not a roadmap
promise.
