# Hlinor Agent Registry

Open-source registry layer for auditable AI agent systems.

## Overview

Hlinor Agent Registry provides a structured way to define agents, departments, skills, validators, policies, and execution boundaries.

Most AI agent frameworks focus on execution. This project focuses on governance:

- What agents exist
- What they are allowed to do
- Which skills they can use
- Which validations must pass
- How responsibilities are organized

## Features

- Registry schemas for agents, departments, skills, validators, and policies
- Runtime binding, pre-dispatch authorization check, and execution receipt schemas
- Production action boundary and control loop schemas
- Agent lifecycle operating modes with transition gates and receipt schemas
- `hlinor-registry` CLI for validating and inspecting registry YAML files
- Synthetic YAML examples validated by the test suite

## Planned

- Policy enforcement tooling
- Department and skill registry population
- JSON configuration support

## Documentation

- [Execution model](docs/execution-model.md)
- [Approval model](docs/approval-model.md)
- [Runtime bindings and execution receipts](docs/runtime-receipts.md)
- [Audit trail](docs/audit-trail.md)
- [Control Layer architecture overview](docs/architecture/control-layer-overview.md)
- [Project isolation architecture](docs/architecture/project-isolation.md)
- [Task workspace architecture](docs/architecture/task-workspace.md)
- [Department handoff architecture](docs/architecture/department-handoff.md)

## Patterns

- [Agent lifecycle operating modes](docs/patterns/agent-lifecycle-operating-modes.md)
- [Lifecycle mode transition gates](docs/patterns/lifecycle-mode-transition-gates.md)
- [Production action boundary](docs/patterns/production-action-boundary.md)
- [Autonomous production control loop](docs/patterns/autonomous-production-control-loop.md)
- [Prerequisite acceptance gate](docs/patterns/prerequisite-acceptance-gate.md)

## Engineering Policies

- [Dependency Reuse Policy](docs/policies/dependency-reuse-policy.md)

## CLI Usage

- `hlinor-registry validate <path>`
- `hlinor-registry validate-agent <path>`
- `hlinor-registry validate-department <path>`
- `hlinor-registry validate-policy <path>`
- `hlinor-registry validate-skill <path>`
- `hlinor-registry validate-validator <path>`
- `hlinor-registry validate-runtime-example <path>`
- `hlinor-registry validate-production-action-boundary-example <path>`
- `hlinor-registry validate-lifecycle-map <path>`
- `hlinor-registry validate-lifecycle-receipt <path>`
- `hlinor-registry validate-lifecycle-schema <path>`
- `hlinor-registry inspect <path>`

## Status

Early public release.

## License

Apache License 2.0

### Execution context validation

```bash
hlinor-registry validate-execution-context \
  examples/execution-context/verified-host-native-execution-context.yaml

The execution-context contract distinguishes declared runtime markers from verified
capabilities and blocks live or production-sensitive operations when the current
environment is unverified or restricted.
