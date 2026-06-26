# Hlinor Agent Registry

Open-source registry layer for auditable AI agent systems.

## Overview

Hlinor Agent Registry provides a structured way to define:

- Agents
- Departments
- Skills
- Validators
- Policies
- Execution boundaries

The goal is to make agentic systems easier to inspect, validate, and operate at scale.

## Why

Most AI agent frameworks focus on execution.

Hlinor Agent Registry focuses on governance:

- What agents exist
- What they are allowed to do
- Which skills they can use
- Which validations must pass
- How responsibilities are organized

## Planned Features

- Agent definitions
- Department registry
- Skill registry
- Validation registry
- Policy enforcement
- Audit-friendly metadata
- YAML and JSON configuration support

## Documentation

- [Execution model](docs/execution-model.md)
- [Approval model](docs/approval-model.md)
- [Audit trail](docs/audit-trail.md)
- [Control Layer architecture overview](docs/architecture/control-layer-overview.md)
- [Project isolation architecture](docs/architecture/project-isolation.md)

## Status

Early public release.

## License

Apache License 2.0
## Patterns

- [Autonomous production control loop pattern](docs/patterns/autonomous-production-control-loop.md)
- [Autonomous production control loop YAML example](examples/control-loops/autonomous-production-control-loop.yaml)

