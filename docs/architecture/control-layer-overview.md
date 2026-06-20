# Hlinor Control Layer Architecture

Hlinor is an agent governance and operations framework for running multi-department AI workflows with traceability, project isolation, and human oversight.

## High-level model

```text
Owner / Operator
  ↓
Control Layer
  ↓
Task Workspace
  ↓
Brain Layer
  ↓
Departments
  ├── Search / Discovery
  ├── Contact QA
  ├── Website / Fit QA
  ├── Drafting
  ├── Review
  └── CRM / Operations
```

## Core components

### Agent Registry

Defines the system structure:

* agents
* departments
* skills
* validators
* policies
* execution boundaries

### Control Layer

Provides a governed execution path for non-trivial work:

* task specification
* execution evidence
* review packets
* context snapshots
* resumable task workspaces

### Brain Layer

Stores durable operational context and project memory.

### Departments

Departments are bounded operational units. Each department has its own role, scope, policies, and handoff expectations.

## Why this matters

AI workflows fail operationally when they:

* lose context between runs
* mix data across projects
* perform unclear tasks
* create outputs without evidence
* bypass human approval
* cannot be resumed safely

Hlinor is designed to make agent work inspectable, resumable, and governable.

## Current implementation status

Working components:

* registry structure
* policy documentation
* control-layer task workspace pattern
* evidence capture pattern
* context snapshot pattern
* project isolation rules
* validator-oriented workflow design

## Intended use

Hlinor is intended for real business operations where AI agents need to work across multiple departments while remaining auditable and bounded.

Examples include:

* outreach workflows
* research workflows
* CRM support workflows
* website analysis workflows
* internal operational automation

## Design principles

* evidence before claims
* project isolation by default
* human approval for sensitive actions
* task resumability
* policy-defined execution boundaries
* no hidden cross-project memory
