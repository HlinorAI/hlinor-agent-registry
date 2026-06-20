# Project Isolation Architecture

Project isolation is a core design principle in Hlinor.

Hlinor is intended to run multiple AI-assisted operational workflows without allowing one project to accidentally read, modify, leak, or reuse another project's state.

## Problem

AI agent systems often fail operationally when work from different projects is mixed together.

Common failure modes include:

* using the wrong customer, lead, or account context
* writing artifacts into another project's workspace
* applying one project's policies to another project
* reusing stale decisions from a previous run
* sending drafts or updates from the wrong identity
* losing track of which project approved which action
* allowing hidden memory to cross project boundaries

For business operations, these failures are not cosmetic. They can create privacy, trust, compliance, and operational risks.

## Isolation rule

A project must be treated as a bounded execution domain.

An agent working inside one project must not read from, write to, mutate, or depend on another project's operational state unless that cross-project action is explicitly defined and approved.

Default behavior:

```text
No shared mutable state across projects.
No hidden cross-project memory.
No implicit reuse of artifacts, decisions, contacts, or approvals.
```

## Isolated resources

Each project should own its own operational resources.

Examples:

* task workspaces
* ledgers
* approval records
* review packets
* generated artifacts
* contact records
* draft records
* suppression records
* run reports
* validation results
* policy bindings
* context snapshots

An implementation may store these resources in a shared physical system, but the logical project boundary must remain explicit and enforceable.

## Workspace boundary

A task workspace belongs to exactly one project.

A workspace should include enough metadata to make the boundary inspectable:

```text
project_id
workspace_id
task_id
department_id
agent_id
policy_set
approval_state
input_references
output_references
created_at
updated_at
```

Agents should not infer the project from path names, previous runs, chat history, or ambient context alone.

## Approval boundary

Approvals are project-scoped.

An approval granted in one project does not authorize action in another project.

Examples:

* approval to prepare a draft does not authorize sending it
* approval to contact one account does not authorize contacting another account
* approval to use one workspace does not authorize reading another workspace
* approval to operate in one project does not authorize cross-project enrichment

Approval records should include the project identifier and the scope of the approved action.

## Memory boundary

Durable memory must be project-aware.

A memory record should not be available to agents unless one of the following is true:

* the record belongs to the active project
* the record is part of a shared global policy
* the record has been explicitly promoted to a shared knowledge layer
* the current task has an approved cross-project reference

This prevents hidden state from influencing outputs across unrelated projects.

## Policy boundary

Policies may be global, project-specific, or department-specific.

The effective policy set for a task should be resolved explicitly.

A stricter policy should override a weaker one when conflict exists.

Example hierarchy:

```text
Global policy
  ↓
Project policy
  ↓
Department policy
  ↓
Task-specific constraint
```

## Allowed cross-project interaction

Cross-project interaction is not forbidden completely. It must be explicit.

Allowed examples:

* using a shared public schema
* using a shared validator definition
* using a shared policy template
* reading a global documentation page
* promoting a reusable lesson into an approved shared knowledge layer

Not allowed by default:

* copying private project state
* reusing contact lists
* reusing approval decisions
* mixing customer records
* writing reports into another project
* sending from another project's identity
* treating old project output as current evidence

## Audit requirements

Project boundary decisions should be auditable.

Important events should record:

```text
project_id
actor
department
agent
action
input_reference
output_reference
policy_reference
approval_reference
decision
reason
timestamp
```

This makes it possible to answer:

* which project did this action belong to?
* which policy allowed it?
* which approval authorized it?
* which artifact was produced?
* which state was read or written?
* was any cross-project reference used?

## Synthetic example

Two projects may use the same registry framework but must not share operational state.

```text
Project Alpha
  workspace: alpha/task-001
  approval: alpha/approval-001
  draft: alpha/draft-001

Project Beta
  workspace: beta/task-001
  approval: beta/approval-001
  draft: beta/draft-001
```

An agent working on Project Alpha may use the shared agent registry schema, but it may not read Project Beta's drafts, approvals, ledgers, or contact records.

## Design outcome

Project isolation makes agentic operations safer and easier to govern.

It helps ensure that:

* work remains attributable
* approvals remain scoped
* evidence remains attached to the correct task
* agents do not silently reuse unrelated context
* multiple projects can run in parallel without state contamination

In Hlinor, project isolation is not a convenience feature. It is part of the control layer.
