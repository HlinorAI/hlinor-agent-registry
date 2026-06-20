# Task Workspace Architecture

A task workspace is the bounded working area for one non-trivial unit of agentic work in Hlinor.

It gives agents a controlled place to read task inputs, produce artifacts, record evidence, track approvals, and resume work safely.

## Purpose

Agentic work becomes difficult to govern when it happens only inside chat history, temporary prompts, or unstructured logs.

A task workspace solves this by making work:

* scoped to one project
* tied to one task
* inspectable after execution
* resumable across runs
* auditable through references
* bounded by policy and approval state

The workspace is not just a folder. It is a control boundary.

## Relationship to the Control Layer

The Control Layer uses a task workspace to coordinate work between owner intent, project policies, department execution, evidence capture, and review.

```text
Owner request
  ↓
Task specification
  ↓
Task workspace
  ↓
Department execution
  ↓
Evidence and artifacts
  ↓
Review or next handoff
```

The workspace should contain enough structure for another agent, reviewer, or operator to understand what happened without relying on hidden context.

## Workspace identity

Each workspace should have explicit identity metadata.

Recommended fields:

```text
project_id
workspace_id
task_id
task_type
owner_request_reference
department_id
agent_id
policy_set
approval_state
created_at
updated_at
status
```

Agents should not infer workspace identity from ambient context, path names, or previous conversation state alone.

## Project boundary

A workspace belongs to exactly one project.

The active project boundary determines which records, policies, approvals, and artifacts may be used.

A workspace must not silently read from or write into another project's operational state.

This supports the project isolation model:

```text
one workspace → one task → one project boundary
```

## Workspace contents

A task workspace may contain or reference:

* task specification
* input references
* context snapshot
* execution notes
* evidence records
* generated artifacts
* validation results
* approval records
* review packet
* handoff record
* final status report

The exact physical layout can vary by implementation, but the logical structure should remain explicit.

## Context snapshot

A context snapshot captures the task-relevant state available at the time of execution.

It should answer:

* what was the task?
* which project was active?
* which policies applied?
* what inputs were used?
* what assumptions were made?
* what prior state was referenced?
* what approvals existed before action?

A context snapshot helps prevent agents from depending on invisible memory.

## Evidence records

Evidence records connect claims to observable work.

For meaningful actions, the workspace should preserve references to:

```text
input
decision
output
validator result
policy reference
approval reference
timestamp
```

The goal is not to store everything forever. The goal is to make important decisions inspectable.

## Generated artifacts

Artifacts are outputs created during the task.

Examples:

* reports
* summaries
* draft content
* structured records
* validation output
* review packets
* exported files
* implementation notes

Artifacts should be stored or referenced inside the workspace instead of being scattered across unrelated project state.

## Approval state

A workspace should track approval state explicitly.

Common states:

```text
not_required
required
requested
approved
rejected
expired
superseded
```

Approval should be scoped to the task and project.

An approval to perform one action inside a workspace should not automatically authorize a different action.

## Validation state

Validators should write their results into the workspace or into an auditable record referenced by the workspace.

Validation records should include:

```text
validator_id
input_reference
result
reason
timestamp
blocking
```

This allows a reviewer to distinguish between completed work, blocked work, failed validation, and work that still requires review.

## Resumability

A workspace should make interrupted work recoverable.

A later run should be able to determine:

* what task was being performed
* what has already been done
* which artifacts are current
* which outputs are superseded
* what failed or blocked progress
* what the next safe action is

Resumability is especially important when work spans multiple departments, tools, or approval steps.

## Status model

A workspace should expose a clear status.

Example status values:

```text
created
in_progress
blocked
awaiting_approval
ready_for_review
completed
failed
superseded
cancelled
```

Status should reflect the current operational state, not just whether files exist.

## Department handoff

A task workspace can support handoff between departments.

A handoff should not rely on informal chat context alone.

It should preserve:

```text
source_department
target_department
handoff_reason
input_reference
output_reference
validation_state
approval_state
next_expected_action
```

A detailed department handoff model is defined separately from the workspace itself.

## Safety invariants

A task workspace should follow these invariants:

* one active project boundary
* one primary task objective
* explicit policy set
* explicit approval state
* no hidden cross-project memory
* evidence for meaningful claims
* validation records for important gates
* resumable final state
* clear distinction between draft, approved, and executed actions

## Synthetic example

```text
workspace_id: example-project/task-001
project_id: example-project
task_type: research-and-review
department_id: discovery
approval_state: required
status: ready_for_review

inputs:
  - owner_request.md
  - candidate-record.json

outputs:
  - evidence-summary.md
  - validation-results.json
  - owner-review-packet.md

next_action:
  - wait for owner approval
```

This example does not define a production workflow. It shows the workspace pattern as a governance boundary.

## Design outcome

Task workspaces help Hlinor keep agentic work controlled, inspectable, and recoverable.

They reduce dependence on hidden chat context and make operational work safer to review, resume, and audit.
