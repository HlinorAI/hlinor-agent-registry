# Department Handoff Architecture

A department handoff is the controlled transfer of work from one bounded operational unit to another.

In Hlinor, departments are not just labels. They define responsibility, scope, policy context, validation expectations, and output format.

A handoff makes the transition between departments inspectable and resumable.

## Purpose

Multi-step agentic workflows often fail when one stage passes vague or incomplete context to the next stage.

Common failure modes include:

* unclear next action
* missing evidence
* stale assumptions
* skipped validation
* wrong project context
* lost approval state
* duplicated work
* execution based only on chat history
* downstream agents guessing what upstream agents meant

A department handoff prevents this by making the transfer explicit.

## Core rule

A department should not rely on hidden context when receiving work from another department.

A receiving department should be able to inspect:

```text
what was done
why it was done
what evidence supports it
which validators passed or failed
which approvals exist
what remains blocked
what the next expected action is
```

If that information is missing, the receiving department should treat the handoff as incomplete.

## Relationship to task workspaces

Department handoff usually happens inside a task workspace.

The workspace provides the project boundary, task identity, artifacts, approvals, validation records, and current status.

The handoff record explains how responsibility moves from one department to another.

```text
Task Workspace
  ├── Input references
  ├── Evidence records
  ├── Validation results
  ├── Approval state
  ├── Artifacts
  └── Department handoff record
```

## Handoff identity

A handoff should have explicit identity metadata.

Recommended fields:

```text
handoff_id
project_id
workspace_id
task_id
source_department
target_department
created_at
created_by
status
```

The handoff should never depend only on file location, chat history, or implied execution order.

## Handoff payload

A handoff should include enough information for the target department to continue safely.

Recommended payload:

```text
handoff_reason
task_objective
current_status
input_references
output_references
evidence_references
validation_references
approval_references
policy_references
known_risks
blocked_items
next_expected_action
```

The goal is not to duplicate all workspace data. The goal is to point to the correct auditable records.

## Handoff status

A handoff may have its own status.

Example values:

```text
draft
ready
accepted
rejected
blocked
superseded
completed
```

A handoff marked `ready` means the source department believes the target department has enough information to proceed.

A handoff marked `accepted` means the target department has taken responsibility for the next step.

## Source department responsibility

The source department should provide:

* clear output
* evidence references
* validation state
* known limitations
* approval state
* recommended next action
* explicit reason for handoff

The source department should not hide uncertainty.

If the source department cannot validate an output, it should say so directly.

## Target department responsibility

The target department should verify that the handoff is usable before acting.

It should check:

* project boundary
* task identity
* policy set
* approval state
* input references
* validation results
* blocked conditions
* whether the requested action is inside its scope

If the handoff is incomplete, the target department should reject or block the handoff instead of guessing.

## Validation boundary

Validators should run before a handoff when the downstream department depends on their result.

Examples:

```text
Discovery → Contact QA
  requires: candidate record exists

Contact QA → Drafting
  requires: contact channel validated

Drafting → Review
  requires: draft artifact exists

Review → Operations
  requires: approval state is explicit
```

These are generic examples. A real implementation may define different validators and gates.

## Approval boundary

Approval state must travel with the handoff.

A downstream department should not assume that approval exists.

The handoff should make clear whether the next action is:

```text
allowed
blocked
requires human approval
requires owner approval
already approved
rejected
out of scope
```

Approvals should remain scoped to the project, task, and action.

## Policy boundary

The target department should resolve the effective policy set before acting.

Policy context may include:

```text
global policies
project policies
department policies
task-specific constraints
approval constraints
```

If policies conflict, the stricter or more specific policy should normally take precedence.

## Rejection and blocking

A department may reject or block a handoff.

Valid reasons include:

* missing required input
* failed validation
* unclear task objective
* missing approval
* wrong project boundary
* stale or superseded artifact
* action outside department scope
* policy conflict
* insufficient evidence

A rejected handoff should include a reason and, when possible, the required correction.

## Audit requirements

Important handoff events should be auditable.

Recommended audit fields:

```text
handoff_id
project_id
workspace_id
source_department
target_department
actor
action
decision
reason
input_reference
output_reference
validation_reference
approval_reference
timestamp
```

This allows the system to answer:

* who transferred responsibility?
* which department accepted the work?
* what evidence was available?
* what validation passed or failed?
* what approval allowed the next step?
* why was the handoff blocked or rejected?

## Synthetic example

```text
handoff_id: example-handoff-001
project_id: example-project
workspace_id: example-project/task-001
source_department: discovery
target_department: review
status: ready

handoff_reason:
  Discovery completed initial evaluation and prepared evidence for review.

input_references:
  - owner-request.md
  - candidate-record.json

output_references:
  - evidence-summary.md
  - validation-results.json

approval_state:
  requires_owner_approval

next_expected_action:
  Owner reviews the packet before any external action is taken.
```

This example is synthetic. It shows the structure of a handoff, not a production workflow.

## Design outcome

Department handoff keeps multi-department agent work controlled.

It reduces ambiguity, prevents hidden context transfer, and makes responsibility visible across the workflow.

In Hlinor, a handoff is not just a message. It is an auditable transition of responsibility.
