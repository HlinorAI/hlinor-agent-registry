# Hlinor Approval Model v1

## Purpose

The Hlinor Approval Model defines how actions are approved before execution.

The goal is to allow autonomous operation while maintaining human oversight for sensitive or high-risk actions.

## Approval Flow

```text
Agent
  ↓
Request Action
  ↓
Policy Check
  ↓
Approval Required?
  ↓
Owner / Human Approval
  ↓
Execute Action
```

## Approval Levels

### Automatic

Actions may execute immediately when policies allow them.

Examples:

- search
- classify
- score
- summarize

### Human Approval

Actions require review from an authorized operator.

Examples:

- create external records
- modify production systems
- publish content

### Owner Approval

Actions require explicit owner authorization.

Examples:

- financial operations
- customer communications
- external outreach
- production deployment

## Policy Integration

Policies determine whether an action:

- is allowed
- is denied
- requires approval

Policies should be evaluated before execution.

## Approval Records

Every approval decision should generate an audit event.

An approval record may include:

- action identifier
- requesting agent
- timestamp
- approval level
- reviewer
- decision

## Failure Handling

If approval is denied:

- the action must not execute
- an audit event must be recorded
- the workflow may stop or request revision

## Design Goals

The approval model is designed to be:

- transparent
- auditable
- secure
- explainable
- compatible with autonomous systems
