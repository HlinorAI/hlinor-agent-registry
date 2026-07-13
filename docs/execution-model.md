# Hlinor Execution Model v1

## Purpose

The Hlinor Execution Model defines how work moves through an auditable AI agent system.

It describes the relationship between departments, agents, skills, validators, policies, and actions.

## Core Flow

```text
Department
  ↓
Agent
  ↓
Skill
  ↓
Validator
  ↓
Policy
  ↓
Action
```

## Department

A department owns a functional area of work.

Examples:

- Search
- Data review
- Content review
- Records operations

A department may define:

- agents
- shared skills
- shared validators
- shared policies
- approval boundaries

## Agent

An agent performs a specific role inside a department.

An agent may:

- invoke skills
- produce outputs
- request actions
- emit audit events

## Skill

A skill is a reusable capability available to one or more agents.

Examples:

- search
- classify
- score
- validate
- draft
- summarize

## Validator

A validator checks whether an output is acceptable before work continues.

A validator may:

- pass
- fail
- block progression
- require review

## Policy

A policy defines what is allowed, blocked, or approval-gated.

A policy may:

- allow an action
- deny an action
- require human approval
- require owner approval

## Action

An action is an operation requested by an agent.

Examples:

- search
- classify
- generate draft
- create record
- notify owner
- send message

High-risk actions should be blocked or approval-gated by policy.

## Execution Sequence

1. A department receives work.
2. The department selects an agent.
3. The agent invokes one or more skills.
4. Validators check the result.
5. Policies evaluate the requested action.
6. If allowed, the action executes.
7. An audit event is recorded.

## Design Goals

The execution model is designed to be:

- auditable
- explainable
- policy-aware
- approval-aware
- reusable across different agent systems
