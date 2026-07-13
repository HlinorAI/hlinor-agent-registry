# Production Action Boundary Pattern

Generic pattern for separating analysis, preparation, approval, and external side effects in auditable agent systems.

## Purpose

Agent systems often mix safe internal work with actions that affect external systems. A production action boundary makes that transition explicit and inspectable.

The pattern is designed for actions such as sending a message, publishing content, modifying an external record, changing production configuration, triggering a paid operation, or notifying a real user.

## Boundary Rule

A production action must not execute just because an agent produced a plausible output.

Before dispatch, the runtime should verify:

- the project boundary matches the active task;
- the requested action is allowed by policy;
- the requested target scope matches the approved scope;
- required validations passed;
- required human or owner approval exists;
- caps, suppression, dedupe, and freshness checks passed when applicable;
- a pre-dispatch authorization check was recorded;
- an execution receipt will be emitted for allowed and blocked outcomes.

## Safe Internal Work

The following work is usually safe to run without production-action approval when it stays inside the task workspace:

- read public or approved internal inputs;
- classify or summarize records;
- generate review-only drafts;
- prepare reports;
- validate structured artifacts;
- produce review packets;
- emit audit events.

## Production Actions

The following actions should be approval-gated or denied by default:

- sending external messages;
- publishing or updating public content;
- creating, updating, or deleting records in an external system of record;
- modifying production configuration;
- changing scheduler or service manager state;
- spending money or consuming a paid quota beyond an approved cap;
- notifying a real user through a live channel.

## No-Send / Dry-Run Mode

A no-send or dry-run mode may count work that is ready for review, but it must not perform the production action.

This distinction is important:

```text
ready_for_action != action_executed
```

A dry-run can report `ready_for_action` items so the owner can review system quality. The production boundary still blocks side effects until explicit approval is granted.

## Required Evidence

A production-action boundary should produce or reference:

- task or workspace id;
- actor and requesting agent;
- requested action;
- target resource scope;
- policy decision;
- validation results;
- approval reference when required;
- pre-dispatch check;
- execution receipt;
- side-effect state.

## Failure Handling

If the boundary check fails, the action should be blocked before side effect and a receipt should be emitted.

Common failure outcomes:

- `blocked_missing_approval`;
- `blocked_policy_denied`;
- `blocked_scope_mismatch`;
- `blocked_validation_failed`;
- `blocked_cap_unavailable`;
- `blocked_suppression_match`;
- `blocked_stale_input`.

## Design Principles

- Prepare freely, dispatch carefully.
- Count review-ready work separately from executed work.
- Treat external side effects as a separate authority layer.
- Record blocked outcomes as first-class audit evidence.
- Never let approval for one scope silently authorize another scope.
