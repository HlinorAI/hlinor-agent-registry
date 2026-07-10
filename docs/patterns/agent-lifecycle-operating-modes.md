# Agent Lifecycle Operating Modes

## Purpose

This document defines five lifecycle operating modes for auditable agent systems and workflows:

- Prototyper
- Builder
- Sweeper
- Grower
- Maintainer

The goal is to prevent role confusion, reduce operational chaos, and make every agentic task accountable to the correct stage of product or system maturity.

These modes are not separate mandatory agents. They are operating modes that can be assigned to agents, workflows, scripts, or controlled tasks.

## Core Principle

Every controlled task must declare its lifecycle mode before execution.

A task must not silently switch modes. If the work changes mode, the task must produce a handoff, receipt, or request for classification before continuing.

Examples:

- A Prototyper may generate ideas, but must not modify production.
- A Builder may implement, but must not expand product scope.
- A Sweeper may simplify, but must not change business logic without approval.
- A Grower may run improvement iterations, but must define metrics.
- A Maintainer may protect reliability, but must identify specific operational risks.

## Lifecycle Flow

```text
PROTOTYPER
  -> BUILDER
  -> SWEEPER
  -> GROWER
  -> MAINTAINER
```

This is the canonical maturity path, not an automatic runtime sequence. Transitions are gated: a task may not move to the next mode merely because prior work exists. It must meet the transition evidence requirements in [lifecycle-mode-transition-gates.md](./lifecycle-mode-transition-gates.md).

For any other target declared in `valid_handoff_targets`, define transition-specific `allowed_when` and `required_evidence` entries before handoff.

## Mode Summary

| Mode | Primary purpose | Main risk | Control rule |
| --- | --- | --- | --- |
| Prototyper | Generate hypotheses, directions, and experiments | Producing vague or unbounded ideas | Every idea needs a success signal and kill criteria |
| Builder | Turn approved work into a working implementation | Expanding scope or overbuilding | Build only against approved constraints |
| Sweeper | Reduce complexity while preserving behavior | Breaking working behavior for cleanup | Do not change business logic without approval |
| Grower | Improve working systems through measured iterations | Optimizing without evidence | Every iteration needs a metric and baseline |
| Maintainer | Protect security, reliability, cost, and operations | Blocking progress without a concrete risk | Name evidence, risk, and recovery path |

## Operating Rule

A task that cannot identify its lifecycle mode must stop and request classification before making changes.

## Receipt Requirements

Every lifecycle task should produce a receipt with:

- `task_id`
- `lifecycle_mode`
- `input_refs`
- `output_refs`
- `changed_files`
- `checks_run`
- `risks_detected`
- `next_recommended_mode`
- `stop_reason`
- `secrets_touched`
- `production_behavior_changed`
- `external_messages_sent`
- `services_restarted`

The receipt records what actually happened. It must not claim checks, evidence, or side-effect status that cannot be verified.

## Safety Boundary

This lifecycle model is a documentation, schema, and control layer. It must not change runtime behavior by itself. It must not touch secrets, send external messages, modify CRM or messaging systems, restart services, or expose private commercial logic in public files.
