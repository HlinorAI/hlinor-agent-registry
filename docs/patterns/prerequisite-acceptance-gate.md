# Prerequisite Acceptance Gate Pattern

Generic pattern for enforcing a mandatory prerequisite before a candidate item may be accepted into a pipeline.

## Problem

Multi-stage agent pipelines often promote items downstream before a required prerequisite has been verified. The result is wasted downstream effort, inflated acceptance counts, and items reaching approval or production stages that were never eligible.

## Gate Rule

A pipeline may declare one or more acceptance prerequisites. An item is an accepted item only after every declared prerequisite is verified.

Required order:

1. Discover the candidate item.
2. Run basic fit checks.
3. Verify each declared prerequisite.
4. If any prerequisite is not verified, stop with a terminal skip status (for example `prerequisite_missing_skipped`).
5. Only a verified item becomes an accepted item and may consume downstream processing.

## Fail-Closed Behavior

A prerequisite that is missing, unknown, stale, ambiguous, failed, or skipped is treated as not verified.

```text
prerequisite_verified != true  →  not verified
```

No fallback, retry heuristic, or downstream stage may promote an unverified item.

## Downstream Protection

An unverified item must not:

- be counted as an accepted item in reports or metrics;
- enter materialization or artifact-generation stages;
- consume expensive downstream resources (model calls, browser rendering, paid quota);
- enter review packets, approval queues, or any production-action stage.

## Accepted-Item Definition

An accepted item means all of the following are true:

- the item was discovered through a live, current source;
- basic fit checks passed;
- every declared acceptance prerequisite is explicitly verified.

Without verified prerequisites, there is no accepted item.

## Audit Requirements

Each gate decision should emit an audit event recording the item identifier, the prerequisite checked, the verification result, and the resulting status. Skip statuses are first-class evidence, not silent drops.

## Relationship to Other Patterns

This gate runs before the [production action boundary](production-action-boundary.md). The boundary controls whether an accepted item may cause an external side effect; this gate controls whether an item may be accepted at all.
