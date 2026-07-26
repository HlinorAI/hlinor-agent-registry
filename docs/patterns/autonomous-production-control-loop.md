# Autonomous Production Control Loop Pattern

Generic pattern for running autonomous agents through bounded production control loops.

## Control Loop

- scheduled trigger
- production service
- external state reconcile
- review-only pending work creation
- prior-cycle queue selection
- guarded external action
- completed action reconcile
- scoped post-action validation
- local ledger validation
- next-cycle queue preparation

## Boundary

External actions require project boundary, approved service manager launch, production-action flag, available cap, suppression check, and validation.

## Stale Queue Recovery

If an external reference becomes unavailable, mark the item stale, record an audit event, skip it, and continue processing valid items.

## Project Isolation

Reports, ledgers, exports, queues, suppression records, audit events, service names, and scheduler names stay inside the owning project boundary.
