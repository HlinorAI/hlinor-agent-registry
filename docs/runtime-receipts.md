# Runtime Bindings and Execution Receipts v1

## Purpose

Runtime bindings and execution receipts separate declared governance from
exercised authority.

The registry defines intent: agents, policies, validators, allowed actions, and
approval requirements. A runtime receipt records what actually happened, or what
was blocked, when a session tried to exercise authority.

## Responsibility Boundary

The registry is the source of declared intent and governance.

Examples:

- which actions a class of agent may request
- which policies must be evaluated
- which approvals are required
- which validators are expected
- which schemas describe auditable records

The runtime receipt is the source of truth for exercised authority.

Examples:

- whether a concrete session matched an approved binding
- whether the request was allowed, denied, expired, or required reapproval
- whether dispatch was blocked before side effect
- whether a side effect was attempted
- which registry version, policy bundle digest, tool descriptor digest,
  normalized argument digest, target scope, and approval or lease authorized the
  decision

## Runtime Binding

A runtime policy/session binding is a narrow authorization lease. It binds one
session to the approved registry version, policy bundle digest, tool descriptor
digest, normalized argument digest, target/resource scope, and approval or lease
id.

It does not grant broad authority to perform nearby work. A binding approved for
`read_account` does not authorize `update_account`. A binding approved for one
account record does not authorize another account record.

## Pre-dispatch Check

A pre-dispatch authorization check compares the observed runtime request with
the approved binding immediately before dispatch.

The check must compare:

- registry version
- policy bundle digest
- tool descriptor or schema digest
- normalized argument digest
- target/resource scope
- approval or lease validity

If any of these values drift, the request must be denied, marked expired, or
marked `reapproval_required` before dispatch.

## Execution Receipt

Every pre-dispatch result should produce an execution receipt, including
negative results. The receipt records:

- `authorization_result`: `allowed`, `denied`, `expired`, or
  `reapproval_required`
- `side_effect_state`: `blocked_before_side_effect` or `side_effect_attempted`
- `matched_approved_binding`: boolean
- registry version
- policy bundle digest
- tool descriptor or schema digest
- normalized argument digest
- target/resource scope
- approval or lease id

This receipt is append-only evidence of the authority actually exercised or
blocked by runtime.

## Drift Detection

Drift means the observed runtime request no longer matches the approved binding.

Drift examples:

- the registry version changed after approval
- the effective policy bundle changed after approval
- the tool descriptor or schema changed after approval
- normalized arguments changed after approval
- the target account, workspace, record, file, or operation changed after
  approval
- the approval or lease expired, was revoked, or was superseded

The runtime must treat drift as authorization failure or reapproval-required
state. Silent reuse would make the old approval appear to authorize a request the
reviewer never evaluated.

## No Silent Approval Reuse

Approval cannot be silently reused after registry, policy, tool, arguments, or
scope changes because each of those values can change the risk of the action.

An approval is evidence for the exact request that was reviewed. If the registry
version changes, the declared governance changed. If the policy bundle changes,
the effective rules changed. If the tool descriptor changes, the operation may
perform different work. If normalized arguments or target scope change, the
approved payload is no longer the observed payload.

The safe runtime behavior is to emit a receipt with `denied`, `expired`, or
`reapproval_required`, record `matched_approved_binding: false`, and block before
side effect unless fresh approval is granted.
