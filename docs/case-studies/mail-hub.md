# Case Study: Governing a Production MCP Mail Agent

## Problem

Hlinor Mail Hub aggregates independent email providers and exposes read tools and
internal work operations through MCP. Editing an internal draft or resolving a
conversation changes persisted state. Tool availability alone does not establish
that an authenticated agent may perform that operation in a particular mailbox.

Mail Hub uses Registry 0.11.0 as its policy enforcement library. This is a real
consumer integration; Registry remains a framework-neutral component that can be
used without Mail Hub.

## Architecture

```text
ChatGPT / Agent → MCP request → Mail Hub authenticated dispatcher
                                      │
                                      ▼
                           Registry GovernanceGate
                           ActionRequest → PolicyChecker
                                      │
                 ┌────────────────────┴───────────────────┐
                 ▼                                        ▼
          allowed + audit                           denied + provenance
                 │                                        │
                 ▼                                        ▼
       Mail Hub validation / operation                reject request
```

Registry is called in-process, not as a separate network service. Mail Hub derives
agent/actor identity from the authenticated principal and constructs the action,
tool, mailbox/thread/draft resource, request/session IDs and arguments digest.
Production loads a signed production policy bundle. The Registry decision is
recorded before the protected operation; Mail Hub also owns input validation,
mailbox capabilities, database transactions and mutation auditing.

## Real integration and sanitized examples

Source review of Mail Hub's Stage 4/5 adapter and policy confirms `update_draft`
and `mark_resolved` are allowlisted for its work agent in configured mailbox
scopes. The draft-only principal has a narrower `create_draft` capability;
the read principal cannot gain write permission from email content.

The [minimal synthetic policy](../../examples/mail-hub/agent.yaml) preserves
these boundary shapes without exporting production policy or identifiers.
Its [executable cases](../../examples/mail-hub/policy-tests.yaml) produce:

| Request | Synthetic fixture decision | Boundary illustrated |
| --- | --- | --- |
| `update_draft` / `mark_resolved`, mailbox 1 | `allowed`, `EXPLICITLY_ALLOWED` | Scoped internal operations |
| `unknown_operation` or mailbox 2 | `denied`, `ACTION_NOT_ALLOWLISTED` | No implicit authority |
| Agent `approve_draft` | `denied`, `ACTION_BLOCKLISTED` | Protected owner operation |
| `send_external_email`, approval for another resource | `denied`, `APPROVAL_REQUIRED` | Approval must match the request |

The `approve_draft` block is an explicit synthetic representation of Mail Hub's
owner-only dispatcher protection, not a copy of its production Registry policy.
Missing approval signals yield `POLICY_SIGNAL_MISSING` in this fixture.
**`APPROVAL_REQUIRED` is a reason code on a denied decision, not a third
`DecisionResult`.** The caller may arrange an approval flow and retry a separately
verified request; Registry does not operate an approval UI or send mail.

## Fail-closed behavior

Strict policy denies actions or resources absent from the allowlist. Unknown MCP
tools can also be rejected by Mail Hub before Registry; do not assume every
malformed request reaches the policy checker. Mail Hub rejects unavailable,
wrong-environment, unsigned-required or tampered policy bundles. Its mutation
transaction cannot commit when the required audit write fails.

The public [policy tests](../../tests/test_policy_checker.py) cover policy
semantics and signed bundle validation; [gate tests](../../tests/test_integration_gate.py)
cover denial before dispatch and exact decision emission. They establish library
behavior, not an independent reproduction of the private deployment.

## Auditability and evidence

Registry decisions carry `decision_id`, action/agent identity, result/reason,
`request_digest`, `bundle_digest`, checked time, matched pattern/policy IDs,
enforcement mode, revisions, compiler/schema versions and signature provenance.
Mail Hub stores that provenance alongside its internal mutation audit. Note or
draft text is not included in that mutation record. This integration uses
Mail Hub's PostgreSQL audit; it does not claim every mutation has a Registry
signed execution receipt or independent external collector.

[Sanitized evidence notes](mail-hub-evidence.md) identify the reviewed source
and acceptance boundaries. Saved acceptance reports from 2026-10-04 verify
internal draft/state operations, policy negative paths and restart persistence.
This document does not claim a new live production check.

## Reproduce the public policy example

From a checkout with the development dependencies installed:

```bash
python -m hlinor_registry.cli compile --manifest examples/mail-hub/registry.yaml --output /tmp/mail-hub-reference-bundle.json
python -m hlinor_registry.cli test-policies --bundle /tmp/mail-hub-reference-bundle.json --tests examples/mail-hub/policy-tests.yaml
python -m pytest -q
```

These commands evaluate synthetic policy only and never connect to a mailbox.
Approval signals in fixtures are test inputs. Production Mail Hub derives them
only after checking a signed owner token, request binding and durable replay
state; caller text is not proof.

## Why it matters and limits

Registry separates technical tool access from capability / operation
authorization in a verified scope. Mail Hub applies the same integration pattern
to independent consumers: Registry governs internal operations; ScopeGuard
reviews communication evidence; SheetSentry validates selected spreadsheet
attachments. Analysis findings do not grant execution authority.

See the independent [ScopeGuard project](https://github.com/HlinorAI/scopeguard).
The same policy boundary is intended to govern higher-risk operations such as
external message delivery. Its production acceptance is described below.

## Controlled Send: production acceptance

The two-level proof for this component now extends from public reproducibility
to production evidence. The same policy boundary governs outbound delivery,
which is enabled for exactly one mailbox and remains gated end-to-end:

- an agent can draft and request, but cannot approve: the approval tool is
  absent from the agent-facing tool catalog, the service gate requires the
  separate owner principal, and the Registry policy does not list approval
  actions for the work agent;
- an owner approval is bound to one draft revision and its content digest, is
  single-use, expires, and is consumed atomically with a durable dispatch
  claim;
- the send path re-checks mailbox capability before any SMTP contact, so a
  globally enabled switch never widens per-mailbox authority;
- replaying the same request returns the recorded outcome and never performs a
  second SMTP submission.

Two production verification messages were sent under explicit per-draft owner
authorization — plain text, no customer data. Production verification exposed
a Sent-folder reconciliation edge case before rollout was expanded: the system
preserved exactly-once delivery throughout, the issue was fixed with dedicated
regression tests, and the revalidation passed the full cycle — SMTP accepted,
provider-managed Sent copy present exactly once, reconciliation clean, approval
consumed, replay a no-op.

Per-decision Registry provenance (decision id, bundle digest, reason code,
approval-signal digest) is persisted alongside the action audit trail, so both
allow and deny decisions remain reconstructable.
