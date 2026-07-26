# Hlinor Audit Trail v1

## Purpose

The Hlinor Audit Trail defines how agent activity is recorded.

The goal is to make autonomous work traceable, reviewable, and explainable.

## Audit Event

An audit event records something that happened in the system.

Examples:

- agent selected
- skill invoked
- validator passed
- validator failed
- policy allowed action
- policy blocked action
- approval requested
- approval granted
- approval denied
- action executed

## Event Fields

An audit event may include:

- event_id
- request_id
- timestamp
- actor
- department
- agent
- skill
- validator
- policy
- action
- input_reference
- output_reference
- decision
- reason
- request_digest
- policy_bundle_digest
- matched_policy_ids
- enforcement_mode
- environment
- signature_key_id
- signature_key_fingerprint
- signature_issuer
- signature_issued_at
- signature_expires_at

Runtime policy decision events use schema version `1.1`. The event copies
provenance from the immutable `PolicyDecision`; it does not infer the active
bundle at serialization time. This prevents a decision made under one bundle
from being mislabeled after a reload.

`matched_policy_ids` is reserved and always empty. `PolicyChecker` is an
action-name gate: a decision is produced by the compiled allow and block lists,
not by evaluating the policies named on an agent. Populating the field with a
guessed policy ID would place an unverifiable claim in an audit record, so it
stays empty until real policy evaluation is implemented. Do not treat its
absence as evidence that no policy applied.

## Decisions

Common decisions:

- allowed
- blocked
- approved
- denied
- passed
- failed

## Design Goals

The audit trail is designed to be:

- append-only
- inspectable
- explainable
- useful for debugging
- useful for governance
