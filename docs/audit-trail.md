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
