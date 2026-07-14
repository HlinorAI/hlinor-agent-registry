# Execution Context Verification

Agent systems must distinguish declared execution context from verified execution capability.

## Context types

- `sandbox`: isolated execution with restricted external access.
- `restricted`: partially capable environment with explicit limitations.
- `host_native`: execution on the intended host with verified required capabilities.
- `remote_approved`: execution delegated to an approved remote runtime.

## Core rule

An environment marker is a claim, not proof.

A live or production-sensitive action may proceed only when the required capabilities
have been observed in the current execution context.

## Required order

1. Identify the requested operation.
2. Determine required capabilities.
3. Classify the current execution context.
4. Verify required network, filesystem, tool, and production boundaries.
5. Record the verification result.
6. Continue only when the verified context satisfies the operation.

## Fail-closed behavior

If verification is missing, ambiguous, stale, or contradictory:

- mark the context `unverified` or `invalid`;
- block the affected operation;
- do not silently substitute sandbox execution;
- return a clear execution-context failure;
- preserve a diagnostic record.

## Important distinction

A DNS, TCP, browser, or provider failure observed inside a sandbox proves only that
the sandbox is restricted. It does not prove that the intended host-native or remote
runtime is unavailable.

## Example uses

- live public web discovery;
- browser automation;
- production database maintenance;
- actions that require provider credentials;
- costly model or rendering operations;
- production side effects.
