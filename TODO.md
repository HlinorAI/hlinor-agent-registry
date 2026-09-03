# TODO

## Trusted runtime binding MVP

- [x] Add RFC 8785 contract and normalized-argument digests.
- [x] Bind reviewed and observed contracts before retaining exact callables.
- [x] Validate normalized Python arguments against Tool Contract JSON Schema.
- [x] Enforce declared resource patterns before policy evaluation.
- [x] Dispatch only through the immutable bound registry.
- [x] Add security-negative tests for contract drift, runtime set drift,
  invalid arguments, resource drift, unsupported callables, and policy denial.

## Next milestones

- [x] Publish cross-language JCS golden vectors and verify them in the Python
  runtime and an independent Node.js implementation.
- [x] Define and verify signed request-bound approval tokens in the experimental
  `BoundTool` path.
- [x] Define and emit hash-chained, optionally signed execution receipts for
  pre-dispatch, completion, denial, and binding-failure outcomes.
- [x] Replace `InMemoryReplayGuard` with an atomic SQLite cross-worker replay
  guard and token revocation API.
- [x] Add a resume-safe JSONL receipt sink with an explicit verified checkpoint
  and fail-closed behavior after checkpoint persistence uncertainty.
- [x] Add the framework-neutral fail-closed adapter boundary for an external
  receipt collector.
- [x] Add experimental authenticated delegation chain, audience, nonce, expiry,
  scope attenuation, and bounded SQLite fan-out.
- [x] Bind configured deployment/workload identity to delegation keys and
  verify the signed delegation transport boundary with durable replay state.
- [x] Move runtime circuit-breaker counters out of caller signals into shared
  SQLite state and block `BoundTool` dispatch after real tool failures.
- [x] Add shared SQLite rate/concurrency admission and a propagated
  kill-switch check before `BoundTool` dispatch.
- [x] Enforce explicit project/workspace scope at the `BoundTool` boundary,
  bind it into requests/receipts, compare signed claims, and deny authority
  conveyed through filenames, package metadata, or natural-language messages.
- [x] Propagate explicit project/workspace scope through the shared
  `GovernanceGate`, decorators, LangChain, and CrewAI wrappers.
- [x] Add a durable SQLite workspace/message store with mandatory scope,
  recipient filtering, bounded JSON payloads, and revision tracking.
- [x] Add a signed, scope-bound cross-agent message envelope with sender-key
  binding, exact recipient checks, freshness, payload limits, and replay
  protection; sender metadata in the scoped store remains non-authenticating.
- [x] Add an AutoGen execution wrapper over the public `BaseTool` path and
  verify scope propagation and deny-before-dispatch in the compatibility job.
- [x] Add the local `OutcomeAcceptanceGate`: a task may reach `SUCCESS` only
  when every declared acceptance criterion has verified evidence; timeout,
  interruption, blocked, approval-pending, and partial states remain
  non-success outcomes.
- [x] Add a first-class public Agent Contract validator for owner, goals,
  forbidden actions, action levels, approvals, stop conditions, data access,
  and failure mode. Its stateless compatibility check cross-checks policy and
  Tool Contract declarations without becoming an authority store.
- [x] Add a governance coverage checker and CI failure for known sensitive
  tool paths that bypass `BoundTool` or the shared governance gate. Keep the
  source inventory explicit and fail closed on missing or ambiguous evidence.
- [x] Add an adversarial conformance suite for spoofing, poisoned messages,
  authority conveyed by filenames/tool output, receipt tampering, delegation
  fan-out, runaway retries, and partial execution after interruption.
- [ ] Define a protocol-neutral MCP `tools/call` contract/conformance fixture;
  production gateway, credentials, and tenant routing stay outside this repo.
- [ ] Add portable OpenTelemetry correlation hooks; hosted collection and
  fleet analytics stay outside this repo.
- [ ] Evaluate an OSS A2A contract/conformance fixture only after the public/
  commercial boundary is reviewed.

## Commercial/private scope

Commercial capabilities are developed in the private control-plane repository
and are intentionally omitted from this public roadmap. Public work may add
portable contracts, local reference implementations, and conformance fixtures
for those boundaries, but not the managed product itself.
