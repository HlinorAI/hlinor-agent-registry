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
- [ ] Add an independently operated external receipt collector/checkpoint and
  deployment-specific availability policy.
- [x] Add experimental authenticated delegation chain, audience, nonce, expiry,
  scope attenuation, and bounded SQLite fan-out.
- [x] Bind configured deployment/workload identity to delegation keys and
  verify the signed delegation transport boundary with durable replay state.
- [ ] Add external workload/deployment attestation and provider-specific
  identity verification after a deployment profile is selected.
- [x] Move runtime circuit-breaker counters out of caller signals into shared
  SQLite state and block `BoundTool` dispatch after real tool failures.
- [ ] Add cost accounting and a deployment-wide quota across all agent paths.
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
- [ ] Add network delivery, key rotation, external workload attestation, and
  an independently operated audit boundary for authenticated messages.
- [ ] Add a thin MCP `tools/call` integration with protocol-version and auth
  context handling.
- [ ] Add OpenTelemetry correlation for binding, decision, and dispatch.
- [ ] Evaluate A2A and workload-identity/delegation support after MCP MVP.
