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

- [ ] Publish cross-language JCS golden vectors.
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
- [ ] Bind deployment/workload identity to delegation keys and verify the
  delegation transport boundary.
- [x] Move runtime circuit-breaker counters out of caller signals into shared
  SQLite state and block `BoundTool` dispatch after real tool failures.
- [ ] Add cost, rate, concurrency, fan-out, and propagated kill-switch
  enforcement.
- [ ] Enforce project/workspace isolation and deny authority conveyed through
  filenames, package metadata, or natural-language inter-agent messages.
- [ ] Add a thin MCP `tools/call` integration with protocol-version and auth
  context handling.
- [ ] Add OpenTelemetry correlation for binding, decision, and dispatch.
- [ ] Evaluate A2A and workload-identity/delegation support after MCP MVP.
