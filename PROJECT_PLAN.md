# Project Plan

## Objective

Provide a framework-neutral, fail-closed governance layer for AI-agent tool
actions, with reviewable contracts and evidence that the runtime executed only
the authority that was approved.

## Current architecture

- YAML registry and policy sources compile into verified JSON policy bundles.
- `PolicyChecker` evaluates immutable `ActionRequest` objects and returns
  provenance-rich `PolicyDecision` records.
- Framework adapters enforce decisions before custom, LangChain, CrewAI, and
  AutoGen-related tool flows.
- Tool Contracts describe tool identity, actions, JSON Schema inputs, resource
  patterns, effects, and safety annotations; drift checks run before execution.
- The trusted runtime binding MVP now connects a reviewed/observed contract
  digest to an immutable map of exact Python callables and validated arguments.
- The experimental binding path can verify detached Ed25519 approvals bound to
  the request target and emit hash-chained, optionally signed execution
  receipts before and after dispatch.
- The experimental runtime now has SQLite-backed atomic replay/revocation state
  and a persistent circuit breaker that can stop an exact tool dispatch after
  repeated real tool failures.
- The experimental receipt path can resume a JSONL chain only after full
  verification against an explicit checkpoint, and exposes a fail-closed
  adapter boundary for external collectors.
- The experimental binding path can verify a signed root-to-leaf delegation
  chain with exact audience/context, scope attenuation, and atomic SQLite
  child fan-out registration.
- The experimental delegation transport path signs the complete chain, binds
  sender keys to configured deployment/workload identities, checks exact
  receiver identity, and requires durable replay state.
- The experimental binding path can enforce shared SQLite rate/concurrency
  admission and a propagated kill switch before exact dispatch.
- The experimental binding path can require an explicit project/workspace
  `ExecutionScope`, bind it into request digests and receipts, and compare it
  with signed approval/delegation claims; filename, package, and message data
  are not authority sources.
- RFC 8785 interoperability vectors are published as a language-neutral JSON
  fixture and verified against canonical UTF-8 bytes and SHA-256 digests by
  Python and an independent Node.js implementation.

## Constraints

- Preserve the existing policy bundle and request digest formats.
- Fail closed on malformed contracts, drift, unsupported callable signatures,
  invalid arguments, and out-of-scope resources.
- Keep examples synthetic and the public repository free of private runtime
  logic, credentials, and operational data.

## Phases

1. Stable policy compiler and runtime gate — complete in v0.10.0.
2. Tool Contract and drift foundation — complete in v0.10.0.
3. Trusted in-process runtime binding MVP — complete as an experimental API.
4. Signed request-bound approvals and authenticated execution receipts — first
   primitives complete; independent collection remains deployment work.
5. Thin MCP integration, agent identity/delegation, and OpenTelemetry context —
   signed delegation, identity-bound transport, and bounded fan-out primitives
   are experimental; external workload attestation remains open.
6. Stateful circuit breakers, budgets, kill switch, and runtime isolation —
   rate/concurrency admission and the SQLite kill switch are experimental;
   cost accounting and broader runtime isolation remain open.
7. Control-plane capabilities only after runtime pilots validate demand.

## Current status

The repository is implementing the phase 4/6 runtime-hardening slice. Signed
approval, durable replay/revocation, receipt, checkpoint, circuit-breaker,
and identity-bound delegation transport primitives are experimental and
framework-neutral. The project does not yet claim external deployment or
workload attestation, independently operated receipt collection, cost
accounting, MCP support, or A2A support.

## Open risks

- Runtime binding currently trusts the process that exports the observed
  contract and owns the callable; it does not prove artifact provenance.
- Delegation identity bindings are deployment-configured key metadata, not
  proof from an external workload identity or attestation provider.
- Resource derivation remains an adapter responsibility until a protocol-level
  integration is added.
- `failure_threshold` in `PolicyChecker` still uses caller-reported state; the
  separate SQLite breaker now provides durable runtime failure state, while
  cost accounting and a global budget across unwrapped agent paths are not
  runtime controls yet; delegation fan-out and the SQLite kill switch are
  bounded experimental controls.
- `ExecutionScope` enforcement currently covers `BoundTool` only; framework
  adapters, durable workspace stores, cross-agent message channels, and
  external workload attestation still require deployment-specific integration.
