# Project Plan

## Objective

Provide a framework-neutral, fail-closed governance layer for AI-agent tool
actions, with reviewable contracts and evidence that the runtime executed only
the authority that was approved. This repository is the public OSS core; the
managed multi-deployment control plane is developed separately.

The authoritative OSS/commercial split is documented in
[`docs/open-core-boundary.md`](docs/open-core-boundary.md).

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
- The shared integration gate propagates this explicit scope through the
  framework-neutral decorator, LangChain, and CrewAI wrappers.
- The AutoGen integration now wraps the public `BaseTool` execution path and
  applies the same fail-closed gate before `run_json` delegates to a tool.
- The experimental `SQLiteScopedWorkspaceStore` persists JSON records and
  ordinary recipient-filtered messages under a composite project/workspace
  key; it has no global enumeration API and does not authenticate senders.
- The experimental signed message transport binds sender key, recipient,
  project/workspace scope, body, freshness, and nonce; receivers require
  durable replay protection when operating across workers.
- The local `OutcomeAcceptanceGate` evaluates explicit acceptance criteria and
  verified evidence. It never treats completion, partial execution, or a
  caller claim as proof of successful work; its receipt fields extend the
  existing lifecycle receipt format.
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
5. Protocol contracts and portable identity/delegation primitives — signed
   delegation, identity-bound transport, and bounded fan-out primitives are
   experimental; production gateways and external workload attestation are
   outside this repository.
6. Outcome/acceptance enforcement, stateful circuit breakers, budgets, kill
   switch, and runtime isolation — the local outcome gate, rate/concurrency
   admission, and SQLite kill switch are experimental; cost accounting and
   broader runtime isolation remain open.
7. Commercial control-plane capabilities are outside this repository and must
   not be implemented here; only public contracts or local reference clients
   may be added after runtime pilots validate demand.

## Current status

The public repository has reached the current OSS runtime-hardening boundary.
Signed approval, durable replay/revocation, receipt, checkpoint,
circuit-breaker, scope, AutoGen, and identity-bound delegation/message
transport primitives are experimental and framework-neutral. Further public
work is limited to maintenance, security fixes, documentation, portable
contracts, and conformance tests. Hosted control-plane, managed identity,
network message delivery, independent audit collection, fleet analytics, and
production MCP/A2A gateways are commercial/private work.

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
- `ExecutionScope` enforcement covers `BoundTool`, the shared framework
  wrappers, the AutoGen wrapper, and the experimental scoped store. Signed
  messages still require deployment-specific network delivery, key rotation,
  external workload attestation, and independent audit collection.
- The public/private product boundary must be reviewed before accepting new
  runtime capabilities; see `docs/open-core-boundary.md`.
