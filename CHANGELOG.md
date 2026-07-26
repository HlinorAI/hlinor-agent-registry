# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- A `PolicyChecker` configured with trust roots now requires a signed bundle.
  Under `signature_policy="auto"` the requirement was previously derived from
  `metadata.environment` inside the bundle being verified, so an attacker able
  to rewrite the deployed file could strip the signature, downgrade the declared
  environment, recompute the digest, and disable authentication entirely.
  Deployments that pass `trust_store` or `trusted_keys` are upgraded to
  `required`; `signature_policy="optional"` remains an explicit unsafe override.
- Removed fabricated policy attribution from decisions and audit events.
  `matched_policy_ids` was populated from a hard-coded three-entry action-to-policy
  table that matched only the shipped examples, which placed an unverifiable
  claim into an audit record. The field is now reserved and always empty until
  real policy evaluation exists.

### Added

- A shared integration gate that creates one immutable `ActionRequest`, emits
  one `PolicyDecision`, and blocks tool execution on denial.
- Native async contracts and checker injection for LangChain, CrewAI, and
  framework-agnostic decorators.
- A versioned integration compatibility matrix and real-framework CI jobs.

### Changed

- `GovernedTool` is now a real LangChain `BaseTool` that preserves schemas,
  metadata, callbacks, and sync/async behavior.
- `GovernedCrewTool` now reuses a persistent checker and preserves wrapped
  CrewAI tool schemas.
- `PolicyViolationError` is now a compatibility alias for the shared
  `GovernanceDeniedError`.
- Expanded Ruff format and lint checks to runnable Python examples.
- Split PyPI publication and post-publish verification into independently
  retryable release jobs.
- Added a bounded clean-environment installation check for every published
  package version.
- Updated installation and release documentation to match the current package
  dependencies and Trusted Publishing workflow.

## [0.5.0] - 2026-07-26

### Added

- Ed25519 policy bundle signatures with trusted key IDs, issuers, and explicit
  issuance and expiration windows.
- Deployment-owned JSON trust stores and strict runtime signature verification.
- `verify-bundle` CLI command for integrity, trust, validity, and rollback-floor
  checks.
- Signing key IDs, verified public-key fingerprints, issuers, and validity
  windows in `PolicyDecision` and JSONL audit events.
- Security-negative tests for payload replacement, digest recomputation,
  untrusted keys, invalid issuers, expiration, future issuance, and rollback.

### Changed

- The package version is `0.5.0`.
- Unsigned production bundles are rejected by the default `auto` signature
  policy; production deployments should set `signature_policy="required"`.
- Long-lived checkers revalidate signature expiry and configured trust roots
  before every signed-bundle evaluation.

## [0.4.2] - 2026-07-26

### Added

- Provenance-aware JSONL decision events with the active policy bundle digest.
- Optional durable JSONL audit sinks for `check` and `explain`.
- Controlled bundle refresh for long-lived LangChain and decorator integrations.
- Contract tests for decorators and the optional CrewAI integration.
- Atomic bundle writes, schema/compiler revision metadata, and separate agent
  and capability namespaces.
- Immutable `ActionRequest` evaluation with request digests, actor/resource
  context, matched policy IDs, and request-to-bundle decision provenance.
- Stable `DecisionResult` and `ReasonCode` enums that retain string-compatible
  JSON values.

### Changed

- `explain --format jsonl` now emits one machine-readable record without text output.
- CrewAI, LangChain, and decorator integrations share the `GovernanceDeniedError` contract.
- CI now runs linting, type checks, and YAML linting; development extras include the required tooling.
- Compiler validation rejects unknown entity types, normalized ID collisions,
  unsupported schema majors, and permissive production agents by default.

## [0.4.1] - 2026-07-25

### Added

- Zero-friction `init`, `check`, `explain`, and policy lint CLI commands.
- Optional CrewAI integration and framework-agnostic `@governed` decorator.
- Makefile, pre-commit configuration, and YAML linting defaults.

## [0.3.1] - 2026-07-22

### Added

- Capability registration schema, validator, CLI command, and Funding Intelligence integration example.
- Runtime `PolicyChecker` for declarative allowlist and blocklist enforcement.
- Financial audit and budget-limited research agent examples.
- Optional LangChain integration with `GovernedTool` and `GovernedAgent`.
- GitHub Actions validation across Python 3.10 through 3.13.
- Comprehensive tests for policy enforcement and framework integration.

### Changed

- Expanded package metadata for PyPI discovery and release tooling.
- Documented optional integrations and runtime governance in the README.

### Security

- Runtime policy checks block unauthorized agent actions before tool execution.
- Declarative action boundaries support fine-grained allowlist and blocklist control.
- Existing audit-oriented schemas remain available for execution receipts and governance records.

## [0.4.0] - 2026-07-23

### Added

- Explicit `registry.yaml` manifests and the `compile` command for deterministic policy bundles.
- SHA-256 digests for source entries and integrity-checked compiled bundles.
- Runtime tests for path traversal protection, duplicate IDs, tamper detection, and unlisted files.

### Changed

- `PolicyChecker` now loads only compiled JSON bundles and no longer scans directories at runtime.
- LangChain integrations accept a compiled `bundle_path` for governed tool execution.

## [0.3.0]

Public registry release with YAML schemas, CLI validation, runtime governance
contracts, lifecycle schemas, and audit-friendly examples.

[0.3.1]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.3.0...v0.3.1
[0.4.2]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.3.1...v0.4.0
[0.3.0]: https://github.com/HlinorAI/hlinor-agent-registry/releases/tag/v0.3.0
