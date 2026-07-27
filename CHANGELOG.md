# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This release is the result of an external security and architecture review.
Every finding is described below in the terms that matter to a user of the
package: what was wrong, what changes, and whether it changes behaviour. Two of
the fixes do; both are marked.

### Security

- **Signature enforcement no longer depends on the artifact being verified.**
  Under the default `signature_policy="auto"`, whether a signature was required
  came from `metadata.environment` inside the bundle. An attacker able to
  rewrite the deployed file could delete the `signature` object, set the
  environment to `development`, recompute the digest, and load a tampered
  policy with authentication silently disabled — even with a trust store
  configured. A `PolicyChecker` given `trust_store` or `trusted_keys` now
  requires a signed bundle. `signature_policy="optional"` remains the
  documented explicit override.
- **A blocked action can no longer be reached through a case variant.**
  Matching was exact, so in permissive mode an agent blocked from
  `Initiate_Transfer` could run `initiate_transfer`, and `allowed: [Read_DB]`
  beside `blocked: [read_db]` read as a block while permitting the request.
  Block-list matching is now case-insensitive; allow-list matching stays exact
  so an approval is never extended to a spelling that was not literally
  approved. Authoring validation rejects action names that differ only by case.
- **Removed fabricated policy attribution from audit records.**
  `matched_policy_ids` was filled from a hard-coded three-entry action-to-policy
  table that matched only the shipped examples, putting an unverifiable claim
  into a record that reads as compliance evidence. The field is reserved and
  always empty until real policy evaluation exists.
- **`GovernedAgent` no longer leaves ungoverned tools reachable.** Tools
  discovered on `executor.agent` were wrapped but written back to `executor`,
  so the originals stayed available on the object that owned them. Constructing
  a `GovernedAgent` over an executor with no tools now raises rather than
  silently governing nothing.
- Bounded the signature validity window: signing warns above 90 days and
  refuses above 366. Without a revocation channel, expiry is the only mechanism
  that forces a leaked bundle out of circulation, and nothing prevented
  `--expires-at 2099-01-01`.
- Trust store entries with a relative `public_key_path` must resolve inside the
  trust store directory, matching the boundary already enforced on policy
  sources. Absolute paths remain an explicit deployment choice.
- `load_public_key` treated any string without a PEM header as a filesystem
  path, turning an unintended value into a file read. Strings containing
  newlines or NULs are rejected rather than opened.
- A bundle declaring an unrecognized `enforcement_mode` is rejected instead of
  silently coerced to `strict`. Coercion failed closed but hid a disagreement
  between the compiler that produced the bundle and the runtime reading it.
- The landing page no longer executes third-party code. It loaded the Tailwind
  Play CDN and three Prism files from cdnjs with no subresource integrity; both
  are now built and vendored, and the page loads no external subresource.
- CI scans history with gitleaks and enforces a public-scope rule over every
  tracked file. A matching pre-commit hook rejects internal paths, one-off
  patch-script filenames, and files containing local absolute paths or PEM
  private keys.

### Changed

- **Breaking for scripts.** `check` and `explain` now exit `0` for allowed, `1`
  for denied, and `2` when no decision could be reached: missing or unreadable
  bundle, broken trust configuration, or a failed audit-log write. Every
  failure previously shared exit `1` with a denial, so a pipeline gating on a
  non-zero exit read a broken deployment as working governance. Error messages
  moved from stdout to stderr. Gate on `1` specifically.
- Runtime trust re-verification runs only when the trust material changes.
  Every governed call previously re-read the trust store, re-parsed each PEM,
  rebuilt the canonical JSON of the whole bundle and re-checked the signature,
  so the cost of a decision scaled with bundle size: 4.6 ms per call on a 74 KB
  bundle, now 129 µs and flat. Key revocation still takes effect immediately —
  the fingerprint covers the referenced PEM files by content, not just the
  trust store — and the validity window is still checked on every call.
- `DecisionResult` and `ReasonCode` have a single definition in
  `hlinor_registry.enums`; `hlinor_registry.decision` re-exports them. The two
  copies had drifted, and emitting a reason code present in only one would have
  raised `ValueError` inside the path that constructs a denial.
- `TrustedKey` records the PEM path an entry was loaded from, so a long-lived
  verifier can detect a key replaced in place.
- The repository manifest `registry.yaml` declares the `development`
  environment so the documented `compile` then `check` path works on a fresh
  clone. Production deployments should set `production` and sign the bundle.

### Fixed

- Added the missing `langchain` extra. `pip install "hlinor-registry[langchain]"`
  was documented in the README but never declared, so pip warned and installed
  nothing while the next line of the same README section raised `ImportError`.
- Corrected the README blocklist example, which asserted an output that did not
  match its own input.
- `make lint` covers `scripts/`.

### Added

- CI exercises the documented quickstart end to end, asserts the exit-code
  contract, verifies a signed bundle through a generated key and trust store,
  and asserts that every extra the README tells users to install is declared.
- `scripts/check_public_scope.py`, run by both pre-commit and CI.
- `scripts/build_landing_assets.sh` to regenerate the vendored landing assets.
- README sections placing the project against content-safety tooling and
  against OPA/Cedar, replacing a comparison table that listed LangChain and
  CrewAI — the frameworks this project integrates with — as alternatives.

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
- A shared integration gate that creates one immutable `ActionRequest`, emits
  one `PolicyDecision`, and blocks tool execution on denial.
- Native async contracts and checker injection for LangChain, CrewAI, and
  framework-agnostic decorators.
- A versioned integration compatibility matrix and real-framework CI jobs.

### Changed

- The package version is `0.5.0`.
- Unsigned production bundles are rejected by the default `auto` signature
  policy; production deployments should set `signature_policy="required"`.
- Long-lived checkers revalidate signature expiry and configured trust roots
  before every signed-bundle evaluation.
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

## [0.4.0] - 2026-07-23

### Added

- Explicit `registry.yaml` manifests and the `compile` command for deterministic policy bundles.
- SHA-256 digests for source entries and integrity-checked compiled bundles.
- Runtime tests for path traversal protection, duplicate IDs, tamper detection, and unlisted files.

### Changed

- `PolicyChecker` now loads only compiled JSON bundles and no longer scans directories at runtime.
- LangChain integrations accept a compiled `bundle_path` for governed tool execution.

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

## [0.3.0]

Public registry release with YAML schemas, CLI validation, runtime governance
contracts, lifecycle schemas, and audit-friendly examples.

[Unreleased]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/HlinorAI/hlinor-agent-registry/releases/tag/v0.3.0
