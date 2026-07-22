# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-07-22

### Added

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

[0.3.1]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/HlinorAI/hlinor-agent-registry/releases/tag/v0.3.0
