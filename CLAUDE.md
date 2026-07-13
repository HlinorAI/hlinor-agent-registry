# CLAUDE.md

Guidance for AI coding agents working in this repository.

## Scope

This repository is a public, generic agent registry and governance specification. It must not contain private runtime logic, production pipelines, credentials, real operational data, or business-specific workflow details. All examples must be synthetic and neutral.

## Dependency Reuse

Before implementing non-trivial code, follow `docs/policies/dependency-reuse-policy.md`.

Agents must first check existing project code and dependencies before writing new infrastructure logic or adding new packages.

## Validation

Run `python -m pytest -q` before proposing changes. Registry YAML files can be checked with the `hlinor-registry` CLI (see README).
