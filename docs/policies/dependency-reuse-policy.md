# Dependency Reuse Policy

## Purpose

The goal of this policy is to maximize reliability, reduce maintenance cost, and avoid reinventing well-solved infrastructure problems.

Agents must make an engineering decision before implementing any non-trivial functionality.

## Existing Project First

Before writing new code, inspect the current project.

Always prefer, in this order:

1. Existing project code or internal utilities.
2. Existing project dependencies already installed.
3. Mature, actively maintained open-source libraries.
4. New implementation only if none of the above is appropriate.

Do not duplicate functionality that already exists.

## Evaluate Before Adding Dependencies

If a new dependency is being considered, briefly evaluate:

- project maintenance and activity
- license compatibility
- maturity and adoption
- API stability
- dependency size
- transitive dependency impact
- security and supply-chain risk
- compatibility with the existing technology stack

Do not introduce a dependency unless its long-term value exceeds its maintenance cost.

## Prefer Mature Implementations

Strongly prefer mature implementations for complex infrastructure problems, including but not limited to:

- date and time handling
- time zones
- parsing
- serialization
- markdown
- HTML processing
- PDF generation
- Office document handling
- authentication
- authorization
- cryptography
- retry logic
- rate limiting
- networking
- protocol implementations
- validation
- schema handling
- charts
- drag-and-drop
- file formats
- database drivers
- SDKs
- API clients

Do not rewrite these systems from scratch when a proven implementation already exists.

## Do Not Add Dependencies When

A new dependency should generally NOT be introduced if:

- the task is small and easily solved with the standard library;
- the functionality is project-specific business logic;
- an existing dependency already provides the capability;
- the package is inactive or poorly maintained;
- licensing is incompatible;
- the dependency introduces unnecessary complexity.

## Required Decision

Before implementation, explicitly determine one of the following:

- Reusing existing project code.
- Reusing an existing project dependency.
- Introducing a mature external dependency with justification.
- Implementing directly because no suitable dependency exists or because adding one would create unnecessary risk.

The implementation must follow that decision.

## Engineering Principle

Reliable software is built by composing proven components where appropriate and writing custom code only where it creates unique value.

Agents should spend engineering effort on business logic, not on reimplementing infrastructure that the ecosystem has already solved and validated.
