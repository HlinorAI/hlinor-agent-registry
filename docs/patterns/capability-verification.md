# Capability Verification

> **Scope.** This is an authoring contract, not a runtime control. The schema is
> validated when you compile a bundle; `PolicyChecker` does not evaluate it.
> Enforcement is your adapter's, your preflight step's, or a reviewer's job. See
> [What is enforced at runtime](../../README.md#what-is-enforced-at-runtime).

Declared capabilities are not sufficient.

A capability is considered available only when:

- the required tool or provider is observable;
- required permissions are present;
- the current execution context supports the operation;
- verification is current for the task and workspace;
- the requested scope matches the verified scope.

Verification must fail closed when evidence is missing or stale.
