# Protected Resource Boundary

> **Scope.** This is an authoring contract, not a runtime control. The schema is
> validated when you compile a bundle; `PolicyChecker` does not evaluate it.
> Enforcement is your adapter's, your preflight step's, or a reviewer's job. See
> [What is enforced at runtime](../../README.md#what-is-enforced-at-runtime).

Visibility does not imply authorization.

Protected resources may include:

- production configuration;
- customer or account data;
- credentials;
- deployment state;
- external communication systems;
- project-private artifacts.

Each access must be bounded by project, workspace, operation, scope, and approval level.
