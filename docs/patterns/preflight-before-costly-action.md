# Preflight Before Costly Action

> **Scope.** This is an authoring contract, not a runtime control. The schema is
> validated when you compile a bundle; `PolicyChecker` does not evaluate it.
> Enforcement is your adapter's, your preflight step's, or a reviewer's job. See
> [What is enforced at runtime](../../README.md#what-is-enforced-at-runtime).

Before a costly, live, privileged, or production-sensitive operation begins, the system must verify:

1. execution context;
2. required dependencies;
3. requested capability;
4. required permissions;
5. budget or cost limit;
6. protected resource scope.

A failure at any prerequisite blocks the action before cost or side effect.

The preflight result must be inspectable and attributable.
