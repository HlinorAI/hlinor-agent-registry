# Repeated Failure Circuit Breaker

> **Scope.** This is an authoring contract, not a runtime control. The schema is
> validated when you compile a bundle; `PolicyChecker` does not evaluate it.
> Enforcement is your adapter's, your preflight step's, or a reviewer's job. See
> [What is enforced at runtime](../../README.md#what-is-enforced-at-runtime).

A control loop must stop when the same failure repeats beyond a configured threshold.

The breaker should use a stable failure fingerprint and distinguish:

- identical repeated failure;
- transient unrelated failure;
- dependency failure;
- policy denial;
- invalid execution context.

When opened, the breaker blocks additional cost and side effects until review or a successful probe.
