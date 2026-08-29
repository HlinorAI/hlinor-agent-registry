# Repeated Failure Circuit Breaker

> **Scope.** The YAML schema remains an authoring contract, not a policy checked
> by `PolicyChecker`. The experimental `SQLiteCircuitBreaker` is a separate
> runtime control that stores state durably and blocks `BoundTool` dispatch.

A control loop must stop when the same failure repeats beyond a configured threshold.

The breaker should use a stable failure fingerprint and distinguish:

- identical repeated failure;
- transient unrelated failure;
- dependency failure;
- policy denial;
- invalid execution context.

When opened, the breaker blocks additional cost and side effects until review or
a successful probe. A normal in-flight call cannot clear an already-open
breaker; only an explicit half-open probe may do that.
