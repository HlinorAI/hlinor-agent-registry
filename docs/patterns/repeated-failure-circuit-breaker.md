# Repeated Failure Circuit Breaker

A control loop must stop when the same failure repeats beyond a configured threshold.

The breaker should use a stable failure fingerprint and distinguish:

- identical repeated failure;
- transient unrelated failure;
- dependency failure;
- policy denial;
- invalid execution context.

When opened, the breaker blocks additional cost and side effects until review or a successful probe.
