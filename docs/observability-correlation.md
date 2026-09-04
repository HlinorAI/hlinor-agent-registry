# Portable correlation hooks

The public package exposes a dependency-free `CorrelationContext` for joining
one governed operation across adapters, decisions, and execution receipts:

```python
from hlinor_registry import CorrelationContext

context = CorrelationContext(
    trace_id="0123456789abcdef0123456789abcdef",
    span_id="0123456789abcdef",
    run_id="run:synthetic-1",
    parent_id="run:synthetic-parent",
)
```

The context validates non-zero lowercase trace/span IDs and bounded run IDs.
`load_correlation_fixture()` validates the synthetic YAML/JSON shape and the
attribute projection as well.
`as_attributes()` returns namespaced keys suitable for a log or span adapter;
`as_receipt_fields()` returns the portable top-level fields `trace_id`,
`span_id`, `run_id`, and optional `parent_id`.

Pass the context to `GovernanceGate.authorize(correlation=...)` or
`BoundTool.invoke(correlation=...)`. The gate exposes it to
`InvocationContext`; the bound runtime copies it into every pre-dispatch and
completion receipt. A malformed or mapping-shaped value is rejected before
dispatch. Existing policy request digests do not include correlation metadata,
so it cannot become authority by being present.

The synthetic example is
`examples/observability/correlation-context.yaml`. The public descriptor is
`registry/schema/observability-correlation.yaml`.

## Boundary

These are correlation hooks, not an observability product. The repository does
not provide an OpenTelemetry SDK, exporter, Collector, telemetry storage,
retention, dashboards, alerts, fleet analytics, workload attestation, or
authorization. A deployment may map the namespaced attributes to its chosen
telemetry stack while keeping approval, identity, scope, and policy decisions
on their existing verified paths.
