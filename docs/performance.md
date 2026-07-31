# Runtime performance

Hlinor publishes a reproducible baseline for the hot path that matters most:
evaluating an immutable `ActionRequest` against a `PolicyChecker` whose bundle
has already been compiled, verified, and loaded.

The benchmark is evidence for regression review. It is not a production SLA.
Application latency also includes network calls, framework adapters, audit-log
delivery, bundle reload checks, and the action itself.

## Scenarios

| Scenario | What it measures | Reference target | CI guardrail |
| --- | --- | ---: | ---: |
| Single agent | Sequential allow decisions through one loaded checker | p95 ≤ 1 ms; ≥ 5,000 decisions/s | p95 ≤ 5 ms; ≥ 1,000 decisions/s |
| 8 concurrent workers | Shared-checker allow and deny decisions | p95 ≤ 10 ms; ≥ 2,000 decisions/s | p95 ≤ 25 ms; ≥ 500 decisions/s |

Reference targets describe a healthy modern development machine. CI guardrails
are deliberately wider because shared runners have variable CPU scheduling.
Both are end-to-end decision measurements: request hashing, matching, decision
construction, provenance, timestamps, and IDs are included.

## Run the benchmark

From a development checkout:

```bash
python -m benchmarks.policy_checker_benchmark
```

Machine-readable output:

```bash
python -m benchmarks.policy_checker_benchmark --format json
```

Run the shorter CI workload and enforce regression budgets:

```bash
python -m benchmarks.policy_checker_benchmark \
  --quick \
  --enforce-budget \
  --format json
```

The process exits `0` when the run completes within every applicable budget,
`1` when an enforced budget is missed, and `2` when the benchmark input or
environment is invalid.

## Methodology

- The synthetic YAML fixtures are compiled once before timing starts.
- One unsigned test bundle is loaded once into one `PolicyChecker`.
- Warm-up decisions run before each measured scenario.
- Latency uses `perf_counter_ns`; throughput uses wall-clock `perf_counter`.
- The single-agent scenario reuses one immutable allowed request.
- The concurrent scenario shares one checker across eight threads and
  alternates an allowed request with an explicitly blocked request.
- p50, p95, and p99 use the nearest-rank method.
- Bundle loading, signature verification, file polling, and external I/O are
  outside this baseline and should be measured separately for each deployment.

Benchmark reports include the package version, Python version, platform,
scenario sizes, allow/deny counts, percentiles, elapsed time, and throughput.
Preserve the JSON output with performance investigations so results remain
comparable.

## Interpreting results

A slow result is a signal to investigate, not permission to bypass governance.
Confirm the runner is not overloaded, repeat the measurement, and compare the
same Python version and workload. If the regression is reproducible, profile
the policy path before changing a budget.

Never move policy evaluation behind an agent action to improve a benchmark.
The enforcement boundary remains before side effects.
