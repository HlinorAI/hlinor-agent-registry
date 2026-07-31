"""Measure loaded PolicyChecker decision latency without external services."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import math
import platform
import sys
import tempfile
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter, perf_counter_ns
from typing import Any

from hlinor_registry import ActionRequest, PolicyChecker, __version__
from hlinor_registry.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_MANIFEST = ROOT / "benchmarks" / "fixtures" / "registry.yaml"

# These are regression guardrails for shared CI runners, not production SLAs.
# The published reference targets in docs/performance.md are intentionally
# tighter and should be measured on representative deployment hardware.
DEFAULT_BUDGETS = {
    "single_agent": {"p95_ms": 5.0, "min_throughput_dps": 1_000.0},
    "concurrent_8_workers": {
        "p95_ms": 25.0,
        "min_throughput_dps": 500.0,
    },
}


@dataclass(frozen=True)
class ScenarioResult:
    """One benchmark scenario with distribution and throughput evidence."""

    name: str
    iterations: int
    workers: int
    allowed: int
    denied: int
    elapsed_seconds: float
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    throughput_dps: float


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    if not 0 < percentile <= 100:
        raise ValueError("percentile must be in (0, 100]")
    ordered = sorted(values)
    rank = max(0, math.ceil((percentile / 100) * len(ordered)) - 1)
    return ordered[rank]


def _compile_fixture(destination: Path) -> None:
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        status = main(
            [
                "compile",
                "--manifest",
                str(FIXTURE_MANIFEST),
                "--output",
                str(destination),
            ]
        )
    if status != 0:
        raise RuntimeError(f"Unable to compile benchmark fixture:\n{output.getvalue()}")


def _requests() -> tuple[ActionRequest, tuple[ActionRequest, ...]]:
    single = ActionRequest(
        request_id="benchmark-single",
        agent_id="benchmark-single-agent",
        action="read_record",
        resource="record/42",
        environment="test",
        requested_at="2026-01-01T00:00:00+00:00",
    )
    concurrent = (
        ActionRequest(
            request_id="benchmark-concurrent-allow",
            agent_id="benchmark-concurrent-agent",
            action="query_items",
            resource="tenant/acme",
            environment="test",
            requested_at="2026-01-01T00:00:00+00:00",
        ),
        ActionRequest(
            request_id="benchmark-concurrent-block",
            agent_id="benchmark-concurrent-agent",
            action="export_customer_data",
            environment="test",
            requested_at="2026-01-01T00:00:00+00:00",
        ),
    )
    return single, concurrent


def _timed_evaluation(
    checker: PolicyChecker,
    request: ActionRequest,
) -> tuple[float, bool]:
    started = perf_counter_ns()
    decision = checker.evaluate(request)
    elapsed_ms = (perf_counter_ns() - started) / 1_000_000
    return elapsed_ms, decision.allowed


def _summarize(
    *,
    name: str,
    workers: int,
    elapsed_seconds: float,
    observations: Sequence[tuple[float, bool]],
) -> ScenarioResult:
    latencies = [latency for latency, _ in observations]
    allowed = sum(1 for _, is_allowed in observations if is_allowed)
    iterations = len(observations)
    return ScenarioResult(
        name=name,
        iterations=iterations,
        workers=workers,
        allowed=allowed,
        denied=iterations - allowed,
        elapsed_seconds=round(elapsed_seconds, 6),
        mean_ms=round(sum(latencies) / iterations, 6),
        p50_ms=round(_percentile(latencies, 50), 6),
        p95_ms=round(_percentile(latencies, 95), 6),
        p99_ms=round(_percentile(latencies, 99), 6),
        throughput_dps=round(iterations / elapsed_seconds, 2),
    )


def _run_single(
    checker: PolicyChecker,
    request: ActionRequest,
    *,
    warmup: int,
    iterations: int,
) -> ScenarioResult:
    for _ in range(warmup):
        if not checker.evaluate(request).allowed:
            raise RuntimeError("Single-agent benchmark request was unexpectedly denied")

    started = perf_counter()
    observations = [_timed_evaluation(checker, request) for _ in range(iterations)]
    elapsed = perf_counter() - started
    return _summarize(
        name="single_agent",
        workers=1,
        elapsed_seconds=elapsed,
        observations=observations,
    )


def _run_concurrent(
    checker: PolicyChecker,
    requests: Sequence[ActionRequest],
    *,
    warmup: int,
    iterations: int,
    workers: int,
) -> ScenarioResult:
    for index in range(warmup):
        checker.evaluate(requests[index % len(requests)])

    workload = [requests[index % len(requests)] for index in range(iterations)]
    started = perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        observations = list(
            executor.map(
                lambda request: _timed_evaluation(checker, request),
                workload,
            )
        )
    elapsed = perf_counter() - started
    result = _summarize(
        name=f"concurrent_{workers}_workers",
        workers=workers,
        elapsed_seconds=elapsed,
        observations=observations,
    )
    if result.allowed == 0 or result.denied == 0:
        raise RuntimeError("Concurrent benchmark must exercise allow and deny paths")
    return result


def run_benchmarks(
    *,
    iterations: int,
    concurrent_iterations: int,
    warmup: int,
    workers: int,
) -> dict[str, Any]:
    """Run both scenarios against one immutable loaded bundle."""
    if min(iterations, concurrent_iterations, warmup, workers) < 1:
        raise ValueError("iterations, warmup, and workers must be positive")

    with tempfile.TemporaryDirectory(prefix="hlinor-benchmark-") as directory:
        bundle_path = Path(directory) / "policy-bundle.json"
        _compile_fixture(bundle_path)
        checker = PolicyChecker(str(bundle_path))
        single_request, concurrent_requests = _requests()
        results = [
            _run_single(
                checker,
                single_request,
                warmup=warmup,
                iterations=iterations,
            ),
            _run_concurrent(
                checker,
                concurrent_requests,
                warmup=warmup,
                iterations=concurrent_iterations,
                workers=workers,
            ),
        ]

    return {
        "schema_version": "1.0",
        "benchmark": "policy_checker_loaded_decisions",
        "hlinor_registry_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "methodology": {
            "bundle_state": "compiled_once_loaded_once",
            "signature_mode": "unsigned_test_fixture",
            "latency_clock": "perf_counter_ns",
            "throughput_clock": "perf_counter",
        },
        "scenarios": [asdict(result) for result in results],
    }


def _budget_failures(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for scenario in report["scenarios"]:
        budget = DEFAULT_BUDGETS.get(scenario["name"])
        if budget is None:
            continue
        if scenario["p95_ms"] > budget["p95_ms"]:
            failures.append(
                f"{scenario['name']} p95 {scenario['p95_ms']:.3f} ms exceeds "
                f"{budget['p95_ms']:.3f} ms"
            )
        if scenario["throughput_dps"] < budget["min_throughput_dps"]:
            failures.append(
                f"{scenario['name']} throughput "
                f"{scenario['throughput_dps']:.2f} decisions/s is below "
                f"{budget['min_throughput_dps']:.2f}"
            )
    return failures


def _text_report(report: dict[str, Any], failures: Sequence[str]) -> str:
    lines = [
        "Hlinor PolicyChecker benchmark",
        (
            f"Python {report['python']} | hlinor-registry "
            f"{report['hlinor_registry_version']}"
        ),
    ]
    for scenario in report["scenarios"]:
        lines.append(
            f"{scenario['name']}: p50={scenario['p50_ms']:.3f} ms, "
            f"p95={scenario['p95_ms']:.3f} ms, "
            f"p99={scenario['p99_ms']:.3f} ms, "
            f"throughput={scenario['throughput_dps']:.2f} decisions/s"
        )
    lines.append("Budget: " + ("PASS" if not failures else "FAIL"))
    lines.extend(f"- {failure}" for failure in failures)
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark loaded PolicyChecker decision latency and throughput."
    )
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--concurrent-iterations", type=int, default=10_000)
    parser.add_argument("--warmup", type=int, default=1_000)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--enforce-budget",
        action="store_true",
        help="Exit non-zero when a named CI regression budget is missed.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Use shorter fixed workloads suitable for CI smoke checks.",
    )
    return parser


def benchmark_main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.quick:
        args.iterations = 2_000
        args.concurrent_iterations = 2_000
        args.warmup = 200

    try:
        report = run_benchmarks(
            iterations=args.iterations,
            concurrent_iterations=args.concurrent_iterations,
            warmup=args.warmup,
            workers=args.workers,
        )
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        print(f"Benchmark error: {error}", file=sys.stderr)
        return 2

    failures = _budget_failures(report) if args.enforce_budget else []
    report["budget"] = {
        "enforced": args.enforce_budget,
        "status": "failed" if failures else "passed",
        "failures": failures,
    }
    if args.format == "json":
        print(json.dumps(report, sort_keys=True))
    else:
        print(_text_report(report, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(benchmark_main())
