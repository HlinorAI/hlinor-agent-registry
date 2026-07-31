"""Tests for the reproducible PolicyChecker benchmark harness."""

from benchmarks.policy_checker_benchmark import (
    _budget_failures,
    _percentile,
    run_benchmarks,
)


def test_percentile_uses_nearest_rank() -> None:
    observations = [5.0, 1.0, 4.0, 2.0, 3.0]

    assert _percentile(observations, 50) == 3.0
    assert _percentile(observations, 95) == 5.0
    assert _percentile(observations, 100) == 5.0


def test_benchmark_exercises_single_and_concurrent_decisions() -> None:
    report = run_benchmarks(
        iterations=40,
        concurrent_iterations=40,
        warmup=5,
        workers=2,
    )

    assert report["schema_version"] == "1.0"
    assert report["methodology"]["bundle_state"] == "compiled_once_loaded_once"
    [single, concurrent] = report["scenarios"]
    assert single["name"] == "single_agent"
    assert single["allowed"] == 40
    assert single["denied"] == 0
    assert concurrent["name"] == "concurrent_2_workers"
    assert concurrent["allowed"] == 20
    assert concurrent["denied"] == 20
    assert concurrent["throughput_dps"] > 0


def test_unknown_worker_count_has_no_inapplicable_budget() -> None:
    report = {
        "scenarios": [
            {
                "name": "concurrent_2_workers",
                "p95_ms": 999.0,
                "throughput_dps": 0.01,
            }
        ]
    }

    assert _budget_failures(report) == []
