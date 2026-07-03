from pathlib import Path

from hlinor_registry.validator import (
    validate_agent,
    validate_production_action_boundary_example,
    validate_runtime_example,
)

def test_search_agent_example_is_valid():
    errors = validate_agent("examples/search-agent.yaml")
    assert errors == []

def test_runtime_receipt_examples_are_valid():
    paths = list(Path("examples/runtime").glob("*.yaml"))
    assert paths

    for path in paths:
        errors = validate_runtime_example(path)
        assert errors == []


def test_production_action_boundary_example_is_valid():
    errors = validate_production_action_boundary_example(
        "examples/control-loops/production-action-boundary.yaml"
    )
    assert errors == []
