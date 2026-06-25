from hlinor_registry.validator import validate_agent

def test_search_agent_example_is_valid():
    errors = validate_agent("examples/search-agent.yaml")
    assert errors == []
