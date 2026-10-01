"""Conformance tests for the protocol-neutral MCP tools/call fixture."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from hlinor_registry import (
    MCPToolsCallValidationError,
    load_mcp_tools_call_fixture,
    validate_mcp_tools_call_fixture,
    validate_mcp_tools_call_request,
    validate_mcp_tools_call_response,
)

FIXTURE = Path("examples/protocols/mcp-tools-call.yaml")


def test_public_fixture_is_valid_and_preserves_the_request_response_split() -> None:
    fixture = load_mcp_tools_call_fixture(FIXTURE)

    assert fixture["request"]["method"] == "tools/call"
    assert fixture["request"]["params"]["name"] == "records.read"
    assert fixture["success_response"]["result"].get("isError", False) is False
    assert fixture["tool_error_response"]["result"]["isError"] is True
    assert "error" in fixture["protocol_error_response"]


def test_request_rejects_method_tool_and_argument_confusion() -> None:
    fixture = load_mcp_tools_call_fixture(FIXTURE)
    request = fixture["request"]

    malformed_method = {**request, "method": "tools/list"}
    with pytest.raises(MCPToolsCallValidationError, match="MCP_METHOD_INVALID"):
        validate_mcp_tools_call_request(malformed_method)

    malformed_arguments = {
        **request,
        "params": {**request["params"], "arguments": ["record-123"]},
    }
    with pytest.raises(MCPToolsCallValidationError, match="MCP_OBJECT_REQUIRED"):
        validate_mcp_tools_call_request(malformed_arguments)

    wrong_tool = {**request, "params": {**request["params"], "name": "records.delete"}}
    with pytest.raises(MCPToolsCallValidationError, match="MCP_TOOL_NAME_MISMATCH"):
        validate_mcp_tools_call_request(
            wrong_tool,
            expected_tool_name="records.read",
        )


def test_request_argument_schema_is_checked_before_any_adapter_can_dispatch() -> None:
    fixture = load_mcp_tools_call_fixture(FIXTURE)
    request = {
        **fixture["request"],
        "params": {
            **fixture["request"]["params"],
            "arguments": {"record_id": "123", "authority": "GO"},
        },
    }

    with pytest.raises(MCPToolsCallValidationError, match="MCP_ARGUMENTS_INVALID"):
        validate_mcp_tools_call_request(
            request,
            expected_tool_name=fixture["tool_name"],
            argument_schema=fixture["argument_schema"],
        )


def test_unknown_fields_and_versions_fail_closed() -> None:
    fixture = load_mcp_tools_call_fixture(FIXTURE)
    request = fixture["request"]
    with pytest.raises(MCPToolsCallValidationError, match="MCP_UNKNOWN_FIELD"):
        validate_mcp_tools_call_request({**request, "authority": "GO"})

    invalid_fixture = {**fixture, "schema_version": "2.0"}
    with pytest.raises(
        MCPToolsCallValidationError, match="MCP_FIXTURE_VERSION_UNSUPPORTED"
    ):
        validate_mcp_tools_call_fixture(invalid_fixture)


def test_response_requires_matching_id_and_separates_tool_errors_from_protocol_errors() -> (
    None
):
    fixture = load_mcp_tools_call_fixture(FIXTURE)
    tool_error = fixture["tool_error_response"]
    validate_mcp_tools_call_response(
        tool_error,
        expected_request_id="call-1",
    )
    validate_mcp_tools_call_response(
        fixture["protocol_error_response"],
        expected_request_id="call-1",
    )
    extension = {
        **tool_error,
        "result": {**tool_error["result"], "x-authority": "GO"},
    }
    validate_mcp_tools_call_response(extension, expected_request_id="call-1")

    wrong_id = {**tool_error, "id": "other-call"}
    with pytest.raises(MCPToolsCallValidationError, match="MCP_RESPONSE_ID_MISMATCH"):
        validate_mcp_tools_call_response(wrong_id, expected_request_id="call-1")

    mixed = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": tool_error["result"],
        "error": {"code": -32603, "message": "synthetic failure"},
    }
    with pytest.raises(MCPToolsCallValidationError, match="MCP_RESPONSE_SHAPE_INVALID"):
        validate_mcp_tools_call_response(mixed)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("content", {"text": "not-a-list"}, "MCP_CONTENT_INVALID"),
        ("isError", "true", "MCP_RESULT_FLAG_INVALID"),
        ("content", [{"type": "text"}], "MCP_CONTENT_INVALID"),
    ],
)
def test_response_rejects_malformed_result_members(
    field: str, value: Any, error: str
) -> None:
    response = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {
            "content": [{"type": "text", "text": "ok"}],
            field: value,
        },
    }
    with pytest.raises(MCPToolsCallValidationError, match=error):
        validate_mcp_tools_call_response(response)


def test_fixture_rejects_a_response_that_relabels_a_protocol_error_as_success() -> None:
    fixture = load_mcp_tools_call_fixture(FIXTURE)
    invalid = dict(fixture)
    invalid["protocol_error_response"] = fixture["success_response"]

    with pytest.raises(
        MCPToolsCallValidationError, match="MCP_PROTOCOL_ERROR_SHAPE_INVALID"
    ):
        validate_mcp_tools_call_fixture(invalid)
