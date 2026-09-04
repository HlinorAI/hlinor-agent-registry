"""Protocol-neutral validation for the MCP ``tools/call`` boundary.

This module validates JSON values only. It does not open a transport, discover
tools, authorize a call, or execute a server. A deployment must connect the
validated tool name and arguments to its own Tool Contract and governance gate.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from ._limits import MAX_SOURCE_BYTES, read_text_capped

MCP_TOOLS_CALL_CONTRACT_VERSION = "1.0"
MCP_TOOLS_CALL_FIXTURE_TYPE = "mcp_tools_call_conformance"

_REQUEST_FIELDS = {"jsonrpc", "id", "method", "params"}
_PARAM_FIELDS = {"name", "arguments", "_meta", "task"}
_RESPONSE_FIELDS = {"jsonrpc", "id", "result", "error"}
_RESULT_FIELDS = {"_meta", "content", "structuredContent", "isError"}
_ERROR_FIELDS = {"code", "message", "data"}
_FIXTURE_FIELDS = {
    "schema_version",
    "type",
    "id",
    "tool_name",
    "argument_schema",
    "request",
    "success_response",
    "tool_error_response",
    "protocol_error_response",
}


class MCPToolsCallValidationError(ValueError):
    """Raised when a tools/call request, response, or fixture is invalid."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _require_object(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MCPToolsCallValidationError(
            "MCP_OBJECT_REQUIRED", f"{field} must be an object"
        )
    return value


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise MCPToolsCallValidationError(
            "MCP_TEXT_INVALID", f"{field} must be a non-empty string"
        )
    return value


def _check_fields(
    value: Mapping[str, Any],
    allowed: set[str],
    required: set[str],
    field: str,
) -> None:
    if not all(isinstance(key, str) for key in value):
        raise MCPToolsCallValidationError(
            "MCP_FIELDS_INVALID", f"{field} object keys must be strings"
        )
    unknown = set(value).difference(allowed)
    if unknown:
        raise MCPToolsCallValidationError(
            "MCP_UNKNOWN_FIELD",
            f"{field} has unknown fields: {sorted(unknown)}",
        )
    missing = required.difference(value)
    if missing:
        raise MCPToolsCallValidationError(
            "MCP_REQUIRED_FIELD_MISSING",
            f"{field} is missing fields: {sorted(missing)}",
        )


def _check_request_id(value: object) -> None:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise MCPToolsCallValidationError(
            "MCP_REQUEST_ID_INVALID", "id must be a string or integer"
        )


def _check_arguments_schema(
    arguments: Mapping[str, Any], schema: Mapping[str, Any]
) -> None:
    try:
        validator = Draft202012Validator(schema)
    except SchemaError as exc:
        raise MCPToolsCallValidationError(
            "MCP_ARGUMENT_SCHEMA_INVALID", "argument_schema is not valid JSON Schema"
        ) from exc
    errors = sorted(
        validator.iter_errors(arguments),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            error.message,
        ),
    )
    if errors:
        raise MCPToolsCallValidationError(
            "MCP_ARGUMENTS_INVALID",
            "; ".join(error.message for error in errors),
        )


def validate_mcp_tools_call_request(
    request: Mapping[str, Any],
    *,
    expected_tool_name: str | None = None,
    argument_schema: Mapping[str, Any] | None = None,
) -> None:
    """Validate one JSON-RPC ``tools/call`` request without executing it."""
    value = _require_object(request, "request")
    _check_fields(value, _REQUEST_FIELDS, _REQUEST_FIELDS, "request")
    if value.get("jsonrpc") != "2.0":
        raise MCPToolsCallValidationError(
            "MCP_JSONRPC_VERSION_UNSUPPORTED", "request.jsonrpc must be '2.0'"
        )
    _check_request_id(value.get("id"))
    if value.get("method") != "tools/call":
        raise MCPToolsCallValidationError(
            "MCP_METHOD_INVALID", "request.method must be 'tools/call'"
        )

    params = _require_object(value.get("params"), "request.params")
    _check_fields(params, _PARAM_FIELDS, {"name"}, "request.params")
    tool_name = _require_text(params.get("name"), "request.params.name")
    if expected_tool_name is not None and tool_name != expected_tool_name:
        raise MCPToolsCallValidationError(
            "MCP_TOOL_NAME_MISMATCH", "request tool name does not match the fixture"
        )
    if "arguments" in params:
        arguments = _require_object(params["arguments"], "request.params.arguments")
    else:
        arguments = {}
    if "_meta" in params:
        _require_object(params["_meta"], "request.params._meta")
    if "task" in params:
        _require_object(params["task"], "request.params.task")
    if argument_schema is not None:
        _check_arguments_schema(arguments, argument_schema)


def _validate_content(content: object) -> None:
    if not isinstance(content, list):
        raise MCPToolsCallValidationError(
            "MCP_CONTENT_INVALID", "result.content must be a list"
        )
    for index, item in enumerate(content):
        block = _require_object(item, f"result.content[{index}]")
        _require_text(block.get("type"), f"result.content[{index}].type")
        if len(block) < 2:
            raise MCPToolsCallValidationError(
                "MCP_CONTENT_INVALID",
                f"result.content[{index}] must contain a payload field",
            )


def validate_mcp_tools_call_response(
    response: Mapping[str, Any],
    *,
    expected_request_id: str | int | None = None,
) -> None:
    """Validate a success or JSON-RPC error response for one tool call."""
    value = _require_object(response, "response")
    _check_fields(value, _RESPONSE_FIELDS, {"jsonrpc", "id"}, "response")
    if value.get("jsonrpc") != "2.0":
        raise MCPToolsCallValidationError(
            "MCP_JSONRPC_VERSION_UNSUPPORTED", "response.jsonrpc must be '2.0'"
        )
    _check_request_id(value.get("id"))
    if expected_request_id is not None and value.get("id") != expected_request_id:
        raise MCPToolsCallValidationError(
            "MCP_RESPONSE_ID_MISMATCH", "response.id does not match the request"
        )
    has_result = "result" in value
    has_error = "error" in value
    if has_result == has_error:
        raise MCPToolsCallValidationError(
            "MCP_RESPONSE_SHAPE_INVALID",
            "response must contain exactly one of result or error",
        )
    if has_error:
        error = _require_object(value["error"], "response.error")
        _check_fields(error, _ERROR_FIELDS, {"code", "message"}, "response.error")
        if not isinstance(error.get("code"), int) or isinstance(
            error.get("code"), bool
        ):
            raise MCPToolsCallValidationError(
                "MCP_ERROR_CODE_INVALID", "response.error.code must be an integer"
            )
        _require_text(error.get("message"), "response.error.message")
        return

    result = _require_object(value["result"], "response.result")
    # MCP permits extension members on CallToolResult, so only validate the
    # defined members and leave extension values opaque to this fixture.
    for field in set(result).intersection(_RESULT_FIELDS):
        if field in {"_meta", "structuredContent"}:
            _require_object(result[field], f"response.result.{field}")
        elif field == "isError" and not isinstance(result[field], bool):
            raise MCPToolsCallValidationError(
                "MCP_RESULT_FLAG_INVALID", "response.result.isError must be boolean"
            )
    if "content" not in result:
        raise MCPToolsCallValidationError(
            "MCP_REQUIRED_FIELD_MISSING",
            "response.result is missing fields: ['content']",
        )
    _validate_content(result["content"])


def validate_mcp_tools_call_fixture(data: Mapping[str, Any]) -> None:
    """Validate a complete portable request/response conformance fixture."""
    fixture = _require_object(data, "fixture")
    _check_fields(
        fixture,
        _FIXTURE_FIELDS,
        {
            "schema_version",
            "type",
            "id",
            "tool_name",
            "argument_schema",
            "request",
            "success_response",
            "tool_error_response",
            "protocol_error_response",
        },
        "fixture",
    )
    if fixture.get("schema_version") != MCP_TOOLS_CALL_CONTRACT_VERSION:
        raise MCPToolsCallValidationError(
            "MCP_FIXTURE_VERSION_UNSUPPORTED",
            f"expected {MCP_TOOLS_CALL_CONTRACT_VERSION}",
        )
    if fixture.get("type") != MCP_TOOLS_CALL_FIXTURE_TYPE:
        raise MCPToolsCallValidationError(
            "MCP_FIXTURE_TYPE_INVALID", "fixture.type is not supported"
        )
    _require_text(fixture.get("id"), "fixture.id")
    tool_name = _require_text(fixture.get("tool_name"), "fixture.tool_name")
    argument_schema = _require_object(
        fixture["argument_schema"], "fixture.argument_schema"
    )
    request = _require_object(fixture["request"], "fixture.request")
    validate_mcp_tools_call_request(
        request,
        expected_tool_name=tool_name,
        argument_schema=argument_schema,
    )
    request_id = request["id"]
    if not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
        raise MCPToolsCallValidationError(
            "MCP_REQUEST_ID_INVALID", "fixture.request.id must be a string or integer"
        )
    for field in ("success_response", "tool_error_response", "protocol_error_response"):
        validate_mcp_tools_call_response(
            _require_object(fixture[field], f"fixture.{field}"),
            expected_request_id=request_id,
        )
    tool_error = fixture["tool_error_response"]["result"]
    if not isinstance(tool_error, Mapping) or tool_error.get("isError") is not True:
        raise MCPToolsCallValidationError(
            "MCP_TOOL_ERROR_SHAPE_INVALID",
            "tool_error_response.result.isError must be true",
        )
    if "error" in fixture["protocol_error_response"]:
        return
    raise MCPToolsCallValidationError(
        "MCP_PROTOCOL_ERROR_SHAPE_INVALID",
        "protocol_error_response must be a JSON-RPC error response",
    )


def load_mcp_tools_call_fixture(path: str | Path) -> dict[str, Any]:
    """Load and validate one YAML/JSON MCP tools/call fixture."""
    source_path = Path(path)
    try:
        data = yaml.safe_load(
            read_text_capped(source_path, MAX_SOURCE_BYTES, "MCP tools/call fixture")
        )
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise MCPToolsCallValidationError(
            "MCP_FIXTURE_UNREADABLE", "fixture is missing or not valid YAML/JSON"
        ) from exc
    validate_mcp_tools_call_fixture(data)
    return copy.deepcopy(dict(data))


__all__ = [
    "MCP_TOOLS_CALL_CONTRACT_VERSION",
    "MCP_TOOLS_CALL_FIXTURE_TYPE",
    "MCPToolsCallValidationError",
    "load_mcp_tools_call_fixture",
    "validate_mcp_tools_call_fixture",
    "validate_mcp_tools_call_request",
    "validate_mcp_tools_call_response",
]
