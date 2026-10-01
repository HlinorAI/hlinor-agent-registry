# MCP `tools/call` contract fixture

The public repository contains a narrow, protocol-neutral fixture for wiring a
governed Tool Contract to an MCP `tools/call` boundary:

```bash
python -m pytest tests/test_mcp_conformance.py -q
```

The fixture and validator cover the stable message shape without importing an
MCP SDK or opening a network connection:

- JSON-RPC `2.0`, request id, exact `tools/call` method, and explicit tool name;
- optional object arguments checked against a declared JSON Schema;
- optional `_meta` and task metadata preserved as opaque input;
- a successful `result` with content;
- a tool failure represented by `result.isError: true`;
- a protocol failure represented by a JSON-RPC `error` object;
- response id binding and rejection of mixed `result`/`error` responses.

The canonical synthetic fixture is
`examples/protocols/mcp-tools-call.yaml`. The public descriptor is
`registry/schema/mcp-tools-call.yaml`.

## Security boundary

Validation is necessary but does not authorize or execute anything. A
deployment must resolve `params.name` through its reviewed Tool Contract,
validate arguments, and pass the call through its governance gate before a
server-side effect. Text content, structured output, `_meta`, task metadata,
and extension members are data; they do not grant permission or approval.

Protocol-level failures such as malformed requests or an unknown tool belong
in the JSON-RPC `error` response. Failures produced by the tool itself belong
inside a valid `result` with `isError: true`, so the caller can distinguish a
transport/protocol problem from an execution outcome.

This is a local contract and conformance fixture. It does not implement MCP
transport, tool discovery, authentication, authorization, hosted routing,
external workload attestation, or independent audit collection.
