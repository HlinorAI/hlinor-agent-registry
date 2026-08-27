# Trusted runtime binding MVP

The runtime binding MVP closes the first gap described by [RFC 0001](rfcs/0001-trusted-tool-contract-runtime-binding.md): the object checked during binding is the exact callable retained and dispatched later.

It provides:

- RFC 8785 JCS SHA-256 digests for complete validated Tool Contracts and normalized arguments;
- comparison of reviewed and observed contracts before binding;
- an immutable `BoundToolRegistry` that stores exact callable references;
- Python signature normalization and Draft 2020-12 argument validation;
- resource-scope checks before policy evaluation;
- one existing `GovernanceGate` decision before exact dispatch;
- optional detached Ed25519 approval verification bound to the exact target;
- optional pre-dispatch and completion receipts through a hash-chained sink;
- optional durable circuit-breaker checks around the exact dispatch;
- optional signed agent-delegation-chain verification with bounded fan-out;
- fail-closed errors and negative security tests for drift, argument, scope, and policy denial.

```python
from hlinor_registry import BoundToolRegistry

bound = BoundToolRegistry.bind(
    reviewed_contract,
    observed_contract,
    {"records.read": read_record},
)

bound.invoke(
    "records.read",
    checker,
    agent_id="reader",
    resource="record/123",
    kwargs={"record_id": "123"},
)
```

The caller must export `observed_contract` from the exact runtime objects passed
in `runtime_tools`. The registry retains those objects and never performs a
late name lookup. With `approval_token`, `approval_trusted_keys` and a
`replay_guard`, `BoundTool` verifies a detached approval before policy
evaluation. With `receipt_sink`, it emits a pre-dispatch record and a
completion record; denied and binding-failure paths emit a blocked record.
With `circuit_breaker` and an explicit `failure_threshold`, it blocks an open
breaker before the side effect and records real tool failures in shared state.
With `delegation_chain`, `delegation_trusted_keys`, and an exact
`delegation_audience`, it verifies a signed root-to-leaf delegation chain
before policy evaluation. Child delegations require a registered fan-out
record when the chain has more than one element.

The receipt chain is tamper-evident and may be Ed25519-signed, but a sink in the
same compromised process is not independent deployment attestation. The MVP
does not verify OCI/wheel provenance, provide workload identity, or prove that
an arbitrary callable's hidden side effects match its declaration.

The `rfc8785` dependency is used for this new digest surface because the RFC
requires real JCS behavior. Existing policy-bundle and `ActionRequest` digest
formats are intentionally unchanged for compatibility.
