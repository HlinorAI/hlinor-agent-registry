# Signed request-bound approvals

`sign_approval_token()` creates a detached Ed25519 approval for one exact
request target. `verify_approval_token()` checks the signature against
deployment-configured `TrustedKey` values, the issuer, time window, agent,
action, tool, resource, normalized argument digest, session and tenant.

Single-use tokens require a `ReplayGuard`. `InMemoryReplayGuard` is provided for
tests and one-process development; `SQLiteReplayGuard` provides atomic
cross-worker claims and revocation for local deployments. A missing replay
guard is a verification error, not an invitation to accept a reusable
approval. Production deployments should put this state in a protected shared
store and define key/token revocation rollout.

```python
from hlinor_registry import (
    InMemoryReplayGuard,
    verify_approval_token,
)

verified = verify_approval_token(
    token,
    trusted_keys=approval_trust_store,
    expected_agent_id="reader",
    expected_action="read_record",
    expected_tool_id="records.read",
    expected_resource="record/123",
    expected_arguments_digest=arguments_digest,
    expected_session_id="session-1",
    replay_guard=InMemoryReplayGuard(),
)
```

`BoundTool.invoke()` performs this verification before `PolicyChecker` and
passes only the verified fields to the legacy approval policy signal. Passing a
raw `signals["approval"]` to `PolicyChecker` remains a compatibility path and
does not authenticate the approver.

The signing API accepts an Ed25519 private-key object so applications can place
key custody in a KMS/HSM adapter. It does not attest the host, process, code
artifact, or hidden side effects of the callable.
