# Authenticated scoped messages

`sign_scoped_message()` and `verify_scoped_message()` provide a small,
framework-neutral envelope for ordinary cross-agent messages. The envelope is
signed with Ed25519 and binds these values together:

- `project_id` and `workspace_id`;
- sender and exact recipient agent IDs;
- message ID, nonce, issuance, expiry, and body;
- the configured sender key ID and issuer.

The receiver must supply the expected `ExecutionScope`, exact recipient ID, a
trusted key map, and a replay guard. Verification fails closed on unknown
fields, invalid signatures, sender/key mismatch, scope or recipient mismatch,
expired messages, and replay. The body is canonicalized with RFC 8785 and
bounded to 1 MiB; it remains ordinary data and is never treated as an
authorization command.

```python
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hlinor_registry import (
    ExecutionScope,
    InMemoryReplayGuard,
    MessageTrustedKey,
    sign_scoped_message,
    verify_scoped_message,
)

private_key = Ed25519PrivateKey.generate()
trusted_key = MessageTrustedKey(
    key_id="agent-a-key-1",
    agent_id="agent-a",
    public_key=private_key.public_key(),
    issuer="synthetic-registry",
)
scope = ExecutionScope("project-alpha", "workspace-1")
now = datetime.now(timezone.utc)

envelope = sign_scoped_message(
    private_key=private_key,
    key_id=trusted_key.key_id,
    issuer="synthetic-registry",
    sender_agent_id="agent-a",
    recipient_agent_id="agent-b",
    scope=scope,
    body={"kind": "status", "text": "ordinary synthetic message"},
    issued_at=(now - timedelta(seconds=1)).isoformat(),
    expires_at=(now + timedelta(minutes=5)).isoformat(),
    nonce="nonce-1",
)

verified = verify_scoped_message(
    envelope,
    trusted_keys={trusted_key.key_id: trusted_key},
    expected_scope=scope,
    expected_recipient_agent_id="agent-b",
    replay_guard=InMemoryReplayGuard(),
)
```

`InMemoryReplayGuard` is suitable for tests and one-process development.
Production receivers need a durable, shared implementation such as the
existing SQLite replay guard, with an availability policy that fails closed
when replay state cannot be checked. The current API verifies a received
envelope; it does not provide network delivery, key rotation, external
workload attestation, or independently operated audit collection. Those remain
deployment responsibilities.
