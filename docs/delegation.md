# Authenticated agent delegation

The experimental delegation API makes agent-to-agent authority explicit and
cryptographically verifiable. A delegation token is signed by a configured
key that is bound to `issuer_agent_id`; the token is not trusted because a
caller supplied that string.

Each token binds:

- issuer and subject agent IDs;
- an exact audience;
- exact action and resource-scope lists;
- session, tenant, project, and workspace context when supplied;
- issue/expiry window and nonce;
- delegation depth, maximum depth, and maximum child fan-out;
- an optional direct parent delegation ID.

`DelegationTrustedKey` may additionally bind a key to a deployment identity
and workload identity. Those values are configuration-backed identity claims;
they are not external workload attestation.

`verify_delegation_chain()` verifies the root-to-leaf signature chain, requires
each child issuer to be the previous subject, prevents scope expansion, and
requires every child to be registered in a `FanOutGuard`. A child delegation
must be registered before its token is distributed:

```python
from hlinor_registry import (
    InMemoryFanOutGuard,
    reserve_delegation_child,
    verify_delegation_chain,
)

guard = InMemoryFanOutGuard()
reserve_delegation_child(
    verified_parent,
    verified_child,
    fan_out_guard=guard,
)
verified_chain = verify_delegation_chain(
    [root_token, child_token],
    trusted_keys=delegation_trust_store,
    expected_audience="hlinor.tool-runtime",
    expected_subject_agent_id="worker",
    expected_action="read_record",
    expected_resource_scope="record/123",
    fan_out_guard=guard,
)
```

`SQLiteFanOutGuard` makes child registration, uniqueness, revocation, and the
parent's fan-out limit atomic across workers and restarts. The in-memory guard
is only for tests and one-process development.

`BoundTool.invoke()` accepts the same chain and verifies it before policy
evaluation and exact dispatch. For a transport boundary, use
`sign_delegation_transport()` and `verify_delegation_transport()` with a
durable replay guard:

```python
verified_transport = verify_delegation_transport(
    envelope,
    trusted_keys=delegation_trust_store,
    expected_audience="hlinor.tool-runtime",
    expected_sender_agent_id="worker",
    expected_sender_deployment_identity="oci:sha256:worker",
    expected_sender_workload_identity="workload:worker",
    expected_receiver_deployment_identity="oci:sha256:tool-runtime",
    expected_receiver_workload_identity="workload:tool-runtime",
    replay_guard=sqlite_replay_guard,
    fan_out_guard=fan_out_guard,
)
```

The strict envelope signs the complete chain and sender/receiver identities,
requires exact local receiver expectations, verifies every delegation key's
configured identity binding, and atomically claims the transport nonce. A
plain chain copied from a filename, package metadata, or natural-language
message is not an accepted transport. This still does not attest the process,
model, code artifact, or workload to an external identity provider.
