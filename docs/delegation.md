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
evaluation and exact dispatch. A chain is an authorization input, not a proof
of process, model, workload, code-artifact, or transport identity. Deployment
identity and workspace isolation remain separate controls.
