# ActionRequest and Decision Provenance

`ActionRequest` is the canonical runtime input for policy evaluation. It is an
immutable, JSON-compatible snapshot that identifies the actor, tool, resource,
environment, optional project/workspace and approval context, and attributes
associated with one requested action.

```python
from hlinor_registry import ActionRequest, PolicyChecker

request = ActionRequest(
    request_id="req_01",
    agent_id="finance-agent",
    action="initiate_transfer",
    actor_id="service:finance-prod",
    tool_id="banking-api",
    resource="bank-account:operating",
    arguments_digest="sha256:...",
    attributes={
        "amount": 15,
        "currency": "USD",
        "recipient_status": "approved",
    },
    environment="production",
)

checker = PolicyChecker("dist/policy-bundle.json")
decision = checker.evaluate(request)
```

Every decision produced by `evaluate()` contains:

- the request ID and canonical request digest;
- the exact bundle digest and bundle version metadata;
- the enforcement mode and environment;
- matched declared policy IDs when the current evaluator can identify them;
- verified signing key ID and fingerprint, issuer, issuance time, and
  expiration time when the bundle is signed;
- a stable decision ID, result, reason code, and evaluation timestamp.

The digest binds records to exact content but is not a digital signature. It
does not authenticate the request actor, policy issuer, or audit event.

`project_id` and `workspace_id` are optional for compatibility but must be
provided together. Isolated runtime bindings include them in the digest; they
are explicit context, not values inferred from filenames, package metadata, or
agent messages.

## Compatibility

`check_action(agent_id, action)` remains supported during the 0.5 migration. It creates an
`ActionRequest` with the active bundle environment and delegates to
`evaluate()`. New integrations should use `ActionRequest` directly when actor,
resource, arguments, approval, session, or tenant context matters.

The evaluator still enforces action allowlists and blocklists. Context is
captured and bound to the decision, but contextual rules such as amount limits,
approval validation, and tenant authorization require a later evaluator model.
