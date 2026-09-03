# Agent Contracts

An Agent Contract is a portable declaration of the boundary around one agent.
It makes the accountable owner, allowed goals, out-of-scope work, action levels,
approval recipients, forbidden actions, stop conditions, data access, tool
permissions, policy links, audit requirements, versioning, and failure behavior
explicit.

The public implementation is deliberately stateless. It validates the YAML and
compares it with an existing agent declaration and optional Tool Contract; it
does not create an authority store, identity provider, approval service, tenant
database, or runtime session.

## Minimal commands

Validate the shape of one contract:

```bash
PYTHONPATH=. hlinor-registry validate-agent-contract examples/agent-contract.yaml
```

Check a first-class contract against an agent and Tool Contract:

```bash
PYTHONPATH=. hlinor-registry contract verify-agent \
  --contract examples/agent-contract.yaml \
  --agent examples/search-agent.yaml \
  --tools examples/tool-contracts/customer-support-tools.yaml
```

The second command is expected to report drift when the example contract is
paired with a different agent or Tool Contract. The comparison is a review
signal; it does not grant authority and does not replace runtime enforcement.

`approval_required` uses objects rather than prose so the action and intended
approver are machine-checkable. An approval in this file is not a live approval
and cannot authorize an execution by itself.

## Public/private boundary

This repository contains the portable format, local validator, compatibility
check, and synthetic fixtures. Managed storage, RBAC/SSO, approval workflows,
tenant and fleet state, KMS/key lifecycle, workload attestation, central audit
retention, quotas, analytics, and managed MCP/A2A gateways remain outside the
public core; see [`open-core-boundary.md`](open-core-boundary.md).
