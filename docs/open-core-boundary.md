# Open-core boundary

This repository is the public, framework-neutral OSS core of Hlinor. It is a
portable policy and verification layer, not the Hlinor hosted control plane.
The boundary below is the default for new work.

## Public OSS core

The following remain appropriate for this repository:

| Area | Public scope |
| --- | --- |
| Policy | YAML registry, compiler, schemas, `PolicyChecker`, request/decision model |
| Local enforcement | `BoundTool`, shared governance gate, decorator, and reference framework adapters |
| Contracts | Tool Contracts, drift checks, canonicalization, conformance fixtures |
| Security primitives | Request-bound approvals, receipts, replay/revocation, delegation, scope checks, rate/concurrency limits, kill switch |
| Local reference state | SQLite scoped store and replay state for development and single-node deployments |
| Framework compatibility | Reference LangChain, CrewAI, AutoGen, and custom-Python adapters |
| Verification | Synthetic examples, negative security tests, local CLI, package build and compatibility checks |

These components may be experimental, but their purpose is still portable
local verification. Their public API and behavior must not require Hlinor
Cloud, a Hlinor account, private infrastructure, or real customer data.

## Commercial/private layer

The following belongs in a separate private repository or hosted product:

| Area | Commercial capability |
| --- | --- |
| Control plane | Multi-tenant organizations, projects, agent inventory, policy UI, approvals, RBAC, SSO, billing |
| Managed identity | Key provisioning and rotation, workload identity, attestation, revocation operations, secret storage |
| Message fabric | Network delivery, routing, queues, delivery guarantees, cross-deployment identity exchange, retention |
| Audit operations | Independently operated receipt collector, immutable retention, SIEM/export connectors, alerting, incident workflows |
| Fleet intelligence | Cross-deployment drift, risk analytics, usage/cost accounting, quotas, dashboards, reports |
| Enterprise integrations | Managed MCP/A2A gateways, cloud/runtime connectors, organization-specific adapters and compliance packs |
| Operations | Hosted deployment, upgrades, availability/SLO controls, support tooling, migration and recovery automation |

The OSS repository may contain a protocol-neutral interface, a redacted
conformance fixture, or a local reference client for these areas. It must not
contain the hosted service, production control logic, tenant data model,
credential handling, or operational deployment implementation.

## Decision rule for new features

Keep a feature in OSS only when all of the following are true:

1. it is useful without a Hlinor service or account;
2. it is locally testable with synthetic data;
3. it defines a portable contract, verifier, or reference implementation;
4. it does not coordinate multiple customer deployments or hold credentials;
5. publishing it does not disclose a hosted control-plane implementation.

If a feature manages keys, tenants, hosted persistence, fleet-wide visibility,
cross-deployment delivery, or enterprise operations, design the public
interface here if useful and implement the capability outside this repository.

## Immediate roadmap consequence

The next public work is limited to maintenance, security fixes, documentation,
portable conformance tests, and narrow protocol contracts. A production MCP or
A2A gateway, hosted message delivery, key lifecycle, external attestation, and
central audit service are not OSS roadmap items in this repository.

The existing runtime-hardening primitives remain public reference
implementations. They are not being removed retroactively; the commercial
differentiator is the managed, multi-deployment operational layer built around
them.
