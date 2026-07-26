# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.5.x | Yes |
| 0.4.x | Security fixes only |
| 0.3.x | Security fixes only |
| < 0.3 | No |

## Reporting a Vulnerability

Do not report suspected vulnerabilities through public GitHub issues.
Email `team@hlinor.ai` with a description, reproduction steps, affected
version, and any known impact. We aim to acknowledge reports within 48 hours.
Please allow time for investigation and coordinated disclosure before
publishing details.

## Security Scope

Hlinor Agent Registry is an open-source reference implementation of a portable
policy manifest compiler and fail-closed action gate for AI agents. Version
0.5.x is the current stable line and adds signed bundle trust. Security issues
include bypasses of strict action enforcement,
acceptance of unlisted policy sources, signature or trust verification
bypasses, path-boundary bypasses, and governed integrations executing a tool
after a denial.

Configuration mistakes, permissive-mode behavior documented by the project,
and policies that explicitly authorize an unsafe action are generally misuse
or configuration issues rather than vulnerabilities. Reports showing that the
documented behavior creates an unexpected security bypass are still welcome.

## Trust Model and Current Guarantees

- Compilation reads only sources explicitly listed in the manifest.
- Absolute source paths and paths escaping the manifest directory are rejected.
- Unknown explicit entity types and case-colliding entity IDs are rejected.
- Compiled output is verified before atomically replacing an existing bundle.
- Production manifests reject permissive agents unless an explicit unsafe CLI
  override is supplied.
- Runtime enforcement reads a compiled JSON bundle, not authoring YAML files.
- A canonical SHA-256 digest detects accidental corruption and modifications
  made without recomputing the digest.
- Unknown agents and unknown actions in strict mode are denied.
- Blocked actions take priority over allowed actions.
- Supported integrations raise a typed governance exception before executing
  the wrapped tool when a decision is denied.
- `ActionRequest` and `PolicyDecision` bind each evaluation to canonical request
  and bundle digests, bundle version metadata, actor, and environment context.
- Signed bundles are verified against deployment-configured Ed25519 public
  keys. The signature covers the payload, digest, issuer, key ID, and validity
  window.
- Unknown signing keys, invalid signatures, expired signatures, and signatures
  issued too far in the future are rejected.
- A deployment-controlled minimum bundle revision provides an explicit
  rollback floor.

An unsigned bundle digest provides integrity checking, not authentication. A
party that can replace an unsigned bundle can also recompute its digest.
Version 0.5 adds Ed25519 bundle authentication, but trust store distribution,
private-key protection, and rollback-floor state remain deployment
responsibilities. Resource-aware and argument-aware authorization are not yet
implemented.

## Production Hardening

1. Use `enforcement_mode: strict` for production agents.
2. Review manifests and policy sources through a protected change process.
3. Restrict write access to compiled bundles and their deployment path.
4. Require signed bundles with a deployment-owned trust store and expected
   issuer.
5. Set `minimum_bundle_revision` from protected deployment state.
6. Deploy bundles as complete files and monitor digest changes.
7. Treat JSONL decision events as application audit records, not immutable or
   independently authenticated receipts.
8. Validate framework and dependency versions in your own environment.
9. Keep human approval and authorization controls outside the agent process for
   high-impact actions until request-bound approvals are implemented.

## Known Limitations

- Direct KMS/HSM signing providers are not implemented; the CLI currently reads
  an unencrypted PEM Ed25519 private key from a protected file.
- Rollback enforcement requires an external trusted minimum revision. A
  stateless verifier cannot detect rollback by itself.
- Trust-store distribution, key revocation rollout, and private-key custody are
  deployment responsibilities.
- The runtime checker is an action-name gate; policy schemas describing budget,
  rate, resource, evidence, or approval controls are not automatically enforced
  by `PolicyChecker`.
- Policy attribution is not implemented. Decisions are produced by the compiled
  allow and block lists, so the `matched_policy_ids` field on a decision and its
  audit event is reserved and always empty. Treat it as absent rather than as
  evidence that no declared policy applied.
- LangChain and CrewAI compatibility is limited to the versions listed in the
  [integration compatibility matrix](docs/integration-compatibility.md) and may
  require application-specific integration testing.
