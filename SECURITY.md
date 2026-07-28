# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.7.x | Yes |
| 0.6.x | Security fixes only |
| 0.5.x | Security fixes only |
| < 0.5 | No |

## Reporting a Vulnerability

Do not report suspected vulnerabilities through public GitHub issues.
Email `team@hlinor.ai` with a description, reproduction steps, affected
version, and any known impact. We aim to acknowledge reports within 48 hours.
Please allow time for investigation and coordinated disclosure before
publishing details.

## Security Scope

Hlinor Agent Registry is an open-source reference implementation of a portable
policy manifest compiler and fail-closed action gate for AI agents. Version
0.7.x is the current stable line. Security issues
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
- An allowance names its own basis. `EXPLICITLY_ALLOWED` means the action is on
  the allow list. `ALLOWED_NOT_BLOCKLISTED` means permissive mode permitted an
  action the policy never mentions. The audit record does not present the
  second as the first.
- Supported integrations raise a typed governance exception before executing
  the wrapped tool when a decision is denied.
- `ActionRequest` and `PolicyDecision` bind each evaluation to canonical request
  and bundle digests, bundle version metadata, actor, and environment context.
- Signed bundles are verified against deployment-configured Ed25519 public
  keys. The signature covers the payload, digest, issuer, key ID, and validity
  window.
- Unknown signing keys, invalid signatures, expired signatures, and signatures
  issued too far in the future are rejected.
- Signing warns above a 90-day validity window and refuses above 366 days.
  Without a revocation channel, expiry is what forces a leaked bundle out of
  circulation.
- Trust store entries with a relative `public_key_path` must stay inside the
  trust store directory. Absolute paths remain an explicit deployment choice.
- A bundle declaring an `enforcement_mode` the runtime does not recognize is
  rejected rather than coerced, so a compiler and runtime that disagree are
  visible instead of silently reconciled.
- A deployment-controlled minimum bundle revision provides an explicit
  rollback floor.
- Parsed files are size-capped before they are read, so a truncated download or
  a wrong path fails with a diagnosis instead of exhausting memory.
- Runtime dependencies carry upper version bounds and GitHub Actions are pinned
  to commit SHAs, so neither changes under the project without a decision.

An unsigned bundle digest provides integrity checking, not authentication. A
party that can replace an unsigned bundle can also recompute its digest.
Version 0.5 adds Ed25519 bundle authentication, but trust store distribution,
private-key protection, and rollback-floor state remain deployment
responsibilities. Action patterns give resource-aware authorization when the
caller supplies `ActionRequest.resource`; argument-aware authorization is not
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
- The runtime checker is a name-and-pattern gate over the action and the
  resource string the caller supplies. Policy schemas describing budget, rate,
  evidence, or approval controls are not automatically enforced by
  `PolicyChecker`.
- A resource-scoped decision is only as good as the resource string the caller
  passes. `PolicyChecker` cannot verify that `report:quarterly/q1` is the file
  the tool actually opened; the adapter that builds the `ActionRequest` owns
  that correspondence. Derive the resource from the same value the tool will
  use, not from a parallel one.
- `*` in a pattern crosses the `:` separator, so `send:email:*` also covers
  `send:email:external:someone`. `hlinor-registry lint` warns when an allow
  pattern covers a block pattern beside it, but the warning is advisory:
  nothing prevents compiling a bundle whose allow list is broader than its
  author intended.
- Policy attribution covers typed policies only. `matched_policy_ids` names the
  compiled policies whose trigger matched the request. An agent's `policies:`
  entry with no compiled policy behind it is documentation and never appears
  there, so an empty list means "no typed policy applied", not "no declared
  constraint was relevant". `hlinor-registry compile` prints which entries are
  enforced and which are not.
- **Policy signals are asserted by the caller, not verified.** A
  `requires_approval` policy enforces that the request carries an approval
  bound to it and inside the freshness window; it cannot establish that a human
  ever granted that approval. `PolicyChecker` runs inside the process it
  governs and has no independent channel to an approval system. The same holds
  for evidence claims and failure counts. These gates stop omissions and
  mistakes -- an adapter that forgot to wire approval, an approval replayed
  onto a different request, a stale claim -- and do not stop an adapter that
  fabricates the signal. Making them resistant to that requires the approval to
  be independently verifiable, for example a signed token checked against a
  trust store the way bundles already are, which is not implemented.
- Freshness is bounded on both sides. A signal timestamp more than 30 seconds
  ahead of the checker's clock is refused rather than treated as very fresh;
  the allowance exists because machines disagree by seconds, not because a
  future timestamp is acceptable. `bind_to_request` and `same_resource` must be
  real booleans in both the authored file and the compiled bundle, so a binding
  check cannot be disabled by a value that is merely falsy.
- A `failure_threshold` policy compares a count the caller reports. The checker
  keeps no state between requests, deliberately: an in-process counter would
  reset on restart and would not be shared between workers, so it would report
  a protection that a second process does not have. What the bundle contributes
  is the threshold as a reviewed, signed number rather than a constant in
  application code.
- YAML alias expansion is not bounded. Size limits cap the input, but a small
  file with nested anchors can still expand disproportionately. Policy sources
  are named explicitly in a manifest the deployment controls, so this is a
  self-inflicted denial of service rather than an attack path; compile in an
  environment where that is acceptable.
- LangChain and CrewAI compatibility is limited to the versions listed in the
  [integration compatibility matrix](docs/integration-compatibility.md) and may
  require application-specific integration testing.
