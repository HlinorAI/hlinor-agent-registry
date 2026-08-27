# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added language-neutral RFC 8785 JCS golden vectors covering key ordering,
  number normalization, Unicode escaping, arrays, canonical UTF-8, and
  SHA-256 digests.
- Independently verified all published JCS vectors with Node.js
  `canonicalize@2.1.0` in addition to the Python runtime tests.
- Added the trusted runtime binding MVP for Tool Contracts: RFC 8785 digests,
  exact callable references, immutable bound registries, normalized argument
  validation, resource-scope checks, and governed dispatch.
- Added negative security tests proving contract drift, runtime tool-set drift,
  invalid arguments, resource drift, unsupported signatures, and policy denial
  block execution.
- Added project continuity documentation in `PROJECT_PLAN.md` and `TODO.md`.
- Added experimental detached Ed25519 approval tokens bound to agent, action,
  tool, resource, normalized arguments, session, and tenant.
- Added single-use replay protection interface with a thread-safe in-memory
  implementation for tests and one-process development.
- Added hash-chained execution receipts with optional Ed25519 signatures,
  verification, and fsync-backed JSONL persistence.
- Connected `BoundTool.invoke()` to signed approval verification and receipts for
  pre-dispatch, completion, denial, and binding-failure outcomes.

### Security

- Added exact Gitleaks fingerprints for six reviewed synthetic false positives
  from the initial runtime-receipt history scan; future findings remain
  blocking.
- Runtime binding compares reviewed and observed Tool Contract digests before
  retaining a callable and never performs a late name lookup at dispatch.
- Tool arguments are normalized and validated against the reviewed JSON Schema
  before policy evaluation and execution.
- Single-use approvals fail closed without a replay guard; receipt persistence
  commits to the in-memory chain only after a durable JSONL write succeeds.
- Added SQLite-backed atomic replay claims and token revocation, including
  cross-worker race tests.
- Added a persistent SQLite circuit breaker with closed/open/half-open states,
  one-probe recovery, threshold consistency checks, and `BoundTool` dispatch
  blocking after real tool failures.
- Added checkpointed JSONL receipt resume with full shape/chain verification,
  atomic checkpoint replacement, and fail-closed behavior after persistence
  uncertainty.
- Added `FailClosedReceiptSink` as the no-retry boundary for external receipt
  collectors; collector errors block pre-dispatch receipt delivery without
  exposing collector internals.
- Added experimental signed agent delegation chains with issuer-key binding,
  audience/context checks, scope attenuation, depth limits, revocation, and
  atomic SQLite bounded fan-out registration.
- Added experimental SQLite runtime limits for per-scope rate/concurrency
  admission and a shared kill switch, with lease release wired into
  `BoundTool.invoke()`.

## [0.10.0] - 2026-08-03

### Added

- Added `UNSCOPED_ALLOW_PERMISSION`, reported when an allowed entry names an
  action with no resource while the tool of that name always operates with
  one. The two halves of that mistake -- a permission covering no tool, and a
  tool covered by no permission -- were previously reported as unrelated
  findings in separate sections of the report. The message now carries the
  pattern to write instead, and a test applies that suggestion and asserts it
  resolves the finding, because advice that does not fix the problem is worse
  than none.
- Added the opt-in, bounded, thread-safe `PolicyBundleCache` for applications
  that intentionally create multiple checkers for the same verified bundle.
- Added explicit per-path invalidation, full-cache clearing, LRU capacity, and
  cache observability counters.

### Changed

- `UNDECLARED_TOOL_SCOPE` now reports one finding per tool listing every
  uncovered scope, instead of one finding per scope. A tool declaring both
  `http/*` and `https/*` produced two identical-looking lines. Checked against
  an agent with sixteen enabled toolsets and thirty tools, the two changes
  together took the report from 47 findings to 23 without dropping a single
  distinct problem.

### Security

- Bound cache entries to the exact bundle bytes, resolved path, verification
  settings, trusted public keys, and file-backed trust material.
- Recheck signature validity on every cache hit and keep mutable runtime state
  isolated between checker instances.
- Expanded reload fingerprints with device, inode, change time, modification
  time, and size, and fail when a bundle changes while it is being loaded.

### Fixed

- Fixed the release wheel smoke test to compare the documented
  `hlinor-registry X.Y.Z` CLI output instead of expecting a bare version.
- Added a reviewed manual recovery path that checks out and retests an existing
  immutable release tag when workflow logic fails before PyPI publication.
- Required manual release recovery to start from `main` and documented the
  narrow, temporary PyPI environment exception plus mandatory restoration.

## [0.9.0] - 2026-07-31

### Added

- Published RFC 0001 and its threat model for a future trusted Tool Contract
  runtime binding, covering canonical digests, detached signatures, exact tool
  identity, argument validation, resource scope, rollback protection, and
  fail-closed dispatch.
- Added reproducible single-agent and eight-worker `PolicyChecker` benchmarks,
  documented latency and throughput budgets, and a Python 3.11 CI regression
  guardrail with machine-readable output.
- Published Tool Contract schema `1.0` as the first stable capability contract
  with explicit backward-compatibility, exact-reader, deprecation, and
  migration guarantees.
- Added a canonical `1.0` compatibility fixture that future readers must keep
  valid, plus tests separating document schema versions from tool-set versions.
- Exposed `TOOL_CONTRACT_SCHEMA_VERSION` and `tool_contract_schema` through the
  public Python API.
- Added the versioned policy-test suite format for deterministic requests,
  expected decisions, reason codes, and matched policy IDs.
- Added `hlinor-registry test-policies` with stable text and JSON reports plus
  distinct success, expectation-failure, and invalid-input exit codes.
- Added an injectable `PolicyChecker` clock for reproducible freshness tests
  while preserving the system UTC clock as the production default.
- Added a synthetic refund-policy suite and run it through the public
  compile-to-test path in CI.
- Added the versioned, framework-neutral Tool Contract format for describing
  concrete tool IDs, governed actions, JSON Schema inputs, resource patterns,
  observable effects, and safety annotations.
- Added `hlinor-registry validate-tool-contract` and the fail-closed
  `load_tool_contract` Python API for YAML and JSON contracts.
- Added a packaged JSON Schema Draft 2020-12 artifact and a synthetic customer
  support contract example.
- Added deterministic agent-to-tool drift detection for undeclared tool scopes,
  stale allow permissions, and stale block permissions.
- Added `hlinor-registry contract check` and `contract diff` with stable text
  and JSON reports plus CI-friendly aligned, drift, and input-error exit codes.
- Added governance-shape comparison for tool additions, removals, actions,
  input schemas, resource scopes, effects, annotations, and contract identity.
- Added LangChain and CrewAI Tool Contract exporters that read framework tool
  names, descriptions, and argument schemas without invoking tools.
- Added explicit `ToolGovernance` metadata for effects, resource scopes, action
  mapping, stable tool IDs, and safety annotations that frameworks cannot
  infer reliably.
- Added validated, atomic YAML and JSON output through
  `write_tool_contract`.
- Added Microsoft AutoGen Core Tool Contract export through the public
  `BaseTool.schema` protocol without invoking tools.
- Added framework-neutral custom Python Tool Contract export with explicit
  input schemas and callable-derived names and descriptions.
- Added an `autogen` optional dependency, pinned AutoGen compatibility tests,
  and runnable AutoGen and custom Python export examples.

### Security

- Tool Contract readers now return one stable fail-closed error for every
  unsupported schema version, including unknown future `1.x` versions, rather
  than relying on a generic JSON Schema constant mismatch.
- Release distributions are now built once, tested in a clean environment,
  attested, and passed unchanged to PyPI and GitHub Releases. Publishing no
  longer rebuilds a second, untested copy of the package.
- CI now compares the SHA-256 digest of every published PyPI file with the
  corresponding artifact produced by the release build. A filename or digest
  mismatch fails the release.
- GitHub build provenance and PyPI Trusted Publishing attestations are emitted
  for release distributions.
- Repository rules now prevent `v*` release tags from being updated or deleted.
  The PyPI environment accepts deployments only from `v*` tags and no longer
  permits administrator bypass.
- Tool Contract loading rejects unknown fields, unsupported versions,
  non-JSON YAML values, invalid nested argument schemas, case-colliding IDs,
  malformed resource patterns, and contradictory safety annotations instead
  of producing a partial descriptor.
- Contract drift commands validate every input before comparison and return a
  distinct error exit code instead of reporting invalid data as policy drift.
- Framework export fails when governance is missing or stale, tool identities
  collide, input schemas are unusable, or the final contract is invalid.

### Changed

- GitHub Releases now include the exact wheel, source distribution, and
  `SHA256SUMS` manifest published by the workflow.
- Release automation refuses to edit an existing GitHub Release. Duplicate or
  moved release state now fails visibly instead of rewriting published notes.
- Added a Git-ignored `.private/` location for local roadmaps and internal
  planning that must not enter the public repository.
- Updated the release checklist to describe the immutable artifact path,
  digest verification, provenance checks, and repository protections.

## [0.8.1] - 2026-07-28

A patch release, and the reason it is one: three of the findings below are in
code 0.8.0 shipped, and the release pipeline that published it ran no tests.

`resource` and `signals` on the framework wrappers are new parameters, which by
a strict reading is a minor version. They are here because without them the two
features 0.8.0 added could not be reached through the integrations this project
tells people to use -- repairing something unreachable rather than adding
something new. Getting the security fixes out quickly won the argument.

### Security

Found by a read-only review of the published 0.8.0 and reproduced before being
touched. All are in code shipped by 0.8.0.

- **A typed policy that could not be enforced disappeared instead of failing.**
  `load_policy_rules` skipped every unusable compiled shape -- unknown handler
  kind, non-list trigger, malformed config -- so the policy vanished from the
  agent's rules while the agent file still declared it, and the gated action
  was allowed and recorded `EXPLICITLY_ALLOWED`. Two shapes were worse: an
  empty trigger produced a rule that matched nothing, and a trigger holding a
  non-string was filtered down to its valid entries, turning an invalid policy
  into a valid narrower one. All of these now reject the bundle. A policy with
  no `kind` remains prose and still produces no rule.
  The compiler refuses these shapes, so no YAML written through the official
  path reaches them; a bundle from another implementation, a custom signing
  pipeline, a hand-edited development bundle, or a compiler/runtime version
  skew does.
- **Non-string entries in an agent's `policies` list were filtered out.** A
  declared contract could be dropped without anything being said. The bundle is
  now refused.
- **`max_age_seconds` accepted NaN and infinity.** Every ordered comparison
  with NaN is false, and the check was `value <= 0`. PyYAML parses `.nan` and
  `.inf` as floats, so both were writable in a policy file. Canonical JSON
  refused them at compile time, so validation and compilation disagreed about
  what is valid and the resulting error named neither the field nor the reason.
  The check now requires a finite positive number, and a key present with a
  null value is an error rather than an absent window.

### Changed

- **A release no longer publishes before its tests run.** `Tests & Validation`
  triggers on `push: branches: [main]`, which a tag push does not match, so the
  release workflow reached PyPI having run nothing. The test workflow is now
  callable and the publish job depends on it against the tagged commit.
- **`skip-existing` removed from the PyPI publish step.** It was added when
  tags were still being force-pushed during a history rewrite. Its failure mode
  is worse than the one it prevented: move a tag to different source, re-run,
  and PyPI correctly refuses to replace the published version while the
  workflow reports success, leaving tag and artifact disagreeing silently.
- The quickstart ends at a governed function rather than a CLI answer, and
  bundle signing moves out of the newcomer's path into a Production hardening
  section. Both python examples in the new step were executed to confirm they
  behave as their comments claim.

### Fixed

- **`init` shipped a template that the next command complained about.** The
  generated agent declared a policy, a validator and a skill that nothing
  evaluated, so running `compile` -- the command `init` tells you to run --
  reported that the file just written declares a policy it does not enforce.
  The template also predated 0.8.0 and showed neither resource patterns nor
  typed policies, so a short evaluation came away with the model the project
  had two releases ago. `init` now writes a manifest, an agent with a scoped
  allow list, and a typed policy the agent opts into; compiling them reports an
  enforced policy instead of a warning.

### Added

- **`resource` and `signals` on `@governed`, `GovernedTool` and
  `GovernedCrewTool`.** The wrappers built every request from an agent id and
  an action name, so an agent whose allow list scopes an action to a resource,
  or whose policy requires an approval, could not be governed through them at
  all: both 0.8.0 features were reachable only by calling `PolicyChecker`
  directly. A decorated call against `refund_payment:order/*` was denied
  `ACTION_NOT_ALLOWLISTED` -- the wrong reason, indistinguishable from
  enforcement working. Either parameter may be a fixed value or a callable
  receiving the invocation, so the resource can be derived from the arguments
  of the call being authorized. Combining them with a `request_factory` raises,
  because a factory builds the whole request and silently dropping a
  configured resource is the defect class this project keeps closing.

## [0.8.0] - 2026-07-28

Two layers of the same idea. An action list entry can now name the resources it
covers, and a policy can require that a permitted action still discharge an
obligation before it runs. Together they are what `matched_policy_ids` was
reserved for since 0.6.0.

**Breaking: the request digest changes.** `ActionRequest.signals` is part of the
canonical representation, so digests recomputed after upgrading will not match
digests recorded before it. Signals had to be inside the digest -- a decision
record that could not distinguish a request carrying an approval from one
without it would leave the field the decision turned on as the one field nobody
could verify afterwards.

### Added

- **Typed policies.** A policy is its own file with `type: policy`, compiled
  into the bundle, and an agent opts in by naming its id. It carries a
  `trigger` using the action pattern syntax and a handler `kind`:
  `requires_approval`, `requires_evidence`, or `failure_threshold`. An
  unrecognised kind is refused at compile time rather than skipped, because a
  policy that silently applies to nothing reads, in the registry, exactly like
  one that is in force.
- `ActionRequest.signals` carries the material a policy reads: an approval,
  evidence claims, a failure count.
- `PolicyDecision.matched_policy_ids` names the typed policies that were
  evaluated, and `policy_detail` says which one refused and what was missing.
  Both appear in the audit event. The field has been reserved and empty since
  0.6.0, when a fabricated version of it was removed.
- `hlinor-registry compile` prints, per agent, which declared policies are
  enforced and which have no compiled policy behind them. Dropping a policy
  file from the manifest otherwise removes enforcement with nothing in the
  agent file changing.
- `hlinor-registry check` prints the policy detail on a denial, so an action
  that needs an approval nobody attached is distinguishable from one that is
  simply forbidden.
- `hlinor-registry check` and `explain` accept `--resource` and
  `--signals-file`. Without them the CLI could only ask about a bare action
  name, so an agent whose permission is scoped or policy-gated could not be
  exercised from the terminal at all -- and would be reported as
  `ACTION_NOT_ALLOWLISTED` for an action it is in fact permitted to perform.
- **Action list entries may be patterns, so a permission can name the resources
  it covers.** An entry is matched against `action:resource`, built from
  `ActionRequest.resource`, and `*` and `?` are the whole vocabulary:
  `read:report:quarterly/*` permits reads of quarterly reports and nothing
  else. Before this, `PolicyChecker` compared action names and ignored
  `resource` entirely, so "may read reports" and "may read *these* reports"
  were the same statement.
- `PolicyDecision.matched_pattern` and the corresponding audit field name the
  entry that produced the decision, so a record can say *denied by
  `send:email:external:*`* instead of *denied*. Computed from the comparison
  that was made, unlike the reserved `matched_policy_ids`.
- `hlinor-registry lint` reports allow patterns that reach past their apparent
  scope. `*` crosses `:`, so `send:email:*` covers `send:email:external:someone`
  and is held in bounds only by the block list; deleting that block entry
  widens the agent with no visible change to the allow list. Reported as a note
  rather than a warning, because with no negation in the syntax this is the
  only way to write that intent, and `lint` still exits 0.
- `hlinor-registry lint` warns — and fails — when `allowed_actions` contains
  `*`, which is permissive enforcement written in the allow list.

### Security

Three fail-open cases in the typed-policy work, all found by an external review
of the unreleased branch and all reproduced before being fixed. None of them
reached a published package.

- **A future-dated timestamp satisfied every freshness check.** Age is computed
  as `now - timestamp`, so a timestamp ahead of the clock produced a negative
  age and `age > max_age_seconds` was false for it: an approval dated a year
  from now read as fresher than one issued a second ago. Freshness is now a
  window with both ends, sharing one helper between approvals and evidence, and
  allowing 30 seconds of clock skew. A negative age is reported rather than
  clamped, so the audit record says the timestamp was wrong instead of calling
  it fresh.
- **`same_resource: true` switched itself off when the request named no
  resource.** The comparison was skipped instead of failing, so an action with
  no resource accepted evidence about anything — the binding disappeared in
  exactly the case where nothing else constrained the claim. The request must
  now name a resource for the policy to be satisfiable.
- **Boolean policy switches were read with Python truthiness.**
  `bind_to_request: 0` disabled request binding, and `same_resource: ""`
  disabled resource binding, without being valid booleans. Both are now
  rejected during authoring validation and when a compiled bundle is loaded,
  because a bundle can be produced by another implementation or edited by hand
  and a runtime that trusts the artifact it verifies verifies nothing.

### Fixed

- **`explain` described a decision model that no longer existed.** It assumed
  every denial came from the action lists and every allowance was explicit, so
  an operator denied for a missing approval was told to add the action to
  `allowed_actions` — advice that removes a control to work around a control
  that was working. Explanation text is now derived from `reason_code`,
  `matched_pattern` and `policy_detail`, with a branch per reason code the
  runtime can produce and a test that fails if one is added without it.
- **A bare block-list entry stopped covering scoped requests.** Introduced
  earlier in this release by the action pattern work: with the block list
  matched only against `action:resource`, `blocked_actions: [delete_records]`
  kept refusing the unscoped call and began permitting `delete_records` on
  `customer/5`. Permissive mode is where it bit, since there the block list is
  the only thing saying no, and it triggered on nothing more than a caller
  populating `ActionRequest.resource` -- a field that has existed since 0.4.
  The block list is now matched against the action alone as well as the full
  key, which can only widen it. Found by running a pre-existing bundle rather
  than by reading the diff.

### Changed

- Policies are evaluated after the allow list and can only refuse. A satisfied
  policy can never re-enable something the block list refuses or the allow list
  omits, so the action lists remain readable as the outer bound of what an
  agent can do.
- `validate-policy` checks the enforceable part of a policy file: handler kind,
  trigger syntax, and the fields each kind cannot work without. A policy with
  no `kind` remains valid prose.
- Authoring validation no longer rejects `*` and `?` in action names. Anything
  outside the supported syntax — `**`, character classes, alternation,
  negation — is still rejected, now with a message naming the construct and
  what to use instead.

### Compatibility

An action list entry with no wildcard is an exact match, so every list written
before this release decides as it did. An agent's `policies:` entries behave
exactly as before unless a typed policy with that id is compiled into the same
bundle, so upgrading turns no existing documentation into a denial. Callers
that never set `resource` or `signals` see the same decisions, with the digest
caveat above.

## [0.7.0] - 2026-07-27

Follow-up to the 0.6.0 review, acting on a second external code review that
agreed with most of it and caught two things it had missed.

**One breaking change.** In permissive mode the reason code on an allowance is
now `ALLOWED_NOT_BLOCKLISTED` rather than `EXPLICITLY_ALLOWED`. Anything
matching reason codes as strings — a log filter, a dashboard query, an
assertion — has to account for it. Strict mode is unaffected: there, every
allowance is explicit and still reports `EXPLICITLY_ALLOWED`.

### Security

- **A permissive-mode allowance is no longer reported as explicit.** An action
  nobody had listed was allowed and recorded as `EXPLICITLY_ALLOWED`; nothing
  explicitly allowed it. New reason code `ALLOWED_NOT_BLOCKLISTED` records that
  the policy is silent about the action. Same defect class as the fabricated
  `matched_policy_ids` removed in 0.6.0: a claim in the audit record that the
  policy does not support. Strict-mode allowances are unchanged.
- Runtime dependencies carry upper bounds, so a major release of the crypto or
  parsing library cannot arrive silently on the next install.
- GitHub Actions are pinned to commit SHAs rather than mutable major tags.
- Parsed files are size-capped before being read: 1 MB for a trust store, 4 MB
  for a policy source, 64 MB for a compiled bundle. A wrong path now fails with
  a diagnosis instead of exhausting memory. YAML alias expansion remains
  unbounded and is documented as such.

### Added

- A README table stating, concern by concern, what `PolicyChecker` enforces at
  runtime and what is only validated at compile time. Five rows are enforced,
  eight are not. Every pattern document carries the same scope note.
- Compiled capabilities are readable through `PolicyChecker.capabilities` and
  `get_capability_info()`. They were written into every bundle and never read.
  They remain outside enforcement by design.

### Changed

- `main()` dispatches subcommands one way instead of two. Four parsers set an
  argparse `func` default that nothing called, while a 135-line if-chain
  repeated an identical block nine times beside a table that already expressed
  it. `cli.py` drops from 1117 to 1010 lines with no behaviour change.
- The PyPI publish step skips versions already published, so a re-pushed tag no
  longer fails the release workflow for what is a no-op.

## [0.6.0] - 2026-07-27

This release is the result of an external security and architecture review.
Every finding is described below in the terms that matter to a user of the
package: what was wrong, what changes, and whether it changes behaviour. Two of
the fixes do; both are marked.

### Security

- **Signature enforcement no longer depends on the artifact being verified.**
  Under the default `signature_policy="auto"`, whether a signature was required
  came from `metadata.environment` inside the bundle. An attacker able to
  rewrite the deployed file could delete the `signature` object, set the
  environment to `development`, recompute the digest, and load a tampered
  policy with authentication silently disabled — even with a trust store
  configured. A `PolicyChecker` given `trust_store` or `trusted_keys` now
  requires a signed bundle. `signature_policy="optional"` remains the
  documented explicit override.
- **A blocked action can no longer be reached through a case variant.**
  Matching was exact, so in permissive mode an agent blocked from
  `Initiate_Transfer` could run `initiate_transfer`, and `allowed: [Read_DB]`
  beside `blocked: [read_db]` read as a block while permitting the request.
  Block-list matching is now case-insensitive; allow-list matching stays exact
  so an approval is never extended to a spelling that was not literally
  approved. Authoring validation rejects action names that differ only by case.
- **Removed fabricated policy attribution from audit records.**
  `matched_policy_ids` was filled from a hard-coded three-entry action-to-policy
  table that matched only the shipped examples, putting an unverifiable claim
  into a record that reads as compliance evidence. The field is reserved and
  always empty until real policy evaluation exists.
- **`GovernedAgent` no longer leaves ungoverned tools reachable.** Tools
  discovered on `executor.agent` were wrapped but written back to `executor`,
  so the originals stayed available on the object that owned them. Constructing
  a `GovernedAgent` over an executor with no tools now raises rather than
  silently governing nothing.
- Bounded the signature validity window: signing warns above 90 days and
  refuses above 366. Without a revocation channel, expiry is the only mechanism
  that forces a leaked bundle out of circulation, and nothing prevented
  `--expires-at 2099-01-01`.
- Trust store entries with a relative `public_key_path` must resolve inside the
  trust store directory, matching the boundary already enforced on policy
  sources. Absolute paths remain an explicit deployment choice.
- `load_public_key` treated any string without a PEM header as a filesystem
  path, turning an unintended value into a file read. Strings containing
  newlines or NULs are rejected rather than opened.
- A bundle declaring an unrecognized `enforcement_mode` is rejected instead of
  silently coerced to `strict`. Coercion failed closed but hid a disagreement
  between the compiler that produced the bundle and the runtime reading it.
- The landing page no longer executes third-party code. It loaded the Tailwind
  Play CDN and three Prism files from cdnjs with no subresource integrity; both
  are now built and vendored, and the page loads no external subresource.
- CI scans history with gitleaks and enforces a public-scope rule over every
  tracked file. A matching pre-commit hook rejects internal paths, one-off
  patch-script filenames, and files containing local absolute paths or PEM
  private keys.

### Changed

- **Breaking for scripts.** `check` and `explain` now exit `0` for allowed, `1`
  for denied, and `2` when no decision could be reached: missing or unreadable
  bundle, broken trust configuration, or a failed audit-log write. Every
  failure previously shared exit `1` with a denial, so a pipeline gating on a
  non-zero exit read a broken deployment as working governance. Error messages
  moved from stdout to stderr. Gate on `1` specifically.
- Runtime trust re-verification runs only when the trust material changes.
  Every governed call previously re-read the trust store, re-parsed each PEM,
  rebuilt the canonical JSON of the whole bundle and re-checked the signature,
  so the cost of a decision scaled with bundle size: 4.6 ms per call on a 74 KB
  bundle, now 129 µs and flat. Key revocation still takes effect immediately —
  the fingerprint covers the referenced PEM files by content, not just the
  trust store — and the validity window is still checked on every call.
- `DecisionResult` and `ReasonCode` have a single definition in
  `hlinor_registry.enums`; `hlinor_registry.decision` re-exports them. The two
  copies had drifted, and emitting a reason code present in only one would have
  raised `ValueError` inside the path that constructs a denial.
- `TrustedKey` records the PEM path an entry was loaded from, so a long-lived
  verifier can detect a key replaced in place.
- The repository manifest `registry.yaml` declares the `development`
  environment so the documented `compile` then `check` path works on a fresh
  clone. Production deployments should set `production` and sign the bundle.

### Fixed

- Added the missing `langchain` extra. `pip install "hlinor-registry[langchain]"`
  was documented in the README but never declared, so pip warned and installed
  nothing while the next line of the same README section raised `ImportError`.
- Corrected the README blocklist example, which asserted an output that did not
  match its own input.
- `make lint` covers `scripts/`.

### Added

- CI exercises the documented quickstart end to end, asserts the exit-code
  contract, verifies a signed bundle through a generated key and trust store,
  and asserts that every extra the README tells users to install is declared.
- `scripts/check_public_scope.py`, run by both pre-commit and CI.
- `scripts/build_landing_assets.sh` to regenerate the vendored landing assets.
- Working entries in `registry/`, one per contract type, cross-referencing each
  other and validated in CI. The five directories previously held nothing.
- README sections placing the project against content-safety tooling and
  against OPA/Cedar, replacing a comparison table that listed LangChain and
  CrewAI — the frameworks this project integrates with — as alternatives.

## [0.5.0] - 2026-07-26

### Added

- Ed25519 policy bundle signatures with trusted key IDs, issuers, and explicit
  issuance and expiration windows.
- Deployment-owned JSON trust stores and strict runtime signature verification.
- `verify-bundle` CLI command for integrity, trust, validity, and rollback-floor
  checks.
- Signing key IDs, verified public-key fingerprints, issuers, and validity
  windows in `PolicyDecision` and JSONL audit events.
- Security-negative tests for payload replacement, digest recomputation,
  untrusted keys, invalid issuers, expiration, future issuance, and rollback.
- A shared integration gate that creates one immutable `ActionRequest`, emits
  one `PolicyDecision`, and blocks tool execution on denial.
- Native async contracts and checker injection for LangChain, CrewAI, and
  framework-agnostic decorators.
- A versioned integration compatibility matrix and real-framework CI jobs.

### Changed

- The package version is `0.5.0`.
- Unsigned production bundles are rejected by the default `auto` signature
  policy; production deployments should set `signature_policy="required"`.
- Long-lived checkers revalidate signature expiry and configured trust roots
  before every signed-bundle evaluation.
- `GovernedTool` is now a real LangChain `BaseTool` that preserves schemas,
  metadata, callbacks, and sync/async behavior.
- `GovernedCrewTool` now reuses a persistent checker and preserves wrapped
  CrewAI tool schemas.
- `PolicyViolationError` is now a compatibility alias for the shared
  `GovernanceDeniedError`.
- Expanded Ruff format and lint checks to runnable Python examples.
- Split PyPI publication and post-publish verification into independently
  retryable release jobs.
- Added a bounded clean-environment installation check for every published
  package version.
- Updated installation and release documentation to match the current package
  dependencies and Trusted Publishing workflow.

## [0.4.2] - 2026-07-26

### Added

- Provenance-aware JSONL decision events with the active policy bundle digest.
- Optional durable JSONL audit sinks for `check` and `explain`.
- Controlled bundle refresh for long-lived LangChain and decorator integrations.
- Contract tests for decorators and the optional CrewAI integration.
- Atomic bundle writes, schema/compiler revision metadata, and separate agent
  and capability namespaces.
- Immutable `ActionRequest` evaluation with request digests, actor/resource
  context, matched policy IDs, and request-to-bundle decision provenance.
- Stable `DecisionResult` and `ReasonCode` enums that retain string-compatible
  JSON values.

### Changed

- `explain --format jsonl` now emits one machine-readable record without text output.
- CrewAI, LangChain, and decorator integrations share the `GovernanceDeniedError` contract.
- CI now runs linting, type checks, and YAML linting; development extras include the required tooling.
- Compiler validation rejects unknown entity types, normalized ID collisions,
  unsupported schema majors, and permissive production agents by default.

## [0.4.1] - 2026-07-25

### Added

- Zero-friction `init`, `check`, `explain`, and policy lint CLI commands.
- Optional CrewAI integration and framework-agnostic `@governed` decorator.
- Makefile, pre-commit configuration, and YAML linting defaults.

## [0.4.0] - 2026-07-23

### Added

- Explicit `registry.yaml` manifests and the `compile` command for deterministic policy bundles.
- SHA-256 digests for source entries and integrity-checked compiled bundles.
- Runtime tests for path traversal protection, duplicate IDs, tamper detection, and unlisted files.

### Changed

- `PolicyChecker` now loads only compiled JSON bundles and no longer scans directories at runtime.
- LangChain integrations accept a compiled `bundle_path` for governed tool execution.

## [0.3.1] - 2026-07-22

### Added

- Capability registration schema, validator, CLI command, and Funding Intelligence integration example.
- Runtime `PolicyChecker` for declarative allowlist and blocklist enforcement.
- Financial audit and budget-limited research agent examples.
- Optional LangChain integration with `GovernedTool` and `GovernedAgent`.
- GitHub Actions validation across Python 3.10 through 3.13.
- Comprehensive tests for policy enforcement and framework integration.

### Changed

- Expanded package metadata for PyPI discovery and release tooling.
- Documented optional integrations and runtime governance in the README.

### Security

- Runtime policy checks block unauthorized agent actions before tool execution.
- Declarative action boundaries support fine-grained allowlist and blocklist control.
- Existing audit-oriented schemas remain available for execution receipts and governance records.

## [0.3.0]

Public registry release with YAML schemas, CLI validation, runtime governance
contracts, lifecycle schemas, and audit-friendly examples.

[Unreleased]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/HlinorAI/hlinor-agent-registry/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/HlinorAI/hlinor-agent-registry/releases/tag/v0.3.0
