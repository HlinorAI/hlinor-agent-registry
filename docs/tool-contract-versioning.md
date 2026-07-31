# Tool Contract compatibility and migration policy

## Stability status

Tool Contract schema `1.0` is the first stable Hlinor Tool Contract format.
Contracts that validate as `1.0` are compatibility fixtures for every future
Hlinor reader that supports schema major version `1`.

This stability promise applies to the declarative contract format. It does not
make Tool Contracts a runtime authorization source: `PolicyChecker` still
enforces compiled agent policies, not Tool Contract files.

## Two independent versions

Every contract has two version fields:

| Field | Owner | Meaning |
| --- | --- | --- |
| `schema_version` | HlinorAI | Version of the Tool Contract document format |
| `version` | Contract owner | Semantic version of the described tool set |

Changing a tool, action, argument schema, resource scope, effect, or annotation
changes the described tool set and should update `version`. It does not change
`schema_version` unless the Hlinor document format itself changes.

## Reader compatibility

Readers accept only schema versions they implement.

| Contract schema | Current `1.0` reader | Future compatible `1.x` reader |
| --- | --- | --- |
| `1.0` | Accept | Must accept |
| Future `1.x` | Reject | Accept only when explicitly implemented |
| Future `2.x` | Reject | Reject until explicitly implemented |

Exact-version reading is intentional. Tool Contracts reject unknown fields,
and silently ignoring a field added by a future schema could discard a
security effect, annotation, or resource boundary. An old reader therefore
fails closed instead of claiming partial forward compatibility.

## Schema change rules

The following guarantees apply to Tool Contract schema `1.x`:

- existing field names, types, and meanings are not removed or weakened;
- a field that is required in `1.0` remains required throughout `1.x`;
- existing effect and annotation meanings remain stable;
- new optional fields or enum values require a new schema minor version;
- readers must explicitly implement a new schema minor before accepting it;
- removing a field, changing its meaning, or making a previously valid `1.x`
  contract invalid for structural reasons requires schema `2.0`.

Validation defects may be fixed without changing `schema_version` when the old
behavior contradicted the published schema or a documented security invariant.
Such fixes are listed in the package changelog.

## Tool-set version rules

The contract owner controls the root `version` field:

- increment the patch version for documentation or metadata corrections that
  do not change governance comparison;
- increment the minor version when adding a backward-compatible tool or
  optional capability;
- increment the major version when removing or renaming a tool, changing its
  action identity, or making existing callers incompatible.

Governance-relevant changes are still detected by `contract diff` regardless
of the declared version increment. A version number never suppresses drift.

## Migration procedure

When Hlinor publishes a new Tool Contract schema:

1. Keep the reviewed old contract unchanged.
2. Upgrade `hlinor-registry` to a release that explicitly supports the target
   schema.
3. Apply the migration guide for that schema version.
4. Validate the migrated file with `validate-tool-contract`.
5. Export a fresh runtime contract and run `contract diff`.
6. Review every governance finding before replacing the old contract.
7. Commit the migrated contract and its updated compatibility fixtures
   together.

Do not change `schema_version` merely to silence validation. A migration is
complete only when the new reader validates the whole document and drift has
been reviewed.

## Deprecation policy

Schema `1.0` has no deprecated fields. If a future field is deprecated, the
documentation will name its replacement and the first schema version in which
it may be removed. Removal cannot occur inside schema major version `1`.

Security fixes may reject an input that was previously accepted only when that
input violated the published schema or a documented fail-closed invariant.
The changelog must identify the affected shape and the reason for rejection.

## Compatibility fixture

`tests/fixtures/tool-contracts/stable-v1.0.yaml` is the canonical minimum
compatibility fixture. Future changes to loaders, exporters, schemas, or drift
logic must keep it valid unless a schema-major migration is intentionally
performed.
