# Signed Bundles and Trust Stores

Hlinor Agent Registry supports Ed25519 signatures for compiled policy bundles.
A signature authenticates a bundle against public keys configured by the
runtime operator. It is separate from the bundle's SHA-256 integrity digest.

## Security contract

The signature covers:

- the compiled policy payload;
- the canonical bundle digest;
- schema, compiler, bundle, and policy revisions;
- environment metadata;
- signature algorithm and key ID;
- issuer;
- issuance and expiration timestamps.

The bundle does not contain its trusted public key. `PolicyChecker` obtains
trust roots from deployment configuration so an attacker cannot replace a
bundle and declare a new key trusted in the same artifact.

Decisions and audit events include both the configured key ID and a SHA-256
fingerprint of the Ed25519 public key that actually verified the signature.

## Create an Ed25519 key pair

Generate keys outside the policy repository:

```bash
openssl genpkey -algorithm ED25519 -out policy-signing-key.pem
openssl pkey \
  -in policy-signing-key.pem \
  -pubout \
  -out policy-signing-key.pub.pem
```

Protect the private key with your CI secret store, KMS-backed workflow, or
another restricted signing environment. The current CLI accepts an
unencrypted PEM private key file so non-interactive CI can sign. Use a
short-lived, access-controlled file and remove it after compilation.

## Compile a signed bundle

All signing fields are required together. Explicit timestamps preserve
deterministic compilation and make the reviewable validity window clear.

```bash
hlinor-registry compile \
  --manifest registry.yaml \
  --output dist/policy-bundle.json \
  --signing-key /run/secrets/policy-signing-key.pem \
  --key-id prod-policy-2026-01 \
  --issuer hlinor-policy-ci \
  --issued-at 2026-07-26T00:00:00Z \
  --expires-at 2026-08-26T00:00:00Z
```

`expires_at` must be later than `issued_at`. Both timestamps must be
timezone-aware ISO-8601 values.

## Configure trusted keys

Create a JSON trust store owned by the deployment environment:

```json
{
  "schema_version": "1.0",
  "keys": {
    "prod-policy-2026-01": {
      "algorithm": "Ed25519",
      "public_key_path": "keys/prod-policy-2026-01.pub.pem",
      "issuer": "hlinor-policy-ci"
    }
  }
}
```

Relative public-key paths resolve from the trust store's directory. Removing a
key from the trust store revokes it for subsequent evaluations. For signed
bundles, long-lived checkers reload the configured trust store and reverify the
in-memory bundle snapshot before each evaluation so key rotation and revocation
do not require a process restart.

## Verify before deployment

```bash
hlinor-registry verify-bundle \
  --bundle dist/policy-bundle.json \
  --trust-store /etc/hlinor/trust-store.json \
  --signature-policy required \
  --required-issuer hlinor-policy-ci \
  --minimum-bundle-revision 42 \
  --format json
```

Verification fails closed for:

- digest mismatch;
- missing signature when required;
- unknown key ID;
- issuer mismatch;
- unsupported algorithm;
- invalid base64 or Ed25519 signature;
- expiration;
- issuance too far in the future;
- a bundle revision below the configured rollback floor.

## Runtime verification

```python
from hlinor_registry import PolicyChecker

checker = PolicyChecker(
    "dist/policy-bundle.json",
    trust_store="/etc/hlinor/trust-store.json",
    signature_policy="required",
    required_issuer="hlinor-policy-ci",
    minimum_bundle_revision=42,
    clock_skew_seconds=60,
)
```

Signature policies:

- `required`: every bundle must be signed by a trusted key;
- `auto`: unsigned bundles are accepted only when their own environment is
  `development`, `test`, or `local`;
- `optional`: explicitly accepts unsigned bundles in any environment.

Production deployments should use `required`. The `auto` mode is a migration
and local-development convenience; bundle environment metadata is not a
deployment trust root.

## Rotation and rollback

For key rotation:

1. Add the new public key to the trust store.
2. Deploy the updated trust store.
3. Sign a higher bundle revision with the new key.
4. Raise `minimum_bundle_revision` after promotion.
5. Remove the old key after all valid bundles signed by it have expired.

Rollback protection is deployer-controlled. A stateless verifier cannot know
whether an otherwise valid older bundle is a rollback. Set
`minimum_bundle_revision` from protected deployment state, release metadata,
or a control plane that an attacker cannot roll back together with the bundle.

## Current limitations

- The CLI reads an unencrypted PEM private key; direct KMS/HSM signing providers
  are not yet implemented.
- Trust-store distribution and filesystem permissions remain deployment
  responsibilities.
- Signatures authenticate policy bundles, not runtime requests or JSONL audit
  events.
- Context fields in `ActionRequest` are bound to decisions but are not yet a
  general attribute-based authorization language.
