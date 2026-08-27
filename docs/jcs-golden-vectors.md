# JCS golden vectors

`tests/fixtures/jcs-golden-vectors.json` is the language-neutral fixture for
RFC 8785 JSON Canonicalization Scheme behavior used by the runtime-binding
digests.

Each vector contains:

- `value`: JSON input with intentionally non-canonical object-key order where
  useful;
- `canonical_json`: the exact canonical JSON text, encoded as UTF-8;
- `sha256`: the lowercase SHA-256 hex digest of those UTF-8 bytes.

An SDK in another language must parse `value`, apply an RFC 8785
implementation, encode the result as UTF-8 without a BOM, and compare both
the canonical text and digest. The fixture is deliberately independent of
Python object ordering, YAML, signatures, or deployment-specific data.

The vectors cover object-key sorting, nested objects, number normalization,
Unicode and escaping, and array-order preservation. They are
contract-level interoperability evidence; they do not define or publish a
production non-Python SDK.

## Independent verification

On 2026-08-27, all four vectors were independently verified with the npm
`canonicalize@2.1.0` implementation under Node.js 22.23.2. The check compared
both the canonical JSON text and the SHA-256 digest. The package was installed
in a temporary directory and is not a runtime or development dependency of
this Python project.
