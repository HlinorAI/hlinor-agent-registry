# Safe policy bundle caching

`PolicyChecker` normally parses and verifies its bundle when the checker is
created. Long-lived checkers already keep that verified state in memory, so
most applications should create one checker and reuse it.

Applications that intentionally create several checkers for the same bundle
can share an opt-in `PolicyBundleCache`:

```python
from hlinor_registry import PolicyBundleCache, PolicyChecker

bundle_cache = PolicyBundleCache(max_entries=32)

first = PolicyChecker(
    "dist/policy-bundle.json",
    trust_store="trust/trust-store.json",
    bundle_cache=bundle_cache,
)
second = PolicyChecker(
    "dist/policy-bundle.json",
    trust_store="trust/trust-store.json",
    bundle_cache=bundle_cache,
)
```

The second checker can reuse the first checker's parsed and verified runtime
state. Agent and capability dictionaries are copied before they are exposed,
so mutating one checker cannot change another checker or poison the cache.

## Security properties

A cache entry is bound to all of the following:

- the resolved bundle path;
- the SHA-256 digest of the exact file bytes read from disk;
- signature policy and required issuer;
- minimum accepted bundle revision;
- clock-skew policy;
- every configured Ed25519 public key;
- the content of a file-backed trust store and its referenced key files.

Changing bundle bytes, a trust root, or a verification setting produces a
cache miss. The loader also checks file identity before and after reading and
fails if the bundle changes during the load.

Signature validity is time-dependent, so its issuance and expiration window is
checked again on every cache hit and every governed evaluation. Caching never
extends an expired signature.

The cache stores verified bundle state, not authorization decisions. Every
`ActionRequest` is still evaluated independently and produces its own decision
and audit provenance.

## Explicit invalidation

Invalidate one bundle after an atomic deployment switch:

```python
bundle_cache.invalidate("dist/policy-bundle.json")
```

Clear the entire application cache after a broader trust configuration change:

```python
bundle_cache.clear()
```

Content and trust binding remain the primary safety controls. Invalidation is
an operational lifecycle hook that releases old entries immediately; forgetting
to call it cannot make changed bytes match an old cache key.

`invalidate()` returns the number of removed entries. `cache_info()` provides
bounded operational counters:

```python
info = bundle_cache.cache_info()
print(info.hits, info.misses, info.current_entries, info.max_entries)
```

The cache is a thread-safe, process-local least-recently-used cache. It is not
persistent, does not fetch bundles, and does not synchronize policy state
between processes. Each process must receive the bundle and trust material
through the deployment mechanism, then invalidate its own cache as part of the
activation step.

## Recommended lifecycle

1. Compile and sign a new immutable bundle outside the runtime process.
2. Place it at a versioned path or atomically replace the active path.
3. Call `invalidate(active_bundle_path)` in each process.
4. Construct the new checker. Loading still verifies digest, revision,
   signature, issuer, and validity before exposing policy state.
5. Swap the application reference only after construction succeeds.

If construction fails, keep the previous checker active and alert the
deployment operator. Never bypass verification or reuse a decision merely to
make a rollout succeed.
