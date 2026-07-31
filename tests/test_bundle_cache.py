"""Security and lifecycle tests for explicit policy bundle caching."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml

from hlinor_registry import (
    BundleCacheInfo,
    BundleSignatureError,
    PolicyBundleCache,
    PolicyChecker,
    VerifiedSignature,
)
from hlinor_registry.cli import main
from hlinor_registry.signing import compute_bundle_digest


def write_bundle(
    root: Path,
    *,
    agent_id: str = "cache-agent",
    allowed_action: str = "read",
) -> Path:
    """Compile one small bundle under an isolated root."""
    policy_dir = root / "policies"
    policy_dir.mkdir(parents=True)
    (policy_dir / "agent.yaml").write_text(
        yaml.safe_dump(
            {
                "id": agent_id,
                "name": "Cache Agent",
                "department": "testing",
                "description": "Synthetic cache lifecycle fixture.",
                "skills": ["test"],
                "validators": ["test-validator"],
                "policies": [],
                "allowed_actions": [allowed_action],
                "blocked_actions": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    manifest = root / "registry.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "version": "1.0",
                "policies": [{"path": "policies/agent.yaml"}],
                "metadata": {"environment": "test", "compiled_by": "pytest"},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    bundle = root / "dist" / "policy-bundle.json"
    assert (
        main(
            [
                "compile",
                "--manifest",
                str(manifest),
                "--output",
                str(bundle),
            ]
        )
        == 0
    )
    return bundle


@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_cache_requires_a_positive_integer_capacity(value: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        PolicyBundleCache(value)  # type: ignore[arg-type]


def test_cache_is_opt_in_and_reports_hits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = write_bundle(tmp_path)
    cache = PolicyBundleCache()

    first = PolicyChecker(str(bundle), bundle_cache=cache)

    def unexpected_parse(*args: object, **kwargs: object) -> object:
        raise AssertionError("cache hit reparsed the bundle")

    monkeypatch.setattr("hlinor_registry.policy_checker.json.loads", unexpected_parse)
    second = PolicyChecker(str(bundle), bundle_cache=cache)

    assert first.check_action("cache-agent", "read").allowed
    assert second.check_action("cache-agent", "read").allowed
    assert cache.cache_info() == BundleCacheInfo(
        hits=1,
        misses=1,
        max_entries=32,
        current_entries=1,
    )


def test_cached_state_is_not_mutably_shared_between_checkers(tmp_path: Path) -> None:
    bundle = write_bundle(tmp_path)
    cache = PolicyBundleCache()

    first = PolicyChecker(str(bundle), bundle_cache=cache)
    first.agents["cache-agent"]["data"]["allowed_actions"].append("delete")

    second = PolicyChecker(str(bundle), bundle_cache=cache)
    assert second.check_action("cache-agent", "delete").denied

    second.capabilities["injected"] = {"id": "injected"}
    third = PolicyChecker(str(bundle), bundle_cache=cache)
    assert "injected" not in third.capabilities


def test_changed_bundle_bytes_never_reuse_stale_state(tmp_path: Path) -> None:
    bundle = write_bundle(tmp_path, allowed_action="read")
    cache = PolicyBundleCache()
    first = PolicyChecker(str(bundle), bundle_cache=cache)
    assert first.check_action("cache-agent", "read").allowed

    agent_path = tmp_path / "policies" / "agent.yaml"
    config = yaml.safe_load(agent_path.read_text(encoding="utf-8"))
    config["allowed_actions"] = ["write"]
    agent_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    assert (
        main(
            [
                "compile",
                "--manifest",
                str(tmp_path / "registry.yaml"),
                "--output",
                str(bundle),
            ]
        )
        == 0
    )

    second = PolicyChecker(str(bundle), bundle_cache=cache)
    assert second.check_action("cache-agent", "read").denied
    assert second.check_action("cache-agent", "write").allowed
    assert cache.cache_info().misses == 2


def test_verification_settings_are_part_of_the_cache_key(tmp_path: Path) -> None:
    bundle = write_bundle(tmp_path)
    cache = PolicyBundleCache()
    PolicyChecker(str(bundle), bundle_cache=cache, minimum_bundle_revision=0)

    with pytest.raises(ValueError, match="below the trusted minimum"):
        PolicyChecker(
            str(bundle),
            bundle_cache=cache,
            minimum_bundle_revision=10_000,
        )

    assert cache.cache_info().hits == 0
    assert cache.cache_info().misses == 2


def test_signature_window_is_rechecked_on_a_cache_hit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_path = write_bundle(tmp_path)
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["signature"] = {
        "algorithm": "Ed25519",
        "key_id": "synthetic",
        "issuer": "pytest",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-08-01T00:00:00Z",
        "value": "synthetic",
    }
    bundle["digest"] = compute_bundle_digest(bundle)
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    verified = VerifiedSignature(
        algorithm="Ed25519",
        key_id="synthetic",
        key_fingerprint="sha256:synthetic",
        issuer="pytest",
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-08-01T00:00:00Z",
    )
    verification_calls = 0

    def verify(*args: object, **kwargs: object) -> VerifiedSignature:
        nonlocal verification_calls
        verification_calls += 1
        return verified

    monkeypatch.setattr(
        "hlinor_registry.policy_checker.verify_bundle_signature",
        verify,
    )
    cache = PolicyBundleCache()
    PolicyChecker(str(bundle_path), bundle_cache=cache, signature_policy="optional")

    def expired(*args: object, **kwargs: object) -> None:
        raise BundleSignatureError("Policy bundle signature has expired")

    monkeypatch.setattr(
        "hlinor_registry.policy_checker.validate_signature_window",
        expired,
    )
    with pytest.raises(BundleSignatureError, match="has expired"):
        PolicyChecker(
            str(bundle_path),
            bundle_cache=cache,
            signature_policy="optional",
        )
    assert cache.cache_info().hits == 1
    assert verification_calls == 1


def test_explicit_invalidation_and_lru_capacity(tmp_path: Path) -> None:
    cache = PolicyBundleCache(max_entries=2)
    first = write_bundle(tmp_path / "one", agent_id="one")
    second = write_bundle(tmp_path / "two", agent_id="two")
    third = write_bundle(tmp_path / "three", agent_id="three")

    PolicyChecker(str(first), bundle_cache=cache)
    PolicyChecker(str(second), bundle_cache=cache)
    PolicyChecker(str(third), bundle_cache=cache)

    assert cache.cache_info().current_entries == 2
    assert cache.invalidate(first) == 0
    assert cache.invalidate(second) == 1
    assert cache.cache_info().current_entries == 1
    cache.clear()
    assert cache.cache_info().current_entries == 0


def test_shared_cache_is_safe_for_concurrent_checker_startup(tmp_path: Path) -> None:
    bundle = write_bundle(tmp_path)
    cache = PolicyBundleCache()

    def load_and_check(_: int) -> bool:
        checker = PolicyChecker(str(bundle), bundle_cache=cache)
        return checker.check_action("cache-agent", "read").allowed

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(load_and_check, range(32)))

    assert all(results)
    assert cache.cache_info().current_entries == 1
