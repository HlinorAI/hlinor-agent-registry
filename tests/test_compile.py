"""Tests for deterministic manifest compilation."""

import json
import os
from pathlib import Path

import pytest
import yaml

from hlinor_registry import PolicyChecker, __version__
from hlinor_registry.cli import main


def write_agent(
    path: Path,
    agent_id: str,
    *,
    entity_type: str | None = None,
    enforcement_mode: str | None = None,
) -> None:
    data = {
        "id": agent_id,
        "name": "Compile Test Agent",
        "department": "testing",
        "description": "Agent used to test manifest compilation.",
        "skills": ["test"],
        "validators": ["test-validator"],
        "policies": [],
        "allowed_actions": ["read"],
        "blocked_actions": ["delete"],
    }
    if entity_type is not None:
        data["type"] = entity_type
    if enforcement_mode is not None:
        data["enforcement_mode"] = enforcement_mode
    path.write_text(
        yaml.safe_dump(data, sort_keys=False),
        encoding="utf-8",
    )


def write_manifest(path: Path, policy_paths: list[str]) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "version": "1.0",
                "policies": [{"path": policy_path} for policy_path in policy_paths],
                "metadata": {"environment": "test", "compiled_by": "pytest"},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def compile_manifest(
    manifest_path: Path,
    output_path: Path,
    *,
    allow_permissive_production: bool = False,
) -> int:
    arguments = [
        "compile",
        "--manifest",
        str(manifest_path),
        "--output",
        str(output_path),
    ]
    if allow_permissive_production:
        arguments.append("--allow-permissive-production")
    return main(arguments)


def test_root_manifest_compiles_real_examples(tmp_path: Path) -> None:
    """The checked-in manifest compiles all explicitly listed entries."""
    output_path = tmp_path / "dist" / "policy-bundle.json"

    assert compile_manifest(Path("registry.yaml"), output_path) == 0

    bundle = json.loads(output_path.read_text(encoding="utf-8"))
    assert set(bundle["agents"]) == {"financial-audit-agent", "web-research-agent"}
    assert set(bundle["capabilities"]) == {"funding-intelligence"}
    assert bundle["schema_version"] == "1.0"
    assert bundle["compiler_version"] == __version__
    assert bundle["bundle_revision"] == 1
    assert bundle["policy_revision"] == "repository-main"
    assert bundle["digest"]
    assert (
        PolicyChecker(str(output_path), signature_policy="optional")
        .check_action("financial-audit-agent", "read")
        .allowed
    )


def test_compile_rejects_path_traversal(tmp_path: Path) -> None:
    """Manifest entries cannot escape the manifest directory."""
    outside_path = tmp_path.parent / "outside.yaml"
    write_agent(outside_path, "outside-agent")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["../outside.yaml"])

    assert compile_manifest(manifest_path, tmp_path / "bundle.json") == 1


def test_compile_rejects_symlink_escape(tmp_path: Path) -> None:
    outside_path = tmp_path.parent / "outside-symlink-agent.yaml"
    write_agent(outside_path, "outside-symlink-agent")
    linked_path = tmp_path / "linked.yaml"
    try:
        linked_path.symlink_to(outside_path)
    except OSError as exc:
        pytest.skip(f"Symlinks unavailable: {exc}")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["linked.yaml"])

    assert compile_manifest(manifest_path, tmp_path / "bundle.json") == 1


def test_compile_rejects_duplicate_agent_ids(tmp_path: Path) -> None:
    """Duplicate IDs are rejected before a bundle is written."""
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    write_agent(policies_dir / "first.yaml", "duplicate-agent")
    write_agent(policies_dir / "second.yaml", "duplicate-agent")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["policies/first.yaml", "policies/second.yaml"])
    output_path = tmp_path / "bundle.json"

    assert compile_manifest(manifest_path, output_path) == 1
    assert not output_path.exists()


def test_compile_rejects_overwriting_a_source_file(tmp_path: Path) -> None:
    """Compilation cannot replace one of the explicitly listed sources."""
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    source_path = policies_dir / "agent.yaml"
    write_agent(source_path, "source-agent")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["policies/agent.yaml"])

    assert compile_manifest(manifest_path, source_path) == 1
    assert "source-agent" in source_path.read_text(encoding="utf-8")


def test_runtime_ignores_unlisted_yaml_files(tmp_path: Path) -> None:
    """Runtime loading only exposes entries present in the compiled bundle."""
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    write_agent(policies_dir / "listed.yaml", "listed-agent")
    write_agent(policies_dir / "unlisted.yaml", "unlisted-agent")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["policies/listed.yaml"])
    output_path = tmp_path / "bundle.json"

    assert compile_manifest(manifest_path, output_path) == 0
    checker = PolicyChecker(str(output_path))

    assert checker.check_action("listed-agent", "read").allowed
    assert checker.check_action("unlisted-agent", "read").denied
    assert checker.check_action("unlisted-agent", "read").reason_code == "UNKNOWN_AGENT"


def test_compile_rejects_unknown_entity_type(tmp_path: Path) -> None:
    source_path = tmp_path / "unknown.yaml"
    write_agent(source_path, "unknown-agent", entity_type="workflow")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["unknown.yaml"])

    assert compile_manifest(manifest_path, tmp_path / "bundle.json") == 1


def test_compile_rejects_case_colliding_ids(tmp_path: Path) -> None:
    write_agent(tmp_path / "first.yaml", "Finance-Agent")
    write_agent(tmp_path / "second.yaml", "finance-agent")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["first.yaml", "second.yaml"])

    assert compile_manifest(manifest_path, tmp_path / "bundle.json") == 1


def test_compile_rejects_permissive_production_agent(tmp_path: Path) -> None:
    source_path = tmp_path / "agent.yaml"
    write_agent(source_path, "unsafe-agent", enforcement_mode="permissive")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["agent.yaml"])
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["metadata"]["environment"] = "production"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")

    assert compile_manifest(manifest_path, tmp_path / "bundle.json") == 1
    assert (
        compile_manifest(
            manifest_path,
            tmp_path / "bundle.json",
            allow_permissive_production=True,
        )
        == 0
    )


def test_failed_atomic_replace_preserves_existing_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_path = tmp_path / "agent.yaml"
    write_agent(source_path, "stable-agent")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["agent.yaml"])
    output_path = tmp_path / "bundle.json"
    output_path.write_text('{"stable": true}\n', encoding="utf-8")

    def fail_replace(source: str | os.PathLike, destination: str | os.PathLike) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr("hlinor_registry.cli.os.replace", fail_replace)

    assert compile_manifest(manifest_path, output_path) == 1
    assert output_path.read_text(encoding="utf-8") == '{"stable": true}\n'
    assert list(tmp_path.glob(".bundle.json.*.tmp")) == []


def test_runtime_rejects_unknown_schema_major(tmp_path: Path) -> None:
    source_path = tmp_path / "agent.yaml"
    write_agent(source_path, "versioned-agent")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["agent.yaml"])
    output_path = tmp_path / "bundle.json"
    assert compile_manifest(manifest_path, output_path) == 0

    bundle = json.loads(output_path.read_text(encoding="utf-8"))
    bundle["schema_version"] = "2.0"
    bundle["digest"] = ""
    from hlinor_registry.cli import _compute_bundle_digest

    bundle["digest"] = _compute_bundle_digest(bundle)
    output_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported policy bundle schema"):
        PolicyChecker(str(output_path))


def test_compile_rejects_unknown_schema_major(tmp_path: Path) -> None:
    source_path = tmp_path / "agent.yaml"
    write_agent(source_path, "future-agent")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["agent.yaml"])
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "2.0"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")

    assert compile_manifest(manifest_path, tmp_path / "bundle.json") == 1
