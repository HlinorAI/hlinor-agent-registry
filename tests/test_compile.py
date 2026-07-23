"""Tests for deterministic manifest compilation."""

import json
from pathlib import Path

import yaml

from hlinor_registry import PolicyChecker
from hlinor_registry.cli import main


def write_agent(path: Path, agent_id: str) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "id": agent_id,
                "name": "Compile Test Agent",
                "department": "testing",
                "description": "Agent used to test manifest compilation.",
                "skills": ["test"],
                "validators": ["test-validator"],
                "policies": [],
                "allowed_actions": ["read"],
                "blocked_actions": ["delete"],
            },
            sort_keys=False,
        ),
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


def compile_manifest(manifest_path: Path, output_path: Path) -> int:
    return main(
        [
            "compile",
            "--manifest",
            str(manifest_path),
            "--output",
            str(output_path),
        ]
    )


def test_root_manifest_compiles_real_examples(tmp_path: Path) -> None:
    """The checked-in manifest compiles all explicitly listed entries."""
    output_path = tmp_path / "dist" / "policy-bundle.json"

    assert compile_manifest(Path("registry.yaml"), output_path) == 0

    bundle = json.loads(output_path.read_text(encoding="utf-8"))
    assert set(bundle["agents"]) == {
        "financial-audit-agent",
        "web-research-agent",
        "funding-intelligence",
    }
    assert bundle["digest"]
    assert PolicyChecker(str(output_path)).check_action(
        "financial-audit-agent", "read"
    ).allowed


def test_compile_rejects_path_traversal(tmp_path: Path) -> None:
    """Manifest entries cannot escape the manifest directory."""
    outside_path = tmp_path.parent / "outside.yaml"
    write_agent(outside_path, "outside-agent")
    manifest_path = tmp_path / "registry.yaml"
    write_manifest(manifest_path, ["../outside.yaml"])

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
