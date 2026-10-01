import pytest
import yaml

from hlinor_registry.cli import EXIT_ERROR, main
from hlinor_registry.governance_coverage import (
    GovernanceCoverageInputError,
    check_governance_coverage,
    check_governance_coverage_file,
    validate_governance_coverage_data,
)


def manifest(source: str = "tools.py", symbol: str = "send_data") -> dict:
    return {
        "schema_version": "1.0",
        "type": "governance_coverage",
        "id": "test-coverage",
        "entries": [
            {
                "id": "sensitive-send",
                "source": source,
                "symbol": symbol,
                "effects": ["message_send"],
                "boundary": "governed_decorator",
            }
        ],
    }


def test_repository_coverage_fixture_is_covered() -> None:
    report = check_governance_coverage_file(
        "examples/governance-coverage/coverage.yaml"
    )

    assert report.status == "covered"
    assert report.entries_checked == 2
    assert report.findings == ()


def test_missing_boundary_is_a_bypass_finding(tmp_path) -> None:
    source = tmp_path / "tools.py"
    source.write_text("def send_data(payload):\n    return payload\n", encoding="utf-8")

    report = check_governance_coverage(manifest(), root=tmp_path)

    assert report.status == "bypass"
    assert report.findings[0].code == "BOUNDARY_BYPASS"


def test_missing_symbol_fails_closed_as_a_finding(tmp_path) -> None:
    source = tmp_path / "tools.py"
    source.write_text(
        "def another_name(payload):\n    return payload\n", encoding="utf-8"
    )

    report = check_governance_coverage(manifest(), root=tmp_path)

    assert report.findings[0].code == "SYMBOL_NOT_FOUND"


def test_ambiguous_symbol_fails_closed(tmp_path) -> None:
    source = tmp_path / "tools.py"
    source.write_text(
        "@governed\ndef send_data(payload):\n    return payload\n\n"
        "def send_data(payload):\n    return payload\n",
        encoding="utf-8",
    )

    report = check_governance_coverage(manifest(), root=tmp_path)

    assert report.findings[0].code == "SYMBOL_AMBIGUOUS"


def test_source_escape_is_rejected_before_parsing(tmp_path) -> None:
    data = manifest(source="../outside.py")

    with pytest.raises(GovernanceCoverageInputError):
        check_governance_coverage(data, root=tmp_path)


def test_invalid_boundary_and_effect_are_rejected() -> None:
    data = manifest()
    data["entries"][0]["boundary"] = "runtime_magic"
    data["entries"][0]["effects"] = ["unknown_effect"]

    errors = validate_governance_coverage_data(data)

    assert "governance_coverage: Invalid boundary: entries[0].boundary" in errors
    assert (
        "governance_coverage: Unsupported sensitive effect: entries[0].effects[0]"
        in errors
    )


def test_cli_validation_and_coverage_commands(capsys) -> None:
    assert (
        main(
            [
                "validate-governance-coverage",
                "examples/governance-coverage/coverage.yaml",
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert (
        main(
            [
                "coverage",
                "check",
                "--manifest",
                "examples/governance-coverage/coverage.yaml",
                "--format",
                "json",
            ]
        )
        == 0
    )
    output = yaml.safe_load(capsys.readouterr().out)
    assert output["status"] == "covered"


def test_cli_invalid_manifest_is_an_input_error(tmp_path, capsys) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("type: governance_coverage\n", encoding="utf-8")

    assert main(["coverage", "check", "--manifest", str(path)]) == EXIT_ERROR
    assert "Invalid governance coverage" in capsys.readouterr().err
