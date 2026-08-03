"""The demo notebook must keep producing the output it claims.

A published demo is a promise about behaviour, and it is the kind of promise
that rots quietly: the notebook keeps rendering, the prose keeps asserting
DENIED, and nobody re-runs it. These tests run the same YAML the notebook
writes and assert the outcomes its prose describes, so a change that makes the
demo wrong fails here instead of in front of a first-time reader.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from hlinor_registry.cli import EXIT_ALLOWED, EXIT_DENIED, main

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILDER = REPO_ROOT / "examples" / "notebooks" / "build_first_look.py"
NOTEBOOK = REPO_ROOT / "examples" / "notebooks" / "first-look.ipynb"


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_first_look", BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def builder():
    return _load_builder()


@pytest.fixture
def demo(tmp_path: Path, builder) -> Path:
    """Write exactly the files the notebook writes."""
    (tmp_path / "agent.yaml").write_text(builder.AGENT_YAML, encoding="utf-8")
    (tmp_path / "tools.yaml").write_text(builder.TOOLS_YAML, encoding="utf-8")
    (tmp_path / "registry.yaml").write_text(builder.MANIFEST_YAML, encoding="utf-8")
    exit_code = main(
        [
            "compile",
            "--manifest",
            str(tmp_path / "registry.yaml"),
            "--output",
            str(tmp_path / "bundle.json"),
        ]
    )
    assert exit_code == 0, "the notebook's compile step failed"
    return tmp_path


def test_the_bare_action_is_allowed_as_the_notebook_shows(
    demo: Path, capsys: pytest.CaptureFixture
):
    exit_code = main(
        [
            "check",
            "--bundle",
            str(demo / "bundle.json"),
            "--agent",
            "support-agent",
            "--action",
            "read_ticket",
        ]
    )
    assert exit_code == EXIT_ALLOWED
    assert "ALLOWED" in capsys.readouterr().out


def test_the_same_action_with_the_resource_the_tool_uses_is_denied(
    demo: Path, capsys: pytest.CaptureFixture
):
    """The whole point of the demo.

    If this ever passes as ALLOWED, the notebook's central claim is false and
    the prose explaining exact-match semantics is wrong too.
    """
    exit_code = main(
        [
            "check",
            "--bundle",
            str(demo / "bundle.json"),
            "--agent",
            "support-agent",
            "--action",
            "read_ticket",
            "--resource",
            "ticket/5",
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == EXIT_DENIED
    assert "DENIED" in output
    assert "ACTION_NOT_ALLOWLISTED" in output


def test_contract_check_reports_the_four_findings_the_notebook_lists(
    demo: Path, capsys: pytest.CaptureFixture
):
    exit_code = main(
        [
            "contract",
            "check",
            "--agent",
            str(demo / "agent.yaml"),
            "--tools",
            str(demo / "tools.yaml"),
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == 1, "a drift report must fail a pull request"

    for expected in (
        "UNSCOPED_ALLOW_PERMISSION",
        "UNDECLARED_TOOL_SCOPE",
        "STALE_ALLOW_PERMISSION",
        "STALE_BLOCK_PERMISSION",
        "ticket.read",
        "ticket.delete",
        "send_customer_reply:ticket/*",
        "refund_payment",
    ):
        assert expected in output, f"the notebook names {expected}; the report does not"

    assert "(4 findings)" in output, "the notebook says four findings"

    # The notebook prints this line as the fix to apply. If the suggestion ever
    # stops being the pattern that actually covers the tool, the demo teaches
    # the wrong lesson.
    assert "Write 'read_ticket:ticket/*' instead" in output


def test_the_committed_notebook_matches_its_builder(builder, tmp_path: Path):
    """The .ipynb is a generated artifact and must not be hand-edited.

    Editing the JSON directly is how the prose and the code cells drift apart,
    which is the failure this whole file exists to prevent.
    """
    committed = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    regenerated = {
        "cells": builder.CELLS,
        "metadata": committed["metadata"],
        "nbformat": committed["nbformat"],
        "nbformat_minor": committed["nbformat_minor"],
    }
    assert committed["cells"] == regenerated["cells"], (
        "first-look.ipynb is out of date; run "
        "python3 examples/notebooks/build_first_look.py"
    )
