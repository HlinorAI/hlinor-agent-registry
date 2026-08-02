#!/usr/bin/env python3
"""Keep the list of required status checks honest against the workflow.

A branch protection rule names the checks that must pass before a merge. That
list lives in GitHub settings, the jobs live in .github/workflows/test.yml, and
nothing connects them. The failure is quiet in the dangerous direction: a job
added to the workflow runs on every pull request and shows a green tick, while
the rule that decides whether a merge is allowed has never heard of it. It
looks exactly like a blocking check and blocks nothing.

That happened here. autogen-integration ran for weeks while the ruleset
required eight contexts, not nine.

This script compares the workflow against .github/required-checks.txt, which is
the file a maintainer applies to the ruleset. It cannot read the ruleset itself
-- GITHUB_TOKEN has no administration scope and there is no workflow permission
that grants one -- so the chain is: workflow, checked by CI against the file;
file, applied to the ruleset by hand. See CONTRIBUTING for the apply command.

Run: python3 scripts/check_required_checks.py
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"
EXPECTED = REPO_ROOT / ".github" / "required-checks.txt"


class WorkflowTooClever(Exception):
    """The workflow uses a construct whose check names this cannot predict.

    Raised rather than guessed. A wrong prediction here would either fail every
    build for no reason or, worse, quietly agree with a list that does not match
    what GitHub actually reports.
    """


def _matrix_values(job_id: str, key: str, raw: object) -> list[str]:
    if not isinstance(raw, list):
        raise WorkflowTooClever(
            f"job {job_id}: matrix.{key} is not a list, cannot enumerate it"
        )
    values = []
    for item in raw:
        if not isinstance(item, str):
            # An unquoted 3.10 parses as the float 3.1 and the check name
            # silently becomes "test (3.1)". Quoting is not a style preference.
            raise WorkflowTooClever(
                f"job {job_id}: matrix.{key} contains {item!r} "
                f"({type(item).__name__}); quote it so the check name is exact"
            )
        values.append(item)
    return values


def check_names(workflow: dict) -> set[str]:
    """Reproduce the check names GitHub reports for a workflow run."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise WorkflowTooClever("workflow declares no jobs")

    names: set[str] = set()
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            raise WorkflowTooClever(f"job {job_id}: not a mapping")

        base = job.get("name", job_id)
        if not isinstance(base, str):
            raise WorkflowTooClever(f"job {job_id}: name is not a string")
        if "${{" in base:
            raise WorkflowTooClever(
                f"job {job_id}: name contains an expression, so its check name "
                f"depends on values this script does not evaluate"
            )

        matrix = (job.get("strategy") or {}).get("matrix")
        if matrix is None:
            names.add(base)
            continue
        if not isinstance(matrix, dict):
            raise WorkflowTooClever(f"job {job_id}: matrix is not a mapping")
        for unsupported in ("include", "exclude"):
            if unsupported in matrix:
                raise WorkflowTooClever(
                    f"job {job_id}: matrix.{unsupported} changes which "
                    f"combinations run; teach this script about it first"
                )

        axes = [_matrix_values(job_id, key, raw) for key, raw in matrix.items()]
        for combination in itertools.product(*axes):
            names.add(f"{base} ({', '.join(combination)})")

    return names


def expected_names(text: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.add(line)
    return names


def main() -> int:
    if not WORKFLOW.is_file():
        print(f"error: {WORKFLOW} not found", file=sys.stderr)
        return 2
    if not EXPECTED.is_file():
        print(f"error: {EXPECTED} not found", file=sys.stderr)
        return 2

    try:
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        produced = check_names(workflow)
    except WorkflowTooClever as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except yaml.YAMLError as exc:
        print(f"error: {WORKFLOW.name} is not valid YAML: {exc}", file=sys.stderr)
        return 2

    declared = expected_names(EXPECTED.read_text(encoding="utf-8"))

    unlisted = sorted(produced - declared)
    stale = sorted(declared - produced)
    if not unlisted and not stale:
        print(f"required checks: {len(produced)} contexts, list matches workflow")
        return 0

    for name in unlisted:
        print(
            f"error: job '{name}' runs but is not in {EXPECTED.name}. "
            f"It will report a green tick without being able to block a merge.",
            file=sys.stderr,
        )
    for name in stale:
        print(
            f"error: '{name}' is listed in {EXPECTED.name} but no job produces "
            f"it. A rule requiring it can never be satisfied.",
            file=sys.stderr,
        )
    print(
        f"\nUpdate {EXPECTED.name}, then apply it to the branch ruleset -- "
        f"the file alone changes nothing. See CONTRIBUTING.md.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
