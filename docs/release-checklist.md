# Release Checklist

Use this checklist for every tagged release. A Git tag is the release source of
truth; GitHub Releases and PyPI artifacts must be produced from that tag.

## Before tagging

- Confirm `hlinor_registry/_version.py` contains the intended version.
- Confirm `CHANGELOG.md` has matching release notes.
- Run `make lint` and `make test`. Lint coverage includes package code, tests,
  and runnable Python examples.
- Run `python -m build` and `python -m twine check dist/*`.
- Install the wheel in a clean virtual environment and verify
  `hlinor-registry --version`.
- Confirm README examples work with the built wheel.

## Publication

- Merge the reviewed release commit before creating `vX.Y.Z`.
- Create the tag once. Repository rules protect release tags from update and
  deletion; never force-push or recreate one.
- Let CI build the wheel and source distribution once from that exact tag.
- CI installs and smoke-tests that wheel before publication, records SHA-256
  digests, creates GitHub build provenance, and transfers the immutable
  artifacts between jobs.
- Publish those same files to PyPI through OIDC Trusted Publishing with PyPI
  attestations enabled. The `pypi` environment accepts only `v*` deployment
  refs.
- Let the separate verification job compare PyPI's SHA-256 digest for every
  file with the CI-built files, then install the exact published version in a
  clean environment. The check uses bounded retries for normal index
  propagation.
- Let CI create the GitHub Release only after PyPI verification. The release
  contains the same wheel, source distribution, and `SHA256SUMS` manifest and
  refuses to overwrite an existing release.

### Safe recovery before publication

If a workflow defect stops a release before PyPI publication:

1. Keep the protected tag unchanged.
2. Fix and review the workflow on `main`.
3. In **Settings → Environments → pypi**, temporarily add the exact branch
   rule `main`. Do not remove or broaden the existing `v*` tag rule.
4. Open **Publish Release** in GitHub Actions and use **Run workflow** with
   **Use workflow from** set to `main`.
5. Enter the existing immutable `vX.Y.Z` tag.
6. Confirm the recovery run checks out and retests that tag, not `main`.
7. Whether the run succeeds or fails, immediately remove the temporary `main`
   deployment rule.
8. Confirm the `pypi` environment again reports zero branches and only the
   `v*` tag rule.

The dispatch path verifies that the checkout commit is the commit referenced by
the tag, repeats the complete test workflow against that ref, and then follows
the same build, attestation, PyPI, digest-verification, and GitHub Release jobs.
GitHub evaluates environment protection against the dispatch branch rather than
the separately checked-out release tag, which is why the narrow, temporary
`main` exception is required. The workflow rejects manual recovery dispatched
from any other branch.

Do not use recovery to overwrite a version that PyPI already accepted. PyPI
artifacts and GitHub Releases are immutable; investigate a post-publication
failure and issue a new patch version when source or artifacts must change.

## Verification

- Confirm the Git tag, GitHub Release, package metadata, CLI version, and PyPI
  version are identical.
- Confirm the automated post-publish installation, dependency check, CLI
  smoke test, and import/package version comparison all passed.
- Confirm the GitHub artifact attestation is present and PyPI displays
  provenance for both distributions.
- Download the GitHub Release assets and run
  `sha256sum --check SHA256SUMS`.
- Retain the CI run URL as part of the release record.

## Repository controls

- Keep the `v*` tag ruleset active with update and deletion blocked.
- Keep the `pypi` environment restricted to release tags.
- Treat a temporary `main` deployment rule as a recovery-only exception and
  remove it immediately after the run, including after a failed run.
- Require an independent environment reviewer as soon as a second trusted
  maintainer is available. Do not enable this with only one maintainer: GitHub
  prevents self-review and the release would be permanently blocked.
