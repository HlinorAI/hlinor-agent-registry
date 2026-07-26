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

- Create the GitHub Release and `vX.Y.Z` tag from the reviewed commit, using the
  matching changelog section as the release notes.
- Build the wheel and sdist in CI from that exact tag.
- Publish to PyPI through OIDC Trusted Publishing.
- Let the separate verification job install the exact published version from
  PyPI in a clean environment. The check makes up to 12 bounded attempts with a
  10-second interval to accommodate normal index propagation. Keeping
  verification separate allows it to be retried without attempting to
  republish immutable files.

## Verification

- Confirm the Git tag, GitHub Release, package metadata, CLI version, and PyPI
  version are identical.
- Confirm the automated post-publish installation, dependency check, CLI
  smoke test, and import/package version comparison all passed.
- Verify release artifact provenance and retain the CI run URL.
