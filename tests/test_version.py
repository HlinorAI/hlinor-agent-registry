"""Tests for package version consistency."""

from hlinor_registry import __version__
from hlinor_registry._version import __version__ as canonical_version


def test_public_version_uses_canonical_source() -> None:
    """The public package version must come from the canonical version module."""
    assert __version__ == canonical_version
