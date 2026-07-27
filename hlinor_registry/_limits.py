"""Size limits for files this package parses.

Every parser here reads a path the deployment named, so these limits are not a
defence against a hostile author. They bound the damage from a file that is
wrong rather than malicious: a truncated download, a runaway generator, a
bundle pointed at the wrong artifact. Without them the first symptom is the
process being killed by the OOM killer, which is a worse way to learn.

The limits are generous. A policy source is a page of YAML; a bundle with a
thousand agents is a few megabytes.
"""

from __future__ import annotations

from pathlib import Path

#: Authoring YAML: one agent, department, policy or receipt.
MAX_SOURCE_BYTES = 4 * 1024 * 1024

#: Compiled bundle. Scales with the number of agents, so it gets more room.
MAX_BUNDLE_BYTES = 64 * 1024 * 1024

#: Trust store JSON and the PEM files it points at.
MAX_TRUST_STORE_BYTES = 1024 * 1024


class FileTooLargeError(ValueError):
    """Raised when a file exceeds the limit for its role."""


def read_text_capped(
    path: str | Path,
    limit: int,
    description: str,
    *,
    encoding: str = "utf-8",
) -> str:
    """Read a text file, refusing to load more than ``limit`` bytes.

    The size is checked before reading rather than after, so an oversized file
    is never held in memory.
    """
    file_path = Path(path)
    size = file_path.stat().st_size
    if size > limit:
        raise FileTooLargeError(
            f"{description} is {size} bytes, above the {limit} byte limit: {file_path}"
        )
    return file_path.read_text(encoding=encoding)


def read_bytes_capped(
    path: str | Path,
    limit: int,
    description: str,
) -> bytes:
    """Read a binary file, refusing to load more than ``limit`` bytes."""
    file_path = Path(path)
    size = file_path.stat().st_size
    if size > limit:
        raise FileTooLargeError(
            f"{description} is {size} bytes, above the {limit} byte limit: {file_path}"
        )
    return file_path.read_bytes()
