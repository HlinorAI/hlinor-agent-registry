"""Bounded, explicit cache for verified policy bundle runtime state."""

from __future__ import annotations

import copy
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_CacheKey = tuple[str, str, str]


@dataclass(frozen=True)
class BundleCacheInfo:
    """Operational counters for one :class:`PolicyBundleCache`."""

    hits: int
    misses: int
    max_entries: int
    current_entries: int


class PolicyBundleCache:
    """Process-local LRU cache for already verified policy bundle state.

    The cache is deliberately opt-in. Share one instance between
    ``PolicyChecker`` objects only when they belong to the same application
    trust boundary. Entries are keyed by the resolved bundle path, the SHA-256
    digest of the bytes read from disk, and the complete verification context.

    ``invalidate`` and ``clear`` are explicit deployment hooks. They are not a
    substitute for content binding: changing bundle or trust material produces
    a cache miss even if an operator forgets to call either method.
    """

    def __init__(self, max_entries: int = 32) -> None:
        if (
            not isinstance(max_entries, int)
            or isinstance(max_entries, bool)
            or max_entries < 1
        ):
            raise ValueError("max_entries must be a positive integer")
        self.max_entries = max_entries
        self._entries: OrderedDict[_CacheKey, dict[str, Any]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._lock = threading.RLock()

    def clear(self) -> None:
        """Remove every cached bundle state."""
        with self._lock:
            self._entries.clear()

    def invalidate(self, bundle_path: str | Path) -> int:
        """Remove entries for one resolved bundle path and return the count."""
        resolved = str(Path(bundle_path).resolve())
        with self._lock:
            keys = [key for key in self._entries if key[0] == resolved]
            for key in keys:
                del self._entries[key]
            return len(keys)

    def cache_info(self) -> BundleCacheInfo:
        """Return a stable snapshot of cache counters and capacity."""
        with self._lock:
            return BundleCacheInfo(
                hits=self._hits,
                misses=self._misses,
                max_entries=self.max_entries,
                current_entries=len(self._entries),
            )

    def _get(self, key: _CacheKey) -> dict[str, Any] | None:
        with self._lock:
            state = self._entries.get(key)
            if state is None:
                self._misses += 1
                return None
            self._entries.move_to_end(key)
            self._hits += 1
            # A checker may expose agent and capability dictionaries. Never
            # share those mutable objects between otherwise independent
            # enforcement instances.
            return copy.deepcopy(state)

    def _put(self, key: _CacheKey, state: dict[str, Any]) -> None:
        with self._lock:
            self._entries[key] = copy.deepcopy(state)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
