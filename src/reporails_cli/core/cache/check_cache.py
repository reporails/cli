"""In-memory check result deduplication for a single validation run.

When multiple rules share the same mechanical check (e.g., file_exists on the
same target), the cache prevents redundant I/O. Scoped to one validation run —
not persisted.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from reporails_cli.core.mechanical.checks import CheckResult


class CheckCache:
    """In-memory dedup for identical checks across rules within one validation run."""

    def __init__(self) -> None:
        self._store: dict[str, CheckResult] = {}

    def key(
        self,
        check_type: str,
        check_name: str,
        args: dict[str, Any] | None,
        target_path: str,
    ) -> str:
        """Build a cache key from check parameters.

        Args:
            check_type: Check type (e.g., "mechanical").
            check_name: Function name (e.g., "file_exists").
            args: Check arguments dict (may be None).
            target_path: Target path string.

        Returns:
            SHA-256 hex digest of the serialized parameters.
        """
        raw = f"{check_type}:{check_name}:{json.dumps(args, sort_keys=True)}:{target_path}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, cache_key: str) -> CheckResult | None:
        """Look up a cached check result."""
        return self._store.get(cache_key)

    def set(self, cache_key: str, result: CheckResult) -> None:
        """Store a check result in cache."""
        self._store[cache_key] = result

    def __len__(self) -> int:
        return len(self._store)
