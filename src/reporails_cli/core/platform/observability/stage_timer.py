"""Per-stage wall-clock timer for `ails check` — dev-only, zero-overhead when off.

Records sequential per-stage durations so a perf fix can be ordered by real
seconds rather than cProfile-inflated ones. Disabled by default: every `mark()`
is a no-op until enabled, so normal runs pay nothing, and it is gated behind a
developer env var (`AILS_STAGE_TIMING`) — the breakdown never reaches the
default text / JSON output.

The timer is a process-global singleton. The CLI entry point marks the coarse
stages; the in-process pipeline marks its finer stages into the same timer on a
cold run. A warm background-process run leaves the finer marks in that process,
so the parent sees only the coarse total.
"""

from __future__ import annotations

import time
from typing import Any


class StageTimer:
    """Sequential stage timer. `mark(label)` records the gap since the last mark."""

    def __init__(self) -> None:
        self.records: list[tuple[str, float]] = []
        self._enabled = False
        self._last = 0.0

    @property
    def enabled(self) -> bool:
        return self._enabled

    def configure(self, enabled: bool) -> None:
        """Set enabled state and reset the timeline.

        Called once per `ails check` so the process-global singleton never leaks
        an `enabled` flag (or stale records) from a prior in-process invocation
        (test runner, MCP server) into the next run.
        """
        self._enabled = enabled
        self.records = []
        self._last = time.perf_counter()

    def mark(self, label: str) -> None:
        """Record elapsed since the previous mark (or `enable()`) under `label`."""
        if not self._enabled:
            return
        now = time.perf_counter()
        self.records.append((label, (now - self._last) * 1000.0))
        self._last = now

    def as_dict(self) -> list[dict[str, Any]]:
        """Stage records as `[{stage, ms}, ...]` for JSON emission."""
        return [{"stage": label, "ms": round(ms, 1)} for label, ms in self.records]

    def render_lines(self) -> list[str]:
        """Aligned `label   N.N ms` lines for verbose text emission."""
        return [f"{label:<12s} {ms:8.1f} ms" for label, ms in self.records]


_TIMER = StageTimer()


def get_stage_timer() -> StageTimer:
    """Return the process-wide stage timer singleton."""
    return _TIMER
