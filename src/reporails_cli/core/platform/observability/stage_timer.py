"""Per-stage wall-clock timer for `ails check`, heal, MCP tool calls and daemon requests; dev-only.

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

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from reporails_cli.core.platform.config.bootstrap import env_flag
from reporails_cli.core.platform.contract.json_value import JsonValue

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StageRecord:
    """One timed stage: its label and its duration in milliseconds."""

    stage: str
    ms: float


class Stopwatch:
    """Elapsed wall-clock time since construction."""

    def __init__(self) -> None:
        self._start = time.perf_counter()

    @property
    def ms(self) -> float:
        """Milliseconds elapsed since the stopwatch started."""
        return (time.perf_counter() - self._start) * 1000.0

    def restart(self) -> None:
        """Start counting again from now."""
        self._start = time.perf_counter()


class StageTimer:
    """Stage timer. `mark(label)` records the gap since the last mark; `stage(label)` times a block."""

    def __init__(self) -> None:
        self.records: list[StageRecord] = []
        self._enabled = False
        self._lap = Stopwatch()

    @property
    def enabled(self) -> bool:
        """Whether stage marks are being recorded."""
        return self._enabled

    def reset(self) -> None:
        """Clear the timeline and read whether timing is on from `AILS_STAGE_TIMING`.

        Called once per `ails check` and at each process start, so the process-global
        singleton never leaks an `enabled` flag or stale records from a prior run.
        """
        self._enabled = env_flag("AILS_STAGE_TIMING")
        self.records = []
        self._lap.restart()

    def mark(self, label: str) -> None:
        """Record elapsed since the previous mark (or `reset()`) under `label`."""
        if not self._enabled:
            return
        self.records.append(StageRecord(label, self._lap.ms))
        self._lap.restart()

    @contextmanager
    def stage(self, label: str) -> Iterator[None]:
        """Time the block: when timing is on, record it and log `<label> <ms> ms` at INFO."""
        if not self._enabled:
            yield
            return
        watch = Stopwatch()
        try:
            yield
        finally:
            ms = watch.ms
            self.records.append(StageRecord(label, ms))
            logger.info("%s %.1f ms", label, ms)

    @contextmanager
    def run(self, label: str) -> Iterator[None]:
        """Start a fresh timeline, then time the block like `stage(label)`.

        For long-lived processes: each call drops the previous run's records and
        measures marks from its own start, not from the idle time before it.
        """
        self.reset()
        with self.stage(label):
            yield

    def as_dict(self) -> list[JsonValue]:
        """Stage records as `[{stage, ms}, ...]` for JSON emission."""
        return [{"stage": r.stage, "ms": round(r.ms, 1)} for r in self.records]

    def render_lines(self) -> list[str]:
        """Aligned `label   N.N ms` lines for verbose text emission."""
        return [f"{r.stage:<12s} {r.ms:8.1f} ms" for r in self.records]


_TIMER = StageTimer()


def get_stage_timer() -> StageTimer:
    """Return the process-wide stage timer singleton."""
    return _TIMER
