"""One timed stage of a run."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StageRecord:
    """One timed stage: its label and its duration in milliseconds."""

    stage: str
    ms: float
