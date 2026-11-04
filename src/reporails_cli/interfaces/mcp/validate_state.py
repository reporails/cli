"""The per-`(path, targets)` state `validate` keeps between calls: its circuit breaker, stored reply and scan root."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.ruleset import RulesetMap

# Circuit breaker: content-aware loop detection.
MAX_CALLS = 10
MAX_UNCHANGED = 2


@dataclass
class CircuitState:
    """What the last `validate` calls for one `(path, targets)` left behind."""

    call_count: int = 0
    last_mtime_hash: str = ""
    consecutive_unchanged: int = 0
    # The full (unbounded) payload from the last run against `last_mtime_hash`. A `full=true`
    # follow-up to a bounded call (the response's own hint tells the caller to make exactly
    # this call) is served from here instead of re-running the pipeline, and does not count
    # as an unchanged repeat — only a re-run after a content change counts.
    full_payload: JsonObject | None = None
    # The last fresh reply came to a signed-in user on a non-paid tier: it is never reused, since
    # the user may have upgraded since (the sign-in on disk still names the old tier).
    unpaid_reply: bool = False
    # The scan root the last validate resolved `path` against — what `remedy_brief` resolves
    # a location's (project-relative / `~/…`) file paths back to absolute against.
    scan_root: Path | None = None
    # The ruleset map + file score from the last fresh pipeline run against `last_mtime_hash` —
    # a cached (unchanged-content) reply's preservation check reuses these instead of
    # re-running the pipeline a second time just to get them again.
    last_ruleset_map: RulesetMap | None = None
    last_score: float | None = None
    # The notices a text view already showed for this path: each shows once per run.
    shown_notices: set[str] = field(default_factory=set)


validate_states: dict[str, CircuitState] = {}


def state_key(path: str, root: Path, tokens: tuple[str, ...]) -> str:
    """The circuit-breaker / workflow key: the resolved path under the resolved project folder, plus the
    targets when any — a targeted `validate` and a whole-project one keep separate counters and workflows,
    and one path read under two project folders keeps two."""
    key = f"{Path(path).resolve()}|root={root.resolve()}"
    return f"{key}|targets={','.join(tokens)}" if tokens else key
