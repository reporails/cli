"""The merged result of a run: findings, stats, the server reply and what was left out."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict

from reporails_cli.core.platform.dto.diagnostics import (
    CrossFileCoordinate,
    CrossFileFinding,
    FileAnalysis,
    FindingItem,
    FunnelError,
    Hint,
    Notice,
    QualityResult,
    RemediationWorkflow,
)
from reporails_cli.core.platform.dto.models import Level
from reporails_cli.core.platform.dto.results import HookEntry


@dataclass(frozen=True)
class CombinedStats:
    """Aggregate statistics for the combined result."""

    total_findings: int = 0
    errors: int = 0
    warnings: int = 0
    infos: int = 0
    cross_file_repetitions: int = 0
    cross_file_overlaps: int = 0  # distinct file pairs whose instructions cover the same topics
    m_probe_count: int = 0
    client_check_count: int = 0
    server_diagnostic_count: int = 0
    # The agents whose rules ran; lets the summary name the agent even when no ruleset map
    # exists (no model on disk); empty when none ran.
    agents: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServerReply:
    """What the diagnostics service answered with, carried onto every output surface."""

    tier: str = ""  # Tier label propagated from LintResult ("free", "pro", "anonymous"); empty when offline
    # The composable remediation HOW; `None` offline, on the anon tier, or
    # from a pre-0.6.0 server. Carried through so JSON / MCP consumers can render it.
    workflow: RemediationWorkflow | None = None
    # The messages the server sent with its reply, for every output surface; empty offline.
    notices: tuple[Notice, ...] = ()
    # The diagnostics outcome when the request was rejected, timed out, or never
    # reached the service (a `FunnelError`); `None` when a response arrived normally
    # or no request was made. Carries the reason so JSON / github output can name it
    # (`offline` alone does not).
    server_error: FunnelError | None = None


@dataclass(frozen=True)
class Omissions:
    """What the run left out or could not check."""

    # The folders and file globs the user left out of the run (built-in default excludes are not listed).
    excluded_dirs: tuple[str, ...] = ()
    excluded_files: tuple[str, ...] = ()
    # True when a checked file imports text from a file the user left out; that text still counts there.
    excluded_imported: bool = False
    # The `(rule id, project-relative file)` pairs whose check did not finish in time, so says
    # nothing about that file; empty when every check finished.
    not_evaluated: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class CombinedResult:
    """Merged local + server findings — the output of the new pipeline."""

    findings: tuple[FindingItem, ...] = ()
    cross_file: tuple[CrossFileFinding, ...] = ()
    quality: QualityResult | None = None
    per_file_analysis: tuple[FileAnalysis, ...] = ()
    stats: CombinedStats = field(default_factory=CombinedStats)
    offline: bool = True
    hints: tuple[Hint, ...] = ()  # from tier gating
    cross_file_coordinates: tuple[CrossFileCoordinate, ...] = ()  # free tier
    level: Level = Level.L0
    reply: ServerReply = field(default_factory=ServerReply)
    # The hooks found in the project's agent hook configs; empty when none were read.
    hooks: tuple[HookEntry, ...] = ()
    omissions: Omissions = field(default_factory=Omissions)


class SeverityCounts(TypedDict):
    """The `CombinedStats` fields holding the total and per-severity finding counts."""

    total_findings: int
    errors: int
    warnings: int
    infos: int
