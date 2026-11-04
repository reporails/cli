"""Shapes of a check run: the scope it covers, what it leaves out, and what it hands back."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, NamedTuple

from reporails_cli.core.platform.dto.diagnostics import FunnelError, LintResult, Notice
from reporails_cli.core.platform.dto.discovery import DetectedAgent, RunExclusions
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.dto.platform import CombinedResult
from reporails_cli.core.platform.dto.ruleset import RulesetMap

# The `(folders, file globs)` a run left out because the user set them.
Excluded = tuple[tuple[str, ...], tuple[str, ...]]

# Why a path was not checked.
RefusalKind = Literal[
    "rules_missing",
    "path_not_found",
    "unknown_agent",
    "empty_project",
    "model_downloading",
    "model_unavailable",
    "failed",
]


@dataclass
class AssembleInputs:
    """Everything the surface-agnostic assemble tail needs from either surface.

    ``filter_agents`` is the agent list the level policy reads (the CLI passes its
    resolved ``filtered`` list; the MCP shell passes its discovered agents until the
    agent-filter drift surface is closed). ``lint_result`` is the surface's own
    server-lint result (or ``None`` when offline) -- this core unpacks its
    ``report``/``hints``/``cross_file_coordinates``/``tier``/``workflow`` itself, so both
    surfaces stop hand-unpacking the same four projections before calling in, and stop
    re-attaching ``workflow`` afterward. ``rule_agents`` names the agents whose rules
    ran (the empty name is the core rule set); left empty, the run is taken to be
    ``effective_agent`` alone.
    """

    m_findings: list[LocalFinding]
    content_findings: list[LocalFinding]
    client_findings: list[LocalFinding]
    ruleset_map: RulesetMap | None
    scan_root: Path
    filter_agents: list[DetectedAgent] | None
    effective_agent: str
    lint_result: LintResult | None
    rule_agents: tuple[str, ...] = ()
    notices: tuple[Notice, ...] = ()
    # `(rule id, file)` pairs whose check did not finish in time; the file is as the check reported it.
    not_evaluated: tuple[tuple[str, str], ...] = ()


class Refusal(NamedTuple):
    """Nothing to check, and why: `kind`, with `message` (a full sentence for the user), for an unknown agent
    its `agent` name, and for an empty project the `target` and what it left out."""

    kind: RefusalKind
    message: str
    target: Path | None = None
    excluded: Excluded = ((), ())
    agent: str = ""

    @property
    def text(self) -> str:
        """The words for the refusal: its message."""
        return self.message


class LeftOut(NamedTuple):
    """What a run left out: the `(folders, file globs)` to report and the exclusion set behind them."""

    record: Excluded = ((), ())
    exclusions: RunExclusions | None = None


class Discovered(NamedTuple):
    """The agents and files a run at one root covers."""

    filter_agents: list[DetectedAgent]
    effective_agent: str
    instruction_files: list[Path]
    file_type_by_path: dict[str, str]
    left_out: LeftOut


class Scope(NamedTuple):
    """Which files a check at one path covers, and how they are read."""

    scan_root: Path
    single_file: Path | None
    filter_agents: list[DetectedAgent]
    effective_agent: str
    instruction_files: list[Path]
    file_type_by_path: dict[str, str]
    left_out: LeftOut


@dataclass(frozen=True)
class CheckRun:
    """One finished check: the merged result, the server's rejection when it sent one, the map and the
    mapper's failure text when the map did not build, and a single file's own display score."""

    result: CombinedResult
    funnel_error: FunnelError | None
    ruleset_map: RulesetMap | None
    mapper_error: str | None
    file_score: float | None
    scope: Scope


class ScopeDiscovery(NamedTuple):
    """What one discovery pass found at a scan root."""

    detected: list[DetectedAgent]
    effective_agent: str
    assumed: bool
    mixed: bool
    filtered: list[DetectedAgent]
    files: list[Path]
    # The `(folders, file globs)` this pass left out because the user set them; empty when it listed no files.
    excluded: tuple[tuple[str, ...], tuple[str, ...]]
    # The run's exclusions: the command-line patterns joined with the project's config.
    exclusions: RunExclusions
