"""Check one path: which files a run covers, the local checks, the server lint and the merged result.

The decisions behind an interface's "check this path" call: whether the rules are installed, whether the
path exists, which agent and files a run covers, whether the model set is ready, the M-probes and content and
client checks, the server lint and the shared assemble spine. A caller gets a typed `CheckRun` or a `Refusal`
naming why nothing was checked, and words the reply itself; no formatter or interface is imported here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, NamedTuple

from reporails_cli.core.discovery.agents import DetectedAgent, get_known_agents
from reporails_cli.core.discovery.exclusions import RunExclusions
from reporails_cli.core.discovery.project_root import resolve_project_root, resolve_project_root_for_file
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.lint.client_checks import run_client_checks
from reporails_cli.core.lint.regex.not_evaluated import not_evaluated_scope
from reporails_cli.core.lint.rule_runner import run_content_quality_checks, run_m_probes_over_pairs
from reporails_cli.core.mapper.model_manifest import ModelFetchError, get_models_path, models_present
from reporails_cli.core.mapper.skills import skill_membership
from reporails_cli.core.pipeline.assemble import (
    AssembleInputs,
    assemble_result,
    lint_request_local,
    with_exclusions,
)
from reporails_cli.core.pipeline.mapping import (
    agent_file_pairs,
    apply_generic_scan,
    discover_scope,
    map_instruction_files,
)
from reporails_cli.core.platform.adapters.api_client import AilsClient
from reporails_cli.core.platform.adapters.notices_seen import visible_notices
from reporails_cli.core.platform.config.config import get_project_config, get_rules_path, is_initialized
from reporails_cli.core.platform.dto.diagnostics import FindingItem, FunnelError, LintResponse, LintResult, Notice
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.runtime.merger import CombinedResult, normalize_finding_path

logger = logging.getLogger(__name__)

# The `(folders, file globs)` a run left out because the user set them.
Excluded = tuple[tuple[str, ...], tuple[str, ...]]

# The `(M-probe, content, client)` findings of one local pass.
LocalFindings = tuple[list[LocalFinding], list[LocalFinding], list[LocalFinding]]

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


def rules_missing_message() -> str:
    """The sentence for a rules folder with no `core` rules: a broken install or a `framework_path` setting
    that points at a folder without them."""
    return (
        f"The rules folder {get_rules_path()} has no `core` rules. The rules ship with the "
        "package: reinstall reporails-cli, or, if the config sets `framework_path`, point it "
        "at a folder that holds them or remove the setting."
    )


class LeftOut(NamedTuple):
    """What a run left out: the `(folders, file globs)` to report and the exclusion set behind them."""

    record: Excluded = ((), ())
    exclusions: RunExclusions | None = None


NOTHING_LEFT_OUT = LeftOut()


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


def resolve_scan_target(target: Path) -> tuple[Path, Path | None]:
    """Map a target to `(scan_root, single_file)`.

    A directory target roots at itself (`resolve_project_root`, CLI parity). A FILE target cannot use that
    same function: it resolves to `target.parent`, which is right for the CLI only because the CLI's actual
    single-file root is the invoking terminal's `cwd`, not the file's directory (see
    `resolve_project_root_for_file`'s docstring). A caller with no cwd to read walks a file target up to the
    real project root instead, matching what the CLI resolves when a human `cd`s there first; otherwise
    `.claude/rules/style.md` roots at `.claude/rules`, which misclassifies the file and never shares the
    CLI's whole-map cache entry for the same file.
    """

    if target.is_file():
        return resolve_project_root_for_file(target), target
    return resolve_project_root(target), None


def discover_files(
    target: Path, single_file: Path | None = None, named: frozenset[Path] = frozenset()
) -> Discovered | Refusal:
    """Detect agents and discover instruction files.

    Returns the `Discovered` set on success, or a `Refusal` when there is nothing to lint: `unknown_agent`
    for a misconfigured `default_agent` (mirroring the CLI's `_validate_agent`), or `empty_project` when
    discovery legitimately comes up empty. An empty set is not an error: an AGENTS.md-only project under a
    `default_agent: claude` misconfiguration, or a rules-only tree with no distinctive main file, reports
    "nothing to find" exactly as the CLI does.

    `target` is the discovery root (a directory). Discovery narrows against the resolved agent set after
    the exclusions, not the raw detected list. When `generic_scanning` is on, the `@`-import-reached files
    join the discovered set. When `single_file` is given the validated set is that one file, kept whatever
    is excluded, while agents resolve against `target`, and `named` is ignored. Otherwise `named` holds
    files the caller named, which stay in the set whatever is excluded.
    """

    config = get_project_config(target)
    normalized_agent = (config.default_agent or "").lower().strip()
    if normalized_agent and normalized_agent not in get_known_agents():
        return Refusal("unknown_agent", f"Unknown agent: {normalized_agent}", agent=normalized_agent)

    # A `single_file` target always resolves (its own existence is checked by the caller); only
    # the whole-project scan can legitimately come up with nothing to lint. The whole-project
    # scan includes each agent's config surfaces (hooks, permissions, MCP declarations, plugin
    # manifests) alongside its instruction and rule files, matching `ails check`'s own scope.
    found = discover_scope(
        target,
        config.default_agent,
        None,
        None,
        scan_files=single_file is None,
        named=frozenset({single_file}) if single_file is not None else named,
    )
    instruction_files = [safe_resolve(single_file)] if single_file is not None else found.files
    if not instruction_files:
        return Refusal("empty_project", f"No instruction files found in {target}", target, found.excluded)

    import_extra, file_type_by_path = apply_generic_scan(
        target, instruction_files, found.effective_agent, config.generic_scanning, found.exclusions
    )
    if import_extra:
        instruction_files = list(instruction_files) + import_extra
    return Discovered(
        found.filtered,
        found.effective_agent,
        instruction_files,
        file_type_by_path,
        LeftOut(found.excluded, found.exclusions),
    )


def build_map(
    target: Path, instruction_files: list[Path], filter_agents: list[DetectedAgent] | None = None
) -> tuple[RulesetMap | None, str | None]:
    """Build the ruleset map via the shared warm path, so a long-lived process reuses a warm model
    instead of loading one on every call.

    Never spawns a background process from here: a caller inside a multi-threaded process can leave a
    new process holding a half-initialized copy of an already-loaded model. It attaches to an
    already-running background helper when one answers, else maps in-process.

    `filter_agents` (the caller's already-resolved `resolve_agent_filters` `filtered` list) is forwarded so
    the file records carry the same corrected agent attribution as the CLI (`map_instruction_files`'s
    `stamp_file_agents`).

    Returns `(ruleset_map, error)`: `error` is `None` on success, else the swallowed exception's own text
    (`"<ExceptionType>: <message>"`), logged here and handed back so a caller can say WHY the map came back
    empty instead of only a bare `None`.
    """
    try:
        return (
            map_instruction_files(target, list(instruction_files), spawn_daemon=False, filtered_agents=filter_agents),
            None,
        )
    except (ImportError, RuntimeError) as exc:
        logger.warning("Mapper unavailable: %s", exc)
        return None, f"{type(exc).__name__}: {exc}"


def model_refusal() -> Refusal | None:
    """Make the model set available (downloading it once); a `Refusal` if it is not.

    While a download already runs in this process (the server's launch-time fetch), answer
    `model_downloading` at once instead of blocking the call on it.
    """

    from reporails_cli.core.mapper import (  # pylint: disable=import-outside-toplevel  # startup: the model fetch loads off the MCP handshake path
        model_fetch,
    )
    from reporails_cli.core.mapper.model_store import (  # pylint: disable=import-outside-toplevel  # startup: the model fetch loads off the MCP handshake path
        ensure_models_available,
    )

    if models_present(get_models_path()):
        return None
    if model_fetch.download_in_progress():
        return Refusal(
            "model_downloading",
            "The model files are still downloading; try again shortly.",
        )
    try:
        ensure_models_available()
    except ModelFetchError as exc:
        return Refusal("model_unavailable", str(exc))
    return None


def scope_for_path(path: str, named: frozenset[Path] = frozenset()) -> Scope | Refusal:
    """The files a check at `path` covers, or why there is nothing to check.

    A directory `path` roots at itself and a file `path` at its project, with that one file checked. For a
    directory `path`, `named` holds files the caller named, which are checked whatever is excluded; for a
    file `path` it is ignored. The refusal is `rules_missing`, `path_not_found`, `unknown_agent`,
    `empty_project` or a model set that is not ready.
    """
    if not is_initialized():
        return Refusal("rules_missing", rules_missing_message())
    target = Path(path).resolve()
    if not target.exists():
        return Refusal("path_not_found", f"Path not found: {target}")
    scan_root, single_file = resolve_scan_target(target)
    discovery = discover_files(scan_root, single_file=single_file, named=named)
    if isinstance(discovery, Refusal):
        return discovery
    model_error = model_refusal()
    if model_error is not None:
        return model_error
    return Scope(scan_root, single_file, *discovery)


def display_score(result: CombinedResult, target: Path | None = None, scan_root: Path | None = None) -> float | None:
    """A single-file run's own per-file display score: the `per_file_analysis` entry whose normalized path
    IS `target`, falling back to the run's aggregate quality score only when `target` has no entry (never
    the first entry blindly: with `generic_scanning` on, `@`-imported files join the scored set, so entry 0
    is not reliably the target's). `None` when neither is scored. `target=None` keeps the first-entry
    fallback, for a caller with no specific file to match."""

    per_file = result.per_file_analysis
    if target is not None:
        target_key = normalize_finding_path(str(target), scan_root)
        match = next((fa for fa in per_file if normalize_finding_path(fa.file, scan_root) == target_key), None)
        if match is not None and match.display_score is not None:
            return float(match.display_score)
    elif per_file and per_file[0].display_score is not None:
        return float(per_file[0].display_score)
    quality = result.quality
    if quality is not None and quality.display_score is not None:
        return float(quality.display_score)
    return None


def _agent_file_pairs(
    scan_root: Path, instruction_files: list[Path], filter_agents: list[DetectedAgent], effective_agent: str
) -> list[tuple[str, list[Path]]]:
    """The shared `core.pipeline.mapping.agent_file_pairs` split: whether the agent is explicit can only
    come from the project's `default_agent` (a call has no per-run `--agent`-style override the way the CLI
    has one)."""

    explicit = bool(get_project_config(scan_root).default_agent)
    return agent_file_pairs(
        instruction_files, filter_agents, scan_root, explicit=explicit, effective_agent=effective_agent
    )


def _checks_over_pairs(
    scan_root: Path,
    pairs: list[tuple[str, list[Path]]],
    ruleset_map: RulesetMap | None,
    scoped: bool,
    exclusions: RunExclusions | None = None,
) -> LocalFindings:
    """Run M-probes + content/client checks over the `(agent, its files)` pairs, returning
    `(m_findings, content_findings, client_findings)`.

    `scoped` mirrors the CLI's `state.scope.is_targeted`: True for a single-file target, so
    project-aggregate mechanical checks (e.g. total-bytes / file-count bounds) are skipped exactly like
    `ails check <file>` skips them.

    The pairs come from the SAME `agent_file_pairs` split the CLI check flow uses: a native file runs its
    owner's rules, an unowned file runs the core rules only, so a check reports identical
    `(rule, file, line)` triples to `ails check` for the same tree.
    """

    skills = skill_membership(ruleset_map)
    m_findings = run_m_probes_over_pairs(scan_root, pairs, scoped=scoped, skills=skills, exclusions=exclusions)
    content_findings: list[LocalFinding] = []
    for agent_id, agent_files in pairs:
        if ruleset_map:
            content_findings.extend(
                run_content_quality_checks(ruleset_map, scan_root, agent_files, agent=agent_id, exclusions=exclusions)
            )
    client_findings = run_client_checks(ruleset_map) if ruleset_map else []
    return m_findings, content_findings, client_findings


def _server_lint(inputs: AssembleInputs) -> LintResponse | None:
    """Send the reported local findings to the server and return the `LintResponse`.

    `.result` is None when offline. Returning the whole response (not just `.result`) lets the caller also
    read `.funnel_error`: a server-side rejection (rate limit, payload/atom cap, project limit) that must
    not read like a network outage. None when nothing was mapped.
    """

    if not inputs.ruleset_map:
        return None
    local, structural_required = lint_request_local(inputs)
    return AilsClient().lint(inputs.ruleset_map, local, structural_required, root=inputs.scan_root)


def _server_lint_result(inputs: AssembleInputs) -> tuple[LintResult | None, FunnelError | None, tuple[Notice, ...]]:
    """Run `_server_lint` and split its response into `(lint_result, funnel_error, notices)`: `(None,
    None, ())` when nothing was mapped (offline / no ruleset)."""
    response = _server_lint(inputs)
    if response is None:
        return None, None, ()
    return response.result, response.funnel_error, visible_notices(response.notices)


def _assemble(
    scan_root: Path,
    effective_agent: str,
    filter_agents: list[DetectedAgent],
    ruleset_map: RulesetMap | None,
    local: LocalFindings,
    *,
    rule_agents: tuple[str, ...],
    not_evaluated: tuple[tuple[str, str], ...],
    exclusions: RunExclusions | None,
) -> tuple[CombinedResult, FunnelError | None]:
    """Server-lint the local findings, then run the shared assemble spine. Returns `(result, funnel_error)`."""

    m_findings, content_findings, client_findings = local
    inputs = AssembleInputs(
        m_findings=m_findings,
        content_findings=content_findings,
        client_findings=client_findings,
        ruleset_map=ruleset_map,
        scan_root=scan_root,
        filter_agents=filter_agents,
        effective_agent=effective_agent,
        lint_result=None,
        rule_agents=rule_agents,
        not_evaluated=not_evaluated,
    )
    lint_result, funnel_error, notices = _server_lint_result(inputs)
    return assemble_result(replace(inputs, lint_result=lint_result, notices=notices), exclusions), funnel_error


def check_and_assemble(
    scan_root: Path,
    instruction_files: list[Path],
    effective_agent: str,
    filter_agents: list[DetectedAgent],
    ruleset_map: RulesetMap | None,
    *,
    left_out: LeftOut = NOTHING_LEFT_OUT,
    scoped: bool = False,
) -> tuple[CombinedResult, FunnelError | None]:
    """Run the local checks, then the server lint and assemble spine; the request is resolved under the
    agents whose rules ran."""
    pairs = _agent_file_pairs(scan_root, instruction_files, filter_agents, effective_agent)
    with not_evaluated_scope() as unfinished:
        local = _checks_over_pairs(scan_root, pairs, ruleset_map, scoped, left_out.exclusions)

    result, funnel_error = _assemble(
        scan_root,
        effective_agent,
        filter_agents,
        ruleset_map,
        local,
        rule_agents=tuple(dict.fromkeys(agent_id for agent_id, _ in pairs)),
        not_evaluated=tuple(unfinished),
        exclusions=left_out.exclusions,
    )
    return with_exclusions(result, left_out.record), funnel_error


def check_scope(scope: Scope) -> CheckRun:
    """Run M-probes + content/client checks over a scope's files and assemble the result.

    Regime and surface health key against `scope.scan_root` (the checked path), not the server cwd.
    Level determination, merge, and post-merge suppression/mutation run through the shared
    `core/pipeline/assemble` spine, so every caller picks up the capability-level coverage the CLI check
    flow has. A single file (`scope.single_file`) scopes the mechanical M-probes the same way
    `ails check <file>` does (project-aggregate checks skipped) and is also when `file_score` is computed.
    A server funnel rejection rides on `funnel_error`; a mapper failure (`ruleset_map` `None`) names its
    cause in `mapper_error`.
    """

    ruleset_map, mapper_error = build_map(scope.scan_root, scope.instruction_files, scope.filter_agents)
    result, funnel_error = check_and_assemble(
        scope.scan_root,
        scope.instruction_files,
        scope.effective_agent,
        scope.filter_agents,
        ruleset_map,
        left_out=scope.left_out,
        scoped=scope.single_file is not None,
    )
    file_score = display_score(result, scope.single_file, scope.scan_root) if scope.single_file is not None else None
    return CheckRun(result, funnel_error, ruleset_map, mapper_error, file_score, scope)


def file_findings(run: CheckRun, file: Path) -> tuple[FindingItem, ...]:
    """The findings a run reports for `file`."""
    key = normalize_finding_path(str(file), run.scope.scan_root)
    return tuple(f for f in run.result.findings if normalize_finding_path(f.file, run.scope.scan_root) == key)


def check_path(path: str, named: frozenset[Path] = frozenset()) -> CheckRun | Refusal:
    """Check `path` (directory or file): the `CheckRun`, or the `Refusal` saying why nothing was checked.

    A file `path` narrows the checked set to that single file. `named` is read as in `scope_for_path`. A
    missing file, a bad value or a runtime failure while checking is a `failed` refusal carrying its text.
    """
    try:
        scope = scope_for_path(path, named)
        if isinstance(scope, Refusal):
            return scope
        return check_scope(scope)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return Refusal("failed", str(e) or f"The check failed ({type(e).__name__}).")
