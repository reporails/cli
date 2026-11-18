"""One owner for applying a workflow's keyed fixes: `ails check --heal` and the x-ray page's per-file heal."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.heal.keyed import keyed_heal
from reporails_cli.core.lint.suppression import suppressed_lines
from reporails_cli.core.mapper.models import Models
from reporails_cli.core.pipeline.check_one import check_path
from reporails_cli.core.pipeline.mapping import map_instruction_files
from reporails_cli.core.platform.config.api_key import has_api_key
from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.contract.environment import EnvironmentFor
from reporails_cli.core.platform.contract.http_get import HttpGet
from reporails_cli.core.platform.dto.diagnostics import AUTH_REJECTED_ERRORS, RemediationWorkflow, tiers_unpaid
from reporails_cli.core.platform.dto.heal import HealOutcome, KeyedResult
from reporails_cli.core.platform.dto.pipeline import Refusal
from reporails_cli.core.platform.dto.ports import DaemonTransport, LintService
from reporails_cli.core.platform.dto.results import ConfiguredRoot
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.utils.utils import matches_any_glob

HEAL_PRO_REQUIRED = "Applying fixes needs a Pro account."
HEAL_SIGN_IN = "Sign in to a Pro account with `ails login` to apply them; the diagnosis is complete either way."
HEAL_NO_FIXES = "The server sent no fixes, so nothing was changed."

HEAL_REQUIRES_AUTH = "heal_requires_auth"
HEAL_REQUIRES_PRO = "heal_requires_pro"
HEAL_NO_FIXES_CODE = "heal_no_fixes"


def heal_signed_in(error: str | None) -> bool:
    """True when a key is present and the server did not reject it in this same run (`error` is the
    run's server error token, if any)."""
    return has_api_key() and error not in AUTH_REJECTED_ERRORS


def heal_withheld_for_run(
    *, error: str | None, tier: str | None, funnel_tier: str | None, server_replied: bool
) -> tuple[str, str]:
    """`(code, message)` for a run that wrote nothing, from what the run returned: its server error
    token, the reply's tier and the server error's tier, and whether the server sent a reply.

    Only a reply whose tier is known not to be paid reads as "needs a Pro account"; a paid or
    unnamed tier with no fixes reads as "the server sent no fixes".
    """
    return heal_withheld(
        signed_in=heal_signed_in(error), server_replied=server_replied and tiers_unpaid(tier, funnel_tier)
    )


def heal_server_replied(*, mapped: bool, offline: bool, rejected: bool) -> bool:
    """True when the server answered with a report: the run mapped the files, was not offline and the server
    did not reject it. The one answer to "did the server reply" for a heal that wrote nothing."""
    return mapped and not (offline or rejected)


def heal_withheld(*, signed_in: bool, server_replied: bool) -> tuple[str, str]:
    """Why a heal run writes nothing: `(code, message)` from the account and what the server sent back.

    No key: fixes need a Pro account and a sign-in. A key but no server reply (unreachable,
    rate-limited, rewrite plan not built): no fixes came, so nothing changed. A reply without fixes:
    the account is not Pro.
    """
    if not signed_in:
        return HEAL_REQUIRES_AUTH, f"{HEAL_PRO_REQUIRED} {HEAL_SIGN_IN}"
    if not server_replied:
        return HEAL_NO_FIXES_CODE, HEAL_NO_FIXES
    return HEAL_REQUIRES_PRO, f"{HEAL_PRO_REQUIRED} Nothing was changed."


def allowed_set(target: Path, allowed_files: Iterable[Path] | None, heal_exclude: list[str]) -> set[Path] | None:
    """The resolved files heal may write: the scoped heal files less those `heal_exclude` matches."""
    allowed = {safe_resolve(p) for p in allowed_files} if allowed_files is not None else None
    if allowed is not None and heal_exclude:
        allowed = {
            p for p in allowed if not matches_any_glob(p, heal_exclude, safe_resolve(target), root_anchored=True)
        }
    return allowed


def heal_bound(scope: Path, project_root: Path) -> Path:
    """The folder heal may not write outside: `scope` when it is a folder, else `project_root`.

    A file named as the scope would bound heal by its own real path, so a symlink at that
    path would pass for any destination; the project holding the file bounds it instead.
    """
    return scope if scope.is_dir() else project_root


def resolved_within(path: Path, scope: Path) -> bool:
    """True when the file's real (symlink-resolved) location is within `scope`: heal writes through to the
    real file, so a file whose real path escapes the named scope is never written."""
    real, root = safe_resolve(path), safe_resolve(scope)
    return real == root or real.is_relative_to(root)


def heal_scope_outside(files: Iterable[Path], scope: Path, project_root: Path) -> list[Path]:
    """The files whose real path escapes `heal_bound`: heal never writes through them."""
    bound = heal_bound(scope, project_root)
    return [f for f in files if not resolved_within(f, bound)]


def heal_scope_files(files: Iterable[Path], scope: Path, project_root: Path) -> list[Path]:
    """The files heal may write for `scope`: those within `heal_bound`.

    A file scope names that file alone: a file it `@import`s, though mapped with it, is left alone.
    """
    bound = heal_bound(scope, project_root)
    kept = [f for f in files if resolved_within(f, bound)]
    if scope.is_dir():
        return kept
    named = safe_resolve(scope)
    return [f for f in kept if safe_resolve(f) == named]


def suppressed_by_path(files: Iterable[Path], target: Path) -> dict[Path, set[int]]:
    """The lines each file annotated with an `ails-disable-line` directive, keyed by resolved path."""
    raw = suppressed_lines([str(f) for f in files], target)
    return {safe_resolve(Path(k)): v for k, v in raw.items()}


def heal_remap(
    root: ConfiguredRoot, daemon: DaemonTransport, models: Models
) -> Callable[[list[Path]], RulesetMap | None]:
    """The re-map a heal run checks each written file with: the files mapped under `root`'s mapper config."""

    def remap(files: list[Path]) -> RulesetMap | None:
        return map_instruction_files(
            root.root, files, spawn_daemon=False, mapper=root.config.mapper, daemon=daemon, models=models
        )

    return remap


def apply_keyed_heal(
    ruleset_map: RulesetMap | None,
    root: ConfiguredRoot,
    workflow: RemediationWorkflow | None,
    *,
    dry_run: bool,
    allowed_files: Iterable[Path] | None,
    suppressed: Mapping[Path, set[int]] | None,
    environment_for: EnvironmentFor,
    remap: Callable[[list[Path]], RulesetMap | None],
) -> KeyedResult:
    """Fix each finding the workflow lists at the place it names; list the places that need a decision.

    `allowed_files` bounds the write set (a file `heal_exclude` matches is never written); `suppressed`
    maps a resolved path to its `ails-disable-line` lines, which heal leaves alone. A written file is
    re-mapped through `remap` and checked against its plan; one that departs is put back.
    """
    if ruleset_map is None or workflow is None:
        return KeyedResult()
    target, config = root.root, root.config
    return keyed_heal(
        ruleset_map,
        target,
        workflow,
        dry_run=dry_run,
        allowed_files=allowed_set(target, allowed_files, config.heal_exclude),
        suppressed=suppressed,
        remap=remap,
        environment_for=environment_for,
    )


def heal_workflow_within(
    ruleset_map: RulesetMap,
    workflow: RemediationWorkflow | None,
    target: Path,
    root: ConfiguredRoot,
    *,
    environment_for: EnvironmentFor,
    daemon: DaemonTransport,
    models: Models,
) -> KeyedResult:
    """Write the workflow's keyed fixes to the mapped files inside `target`'s scope (`heal_scope_files`).

    A file `heal_exclude` matches is never written and a line annotated with `ails-disable-line` is left
    alone; a written file is re-mapped and checked against its plan, and one that departs is put back.
    """
    files = sorted({Path(a.file_path) for a in ruleset_map.atoms})
    files = heal_scope_files(files, target, root.root)
    return apply_keyed_heal(
        ruleset_map,
        root,
        workflow,
        dry_run=False,
        allowed_files=files,
        suppressed=suppressed_by_path(files, root.root),
        environment_for=environment_for,
        remap=heal_remap(root, daemon, models),
    )


def heal_one(
    path: str,
    project_root: Path,
    *,
    lint: LintService,
    environment_for: EnvironmentFor,
    run: RunContext,
    fetch: HttpGet,
    daemon: DaemonTransport,
    models: Models,
) -> HealOutcome:
    """Check one file and write the fixes the reply carries for it.

    A refused check, a run with no map or no workflow writes nothing and says why in the words
    `ails check --heal` uses.
    """
    checked = check_path(path, project_root, lint=lint, run=run, fetch=fetch, daemon=daemon, models=models)
    target = Path(path)
    if isinstance(checked, Refusal):
        return HealOutcome(None, checked.text, target.parent)
    workflow = checked.result.reply.workflow
    if checked.ruleset_map is None or workflow is None:
        error = checked.funnel_error
        replied = heal_server_replied(
            mapped=checked.ruleset_map is not None, offline=checked.result.offline, rejected=error is not None
        )
        _, message = heal_withheld_for_run(
            error=error.error if error else None,
            tier=checked.result.reply.tier,
            funnel_tier=error.tier if error else None,
            server_replied=replied,
        )
        return HealOutcome(None, message, checked.scope.scan_root)
    written = heal_workflow_within(
        checked.ruleset_map,
        workflow,
        safe_resolve(target),
        run.configured_root(checked.scope.scan_root),
        environment_for=environment_for,
        daemon=daemon,
        models=models,
    )
    return HealOutcome(written, "", checked.scope.scan_root)
