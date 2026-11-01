"""One owner for applying a workflow's keyed fixes: `ails check --heal` and the MCP `heal_apply` call it."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.heal.keyed import keyed_heal
from reporails_cli.core.lint.suppression import suppressed_lines
from reporails_cli.core.pipeline.check_one import check_path
from reporails_cli.core.pipeline.mapping import map_instruction_files
from reporails_cli.core.platform.adapters.api_key import has_api_key
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.dto.diagnostics import AUTH_REJECTED_ERRORS, RemediationWorkflow, tiers_unpaid
from reporails_cli.core.platform.dto.heal import HealOutcome, KeyedResult
from reporails_cli.core.platform.dto.pipeline import Refusal
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


def allowed_set(target: Path, allowed_files: Iterable[Path] | None) -> set[Path] | None:
    """The resolved files heal may write: the scoped heal files less those the project's `heal_exclude` matches."""
    allowed = {safe_resolve(p) for p in allowed_files} if allowed_files is not None else None
    patterns = get_project_config(target).heal_exclude
    if allowed is not None and patterns:
        allowed = {p for p in allowed if not matches_any_glob(p, patterns, safe_resolve(target), root_anchored=True)}
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


def suppressed_by_path(files: Iterable[Path], target: Path) -> dict[Path, set[int]]:
    """The lines each file annotated with an `ails-disable-line` directive, keyed by resolved path."""
    raw = suppressed_lines([str(f) for f in files], target)
    return {safe_resolve(Path(k)): v for k, v in raw.items()}


def apply_keyed_heal(
    ruleset_map: RulesetMap | None,
    target: Path,
    workflow: RemediationWorkflow | None,
    *,
    dry_run: bool,
    allowed_files: Iterable[Path] | None,
    suppressed: Mapping[Path, set[int]] | None,
) -> KeyedResult:
    """Fix each finding the workflow lists at the place it names; list the places that need a decision.

    `allowed_files` bounds the write set (a file `heal_exclude` matches is never written); `suppressed`
    maps a resolved path to its `ails-disable-line` lines, which heal leaves alone. A written file is
    re-mapped and checked against its plan; one that departs is put back.
    """
    if ruleset_map is None or workflow is None:
        return KeyedResult()

    def remap(files: list[Path]) -> RulesetMap | None:
        return map_instruction_files(target, files, spawn_daemon=False)

    return keyed_heal(
        ruleset_map,
        target,
        workflow,
        dry_run=dry_run,
        allowed_files=allowed_set(target, allowed_files),
        suppressed=suppressed,
        remap=remap,
    )


def heal_workflow_within(
    ruleset_map: RulesetMap, workflow: RemediationWorkflow | None, target: Path, scan_root: Path
) -> KeyedResult:
    """Write the workflow's keyed fixes to the mapped files inside `target`'s scope (`heal_bound`).

    A file `heal_exclude` matches is never written and a line annotated with `ails-disable-line` is left
    alone; a written file is re-mapped and checked against its plan, and one that departs is put back.
    """
    files = sorted({Path(a.file_path) for a in ruleset_map.atoms})
    files = [f for f in files if resolved_within(f, heal_bound(target, scan_root))]
    return apply_keyed_heal(
        ruleset_map,
        scan_root,
        workflow,
        dry_run=False,
        allowed_files=files,
        suppressed=suppressed_by_path(files, scan_root),
    )


def heal_one(path: str) -> HealOutcome:
    """Check one file and write the fixes the reply carries for it, as `heal_apply` does.

    A refused check, a run with no map or no workflow writes nothing and says why in the words
    `ails check --heal` uses.
    """
    run = check_path(path)
    target = Path(path)
    if isinstance(run, Refusal):
        return HealOutcome(None, run.text, target.parent)
    workflow = run.result.reply.workflow
    if run.ruleset_map is None or workflow is None:
        error = run.funnel_error
        replied = heal_server_replied(
            mapped=run.ruleset_map is not None, offline=run.result.offline, rejected=error is not None
        )
        _, message = heal_withheld_for_run(
            error=error.error if error else None,
            tier=run.result.reply.tier,
            funnel_tier=error.tier if error else None,
            server_replied=replied,
        )
        return HealOutcome(None, message, run.scope.scan_root)
    written = heal_workflow_within(run.ruleset_map, workflow, safe_resolve(target), run.scope.scan_root)
    return HealOutcome(written, "", run.scope.scan_root)
