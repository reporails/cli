"""One owner for applying a workflow's keyed fixes: `ails check --heal` and the MCP `heal_apply` call it."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.heal.keyed import KeyedResult, keyed_heal
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.utils.utils import matches_any_glob

HEAL_PRO_REQUIRED = "Applying fixes needs a Pro account."
HEAL_SIGN_IN = "Run `ails login` to enable fixes."


def allowed_set(target: Path, allowed_files: Iterable[Path] | None) -> set[Path] | None:
    """The resolved files heal may write: the scoped heal files less those the project's `heal_exclude` matches."""
    allowed = {safe_resolve(p) for p in allowed_files} if allowed_files is not None else None
    patterns = get_project_config(target).heal_exclude
    if allowed is not None and patterns:
        allowed = {p for p in allowed if not matches_any_glob(p, patterns, safe_resolve(target))}
    return allowed


def resolved_within(path: Path, scope: Path) -> bool:
    """True when the file's real (symlink-resolved) location is within `scope`: heal writes through to the
    real file, so a file whose real path escapes the named scope is never written."""
    real, root = safe_resolve(path), safe_resolve(scope)
    return real == root or real.is_relative_to(root)


def suppressed_by_path(files: Iterable[Path], target: Path) -> dict[Path, set[int]]:
    """The lines each file annotated with an `ails-disable-line` directive, keyed by resolved path."""
    from reporails_cli.core.lint.suppression import suppressed_lines

    raw = suppressed_lines([str(f) for f in files], target)
    return {safe_resolve(Path(k)): v for k, v in raw.items()}


def apply_keyed_heal(
    ruleset_map: Any,
    target: Path,
    workflow: Any,
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
    from reporails_cli.core.pipeline.mapping import map_instruction_files

    if ruleset_map is None or workflow is None:
        return KeyedResult()

    def remap(files: list[Path]) -> Any:
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
