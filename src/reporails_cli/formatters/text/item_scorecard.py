"""Per-item health-bar rendering for capability listings.

`ails check skills` / `ails check rules` / `ails check agents` render one
bar per item via `compute_item_scores` + `render_item_health`. Same
score formula as the per-surface aggregate; one row per skill folder, and one
row per file for every other kind.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from rich.console import Console

from reporails_cli.formatters.text.display_constants import skill_lookup
from reporails_cli.formatters.text.score import score_color
from reporails_cli.formatters.text.scorecard import SurfaceHealth, _count_tag, _mean_display_score
from reporails_cli.formatters.text.verdict import _score_bar

console = Console()


def compute_item_scores(
    result: Any,
    ruleset_map: Any,
    project_root: Any = None,
    skill_of: dict[str, str] | None = None,
) -> list[SurfaceHealth]:
    """Per-item health scores — name + bar per skill folder or per other scanned file.

    Used by capability-listing mode (`ails check <capability>`) so the
    operator sees which item is the worst at a glance. A skill's whole folder
    is one item named after the skill; every other file is its own item. An
    item's score is the atom-weighted mean of its files' reported `display_score`;
    severity counts are summed over its files' findings.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    if ruleset_map is None:
        return []
    root = Path(project_root) if project_root is not None else Path.cwd()
    skill_of = skill_lookup(ruleset_map, root) if skill_of is None else skill_of

    findings_by_file: dict[str, list[Any]] = {}
    for f in result.findings:
        findings_by_file.setdefault(normalize_finding_path(f.file, root), []).append(f)
    # Server per-file paths are absolute; normalize to the same project-relative
    # key space as `rel` so the per-file display_score lookup matches.
    analysis_by_file: dict[str, Any] = {normalize_finding_path(fa.file, root): fa for fa in result.per_file_analysis}

    try:
        files = list(ruleset_map.files)
    except (AttributeError, TypeError):
        return []
    # item key -> member file paths (insertion-ordered, so a path listed twice counts once); a
    # skill folder shares one key.
    members: dict[str, dict[str, None]] = {}
    for fr in files:
        rel = normalize_finding_path(str(fr.path), root)
        members.setdefault((skill_of or {}).get(rel, rel), {})[rel] = None
    names = _item_names(members, skill_of or {})

    items: list[SurfaceHealth] = []
    for key, paths in members.items():
        rels = list(paths)
        name = names[key]
        findings = [f for rel in rels for f in findings_by_file.get(rel, [])]
        analyses = [analysis_by_file[rel] for rel in rels if rel in analysis_by_file]
        # `None` → unscored: no server analysis, or no score (zero charged atoms).
        items.append(
            SurfaceHealth(
                name=name,
                score=_mean_display_score(analyses),
                file_count=len(rels),
                item_count=1,
                finding_count=len(findings),
                errors=sum(1 for f in findings if f.severity == "error"),
                warnings=sum(1 for f in findings if f.severity == "warning"),
                infos=sum(1 for f in findings if f.severity == "info"),
            )
        )
    # Worst first, alphabetical tiebreak; unscored items sort last (score is None).
    items.sort(key=lambda it: (it.score is None, it.score or 0.0, it.name))
    return items


def _display_name_for_path(rel: str, skill_of: dict[str, str] | None = None) -> str:
    """Return the per-item display label for a path.

    A skill's file (`skill_of` names its skill folder) → the folder name. A `SKILL.md` in no
    skill → its project-relative path. Without a skill lookup, a `SKILL.md` → its parent
    folder's name. Everything else → file stem so
    `git.md` → `git`, `agent-config-staleness.md` → `agent-config-staleness`.
    """
    p = Path(rel)
    if skill_of is not None and rel in skill_of:
        return PurePosixPath(skill_of[rel]).name
    if p.name == "SKILL.md":
        return p.parent.name if skill_of is None else rel
    return p.stem


def _item_names(members: dict[str, dict[str, None]], skill_of: dict[str, str]) -> dict[str, str]:
    """Display name per item key: a skill folder by its name, another file by its stem; two
    skill folders sharing a name are each named by their project-relative folder path."""
    folders = set(skill_of.values())
    names = {
        key: PurePosixPath(key).name if key in folders else _display_name_for_path(key, skill_of) for key in members
    }
    counts = Counter(names.values())
    return {key: key if key in folders and counts[name] > 1 else name for key, name in names.items()}


def _item_cell(s: SurfaceHealth, label_w: int, bar_width: int = 15, count_width: int = 0) -> str:
    """Format one item row: '<name>:  ▓▓▓▓░░░░░░░░░░░  4.2  35 findings · 2 errors'."""
    label = f"{s.name}:"
    suffix = _count_tag(s, count_width)
    if s.score is None:
        empty = "░" * bar_width
        return f"{label:<{label_w}} [dim]{empty}[/dim]  [dim]not scored[/dim]{suffix}"
    color = score_color(s.score)
    bar = _score_bar(s.score, bar_width, color)
    return f"{label:<{label_w}} {bar}  [{color} bold]{s.score:>4.1f}[/{color} bold]{suffix}"


def render_item_health(items: list[SurfaceHealth]) -> None:
    """Render per-item health bars one per line with breathing room.

    Adds a blank line between severity bands (red → yellow → green) so
    the eye naturally chunks the list into "needs attention", "moderate",
    "healthy" clusters.
    """
    if not items:
        return
    label_w = max(len(s.name) for s in items) + 2  # name + ": "
    count_w = max(len(f"{s.finding_count:,}") for s in items)
    console.print()
    prev_band: str | None = None
    for s in items:
        band = "unscored" if s.score is None else score_color(s.score)
        if prev_band is not None and band != prev_band:
            console.print()
        console.print(f"  {_item_cell(s, label_w, count_width=count_w)}")
        prev_band = band
