"""Constants and small utility functions for text display output.

Shared by display.py and scorecard.py. No Rich console usage here —
this module is pure data and path logic.
"""

from __future__ import annotations

import shutil
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

# ── Aggregate rule sets ───────────────────────────────────────────────

# Diagnostics NOT in this set are displayed as structural findings (top of card).
# This includes: "general" (no atoms), memory-*, description-mismatch, and any
# new diagnostics — they appear as actionable structural items by default.
AGGREGATE_RULES = {
    # Server diagnostics — per-atom
    "CORE:C:0042",
    "CORE:E:0004",
    "CORE:C:0043",
    "CORE:E:0003",
    # Server diagnostics — interaction
    "CORE:C:0041",
    "CORE:C:0044",
    "CORE:C:0046",
    "CORE:C:0047",
    "CORE:D:0002",
    "CORE:C:0051",
    "CORE:C:0050",
    "CORE:C:0040",
    # Client check labels
    "format",
    "bold",
    "orphan",
    "heading_instruction",
    "ordering",
    "scope",
    # Classifier confidence
    "ambiguous_charge",
}

AGGREGATE_LABELS: dict[str, str] = {
    "CORE:C:0042": "vague",
    "CORE:E:0004": "brief",
    "CORE:C:0043": "weak",
    "CORE:E:0003": "bold issues",
    "CORE:C:0041": "diluted",
    "CORE:C:0044": "overloaded",
    "CORE:C:0046": "conflicting",
    "CORE:C:0047": "buried",
    "CORE:D:0002": "unbalanced",
    "CORE:C:0051": "weak overall",
    "CORE:C:0050": "low coverage",
    "CORE:C:0040": "redundant",
    "format": "unformatted",
    "bold": "bold",
    "orphan": "orphan",
    "heading_instruction": "heading as instruction",
    "ordering": "misordered",
    "scope": "broad scope",
    "ambiguous_charge": "ambiguous",
}

AGG_ORDER = [
    "CORE:C:0042",
    "CORE:E:0004",
    "CORE:C:0043",
    "format",
    "CORE:E:0003",
    "bold",
    "ordering",
    "orphan",
    "heading_instruction",
    "scope",
    "ambiguous_charge",
    "CORE:C:0044",
    "CORE:C:0041",
    "CORE:C:0047",
    "CORE:D:0002",
    "CORE:C:0046",
    "CORE:C:0051",
    "CORE:C:0050",
    "CORE:C:0040",
]

SEV_WEIGHT = {"error": 0, "warning": 1, "info": 2}
HRULE = "\u2500" * 56

HINT_TYPE_LABELS = {
    "CORE:C:0044": "topic overload",
    "CORE:C:0047": "buried instructions",
    "CORE:C:0046": "conflicts",
    "CORE:C:0041": "content dilution",
    "CORE:C:0051": "vague overall",
    "CORE:D:0002": "unbalanced topics",
    "CORE:C:0050": "low named coverage",
    "CORE:C:0053": "isolated instructions",
    "CORE:C:0040": "repetition",
}

HINT_SEV_ORDER = {"error": 0, "warning": 1, "info": 2}

# Client-check labels map to their canonical rule ID so local findings display the ID like
# server findings. Unmapped tokens (server IDs, ambiguous_charge) pass through unchanged.
CLIENT_CHECK_RULE_ID = {
    "format": "CORE:E:0003",
    "bold": "CORE:E:0003",
    "ordering": "CORE:D:0003",
    "scope": "CORE:C:0048",
    "heading_instruction": "CORE:S:0039",
    "orphan": "CORE:C:0053",
}


def display_rule_id(rule: str) -> str:
    """Canonical rule ID for a finding's rule token; unmapped tokens pass through."""
    return CLIENT_CHECK_RULE_ID.get(rule, rule)


_RULE_DOCS_BASE = "https://reporails.com/rules"


@lru_cache(maxsize=1)
def _rule_slug_map() -> dict[str, str]:
    """`{rule_id: slug}` from the bundled framework registry, loaded once per process."""
    from reporails_cli.core.platform.adapters.rules_query import load_all_rules

    try:
        return {r.id: r.slug for r in load_all_rules() if r.slug}
    except (OSError, ValueError):
        return {}


def rule_docs_url(rule_id: str) -> str | None:
    """Public docs URL (`/rules/<agent|core>/<slug>`) for a canonical rule ID, or None."""
    parts = rule_id.split(":")
    if len(parts) != 3:
        return None
    slug = _rule_slug_map().get(rule_id)
    if not slug:
        return None
    agent = "core" if parts[0] == "CORE" else parts[0].lower()
    return f"{_RULE_DOCS_BASE}/{agent}/{slug}"


def linked_rule_id(rule: str) -> str:
    """Rule token as a Rich hyperlink to its docs page; plain canonical ID if unresolvable."""
    rule_id = display_rule_id(rule)
    url = rule_docs_url(rule_id)
    return f"[link={url}]{rule_id}[/link]" if url else rule_id


def rule_aliases(rule: str) -> set[str]:
    """Every name a suppression directive may use for a finding's rule: raw token, canonical ID, slug."""
    canon = display_rule_id(rule)
    names = {rule, canon}
    slug = _rule_slug_map().get(canon)
    if slug:
        names.add(slug)
    return names


# ── File classification lookup tables ─────────────────────────────────

_CONFIG_NAMES = frozenset(("settings.json", ".mcp.json", "config.yml", "settings.local.json"))
# Case-sensitive — matches agent specs (CLAUDE.md, AGENTS.md uppercase per
# Codex source `DEFAULT_AGENTS_MD_FILENAME = "AGENTS.md"` and the agents.md
# spec). Wrong-case copies (e.g. `agents.md` lowercase in skill assets) are
# not real instruction files.
_MAIN_NAMES = frozenset(("CLAUDE.md", "AGENTS.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md"))

_TYPE_ORDER = ["main", "nested", "rule", "skill", "agent", "config", "memory", "file"]
_TYPE_PLURALS = {
    "main": "main",
    "nested": "nested",
    "rule": "rules",
    "skill": "skills",
    "agent": "agents",
    "config": "configs",
    "memory": "memory",
    "file": "files",
}

# ── Small utility functions ────────────────────────────────────────────


def get_sev_icons(ascii_mode: bool) -> dict[str, str]:
    """Return severity icon mapping for the given display mode."""
    if ascii_mode:
        return {"error": "[red]![/red]", "warning": "[yellow]![/yellow]", "info": "[dim]-[/dim]"}
    return {"error": "[red]\u2717[/red]", "warning": "[yellow]\u26a0[/yellow]", "info": "[dim]\u2139[/dim]"}


def get_term_width() -> int:
    """Get terminal width, defaulting to 80."""
    return shutil.get_terminal_size((80, 24)).columns


def truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len, adding ellipsis if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "\u2026"


def classify_file(filepath: str) -> str:
    """Classify a file path into a human-readable type tag."""
    p = Path(filepath)
    name = p.name
    parts = p.parts

    # Check structural directories first
    if "skills" in parts and name == "SKILL.md":
        idx = parts.index("skills")
        return f"skill:{parts[idx + 1]}" if idx + 1 < len(parts) - 1 else "skill"
    if "agents" in parts and name.endswith(".md"):
        return f"agent:{p.stem}"
    if "rules" in parts and name.endswith(".md"):
        return f"rule:{p.stem}"

    # Check name-based and directory-based categories
    tag = _classify_by_name(name, parts)
    return tag if tag else "file"


def _classify_by_name(name: str, parts: tuple[str, ...]) -> str:
    """Classify by filename or directory membership. Returns empty string if unrecognized."""
    if name in _CONFIG_NAMES:
        return "config"
    if "memory" in parts:
        return "memory"
    # Case-sensitive — matches discovery (walk_glob) and agent specs.
    # Wrong-case copies (e.g. `agents.md` lowercase) are not instruction files.
    if name in _MAIN_NAMES:
        # Files at the project root are `main`; subdirectory copies of the
        # same filename are `nested` (per scope: nested in agent.schema.yml).
        # `parts` for a relative path like `tests/CLAUDE.md` has length 2;
        # a root-level `CLAUDE.md` has length 1.
        return "main" if len(parts) <= 1 else "nested"
    return ""


def friendly_name(filepath: str, tag: str) -> str:
    """Extract a friendly display name from the tag. Falls back to filename.

    For `nested` files (subdirectory copies of CLAUDE.md / AGENTS.md /
    GEMINI.md), return the FULL relative path so users can locate the file
    — `web/CLAUDE.md` alone is ambiguous when the file actually lives at
    `packages/web/CLAUDE.md`.
    """
    if ":" in tag:
        return tag.split(":", 1)[1]
    p = Path(filepath)
    if tag == "nested" and not p.is_absolute():
        # Show the full relative path for nested files so the user can find them
        return p.as_posix()
    if p.parent.name and p.parent.name != ".":
        return f"{p.parent.name}/{p.name}"
    return p.name


def short_path(file_path: str) -> str:
    """Extract short display path for file headers."""
    p = Path(file_path)
    home = Path.home()
    if p.is_absolute():
        try:
            rel = p.relative_to(home).as_posix()
            if "memory" in p.parts:
                idx = p.parts.index("memory")
                return "~/" + str(Path(*p.parts[idx:]))
            return "~/" + rel
        except ValueError:
            pass
    parts = p.parts
    if "memory" in parts:
        idx = parts.index("memory")
        return str(Path(*parts[idx:]))
    for i, part in enumerate(parts):
        if part in (".claude", "tests"):
            return str(Path(*parts[i:]))
        if part.endswith(".md") and part[:1].isupper():
            return str(Path(*parts[i:]))
    return p.name


def file_type_summary(filepaths: set[str]) -> str:
    """Build a compact type breakdown like '1 main, 8 rules, 3 skills'."""
    type_counts: Counter[str] = Counter()
    for fp in filepaths:
        tag = classify_file(fp)
        base = tag.split(":")[0]
        type_counts[base] += 1

    parts = []
    for t in _TYPE_ORDER:
        n = type_counts.get(t, 0)
        if n > 0:
            label = _TYPE_PLURALS.get(t, t) if n > 1 else t
            parts.append(f"{n} {label}")
    return ", ".join(parts)


def index_atoms_by_norm_path(atoms: Any, project_root: Path) -> dict[str, list[Any]]:
    """Group atoms by normalized file path, normalizing each distinct path once.

    Collapses the per-card / per-group re-normalization of every atom (an
    O(atoms x files) render hot loop) into one `normalize_finding_path` call per
    distinct `file_path`. Built once per render and shared via `_CardContext`.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    memo: dict[str, str] = {}
    out: dict[str, list[Any]] = {}
    for a in atoms:
        fp = a.file_path
        norm = memo.get(fp)
        if norm is None:
            norm = normalize_finding_path(fp, project_root)
            memo[fp] = norm
        out.setdefault(norm, []).append(a)
    return out


def per_file_stats(
    filepath: str,
    ruleset_map: Any,
    project_root: Path,
    atoms_by_path: dict[str, list[Any]] | None = None,
) -> str:
    """Compute per-file stats from RulesetMap atoms. Returns compact stat string.

    `atoms_by_path` is the prebuilt normalized-path index from
    `index_atoms_by_norm_path`; when absent (e.g. ad-hoc callers/tests) it falls
    back to the per-atom normalize scan.
    """
    if ruleset_map is None or len(filepath) < 3:
        return ""
    try:
        from reporails_cli.core.platform.runtime.merger import normalize_finding_path

        norm_target = normalize_finding_path(filepath, project_root)
        if atoms_by_path is not None:
            atoms = atoms_by_path.get(norm_target, [])
        else:
            atoms = [a for a in ruleset_map.atoms if normalize_finding_path(a.file_path, project_root) == norm_target]
    except (AttributeError, TypeError):
        return ""
    if not atoms:
        return ""
    return _format_atom_stats(atoms)


def _format_atom_stats(atoms: list[Any]) -> str:
    """Format atom stats into a compact display string."""
    n_dir = sum(1 for a in atoms if a.charge_value == +1)
    n_con = sum(1 for a in atoms if a.charge_value == -1)
    n_amb = sum(1 for a in atoms if a.ambiguous)
    n_total = len(atoms)
    prose_pct = round(100 * (n_total - n_dir - n_con) / n_total) if n_total else 0

    instr_parts = []
    if n_dir:
        instr_parts.append(f"{n_dir} dir")
    if n_con:
        instr_parts.append(f"{n_con} con")
    if n_amb:
        instr_parts.append(f"{n_amb} amb")
    instr_str = " / ".join(instr_parts) if instr_parts else "0 instr"
    return f"{instr_str} \u00b7 {prose_pct}% prose"


def get_group_atoms(
    group_key: str,  # noqa: ARG001
    group_files: list[tuple[str, list[Any]]],
    ruleset_map: Any,
    project_root: Path,
    atoms_by_path: dict[str, list[Any]] | None = None,
) -> list[Any]:
    """Get all atoms belonging to files in this group.

    Uses the prebuilt `atoms_by_path` index when supplied; otherwise falls back
    to the per-atom normalize scan.
    """
    if ruleset_map is None:
        return []
    try:
        from reporails_cli.core.platform.runtime.merger import normalize_finding_path

        norm_fps = {normalize_finding_path(fp, project_root) for fp, _ in group_files}
        if atoms_by_path is not None:
            atoms: list[Any] = []
            for fp in norm_fps:
                atoms.extend(atoms_by_path.get(fp, []))
            return atoms
        return [a for a in ruleset_map.atoms if normalize_finding_path(a.file_path, project_root) in norm_fps]
    except (AttributeError, TypeError):
        return []


def group_stats_line(atoms: list[Any]) -> str:
    """Build a stats summary for a group of atoms."""
    n_dir = sum(1 for a in atoms if a.charge_value == +1)
    n_con = sum(1 for a in atoms if a.charge_value == -1)
    n_total = len(atoms)
    prose_pct = round(100 * (n_total - n_dir - n_con) / n_total) if n_total else 0
    instr_parts = []
    if n_dir:
        instr_parts.append(f"{n_dir} directive")
    if n_con:
        instr_parts.append(f"{n_con} constraint")
    instr_str = " / ".join(instr_parts) if instr_parts else "0 instructions"
    return f"{instr_str} \u00b7 {prose_pct}% prose"
