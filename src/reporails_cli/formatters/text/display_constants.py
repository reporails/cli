"""Constants and small utility functions for text display output.

Shared by display.py and scorecard.py. No Rich console usage here —
this module is pure data and path logic.
"""

from __future__ import annotations

import shutil
from collections import Counter
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple

from reporails_cli.core.classify.file_tags import classify_file

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
    "CORE:C:0058",
    # Server diagnostics — interaction
    "CORE:C:0041",
    "CORE:C:0044",
    "CORE:C:0046",
    "CORE:C:0047",
    "CORE:D:0002",
    "CORE:D:0003",
    "CORE:C:0051",
    "CORE:C:0050",
    "CORE:C:0052",
    "CORE:C:0040",
    "CORE:S:0039",
    "CORE:C:0060",
    # Client check labels
    "format",
    "bold",
    "heading_instruction",
    # Classifier confidence
    "ambiguous_charge",
}

AGGREGATE_LABELS: dict[str, str] = {
    "CORE:C:0042": "vague",
    "CORE:E:0004": "brief",
    "CORE:C:0058": "packed",
    "CORE:C:0043": "weak",
    "CORE:E:0003": "bold issues",
    "CORE:C:0041": "excess context",
    "CORE:C:0044": "overlapping",
    "CORE:C:0046": "conflicting",
    "CORE:C:0047": "buried",
    "CORE:D:0002": "unbalanced",
    "CORE:D:0003": "out of order",
    "CORE:C:0051": "weak overall",
    "CORE:C:0050": "context near vague",
    "CORE:C:0052": "default wins",
    "CORE:C:0040": "redundant",
    "format": "unformatted",
    "bold": "bold",
    "heading_instruction": "heading as instruction",
    "CORE:C:0060": "broad scope",
    "ambiguous_charge": "ambiguous",
}

# Rule ids counted under another aggregate key: the heading rule's findings are grouped under
# the short heading label.
AGGREGATE_KEY = {"CORE:S:0039": "heading_instruction"}

AGG_ORDER = [
    "CORE:C:0042",
    "CORE:E:0004",
    "CORE:C:0058",
    "CORE:C:0043",
    "format",
    "CORE:E:0003",
    "bold",
    "heading_instruction",
    "CORE:C:0060",
    "ambiguous_charge",
    "CORE:C:0044",
    "CORE:C:0041",
    "CORE:C:0047",
    "CORE:D:0002",
    "CORE:D:0003",
    "CORE:C:0046",
    "CORE:C:0051",
    "CORE:C:0050",
    "CORE:C:0052",
    "CORE:C:0040",
]

SEV_WEIGHT = {"error": 0, "warning": 1, "info": 2}
HRULE = "\u2500" * 56

HINT_TYPE_LABELS = {
    "CORE:C:0044": "topic overlap",
    "CORE:C:0047": "buried instructions",
    "CORE:C:0046": "conflicts",
    "CORE:C:0041": "content dilution",
    "CORE:C:0051": "vague overall",
    "CORE:D:0002": "unbalanced topics",
    "CORE:D:0003": "prohibitions out of order",
    "CORE:C:0050": "vague instructions amid context",
    "CORE:C:0052": "topics the default wins",
    "CORE:C:0053": "weak instructions",
    "CORE:C:0040": "repetition",
    "CORE:C:0059": "ambiguous phrasing",
}

# ── File classification lookup tables ─────────────────────────────────

_TYPE_ORDER = ["main", "nested", "rules", "skills", "agents", "config", "memory", "file"]
# A tag's count label: (one, many).
_TYPE_LABELS = {
    "main": ("main", "main"),
    "nested": ("nested", "nested"),
    "rules": ("rule", "rules"),
    "skills": ("skill", "skills"),
    "agents": ("agent", "agents"),
    "config": ("config", "configs"),
    "memory": ("memory", "memory"),
    "file": ("file", "files"),
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


def friendly_name(filepath: str, tag: str, skill_dir: str | None = None) -> str:
    """Extract a friendly display name from the tag. Falls back to filename.

    For `nested` files (subdirectory copies of CLAUDE.md / AGENTS.md /
    GEMINI.md), return the FULL relative path so users can locate the file
    — `web/CLAUDE.md` alone is ambiguous when the file actually lives at
    `packages/web/CLAUDE.md`. A skill's own `SKILL.md` is named for the skill; every other
    file in it (`skill_dir` is the skill's directory), a deeper `SKILL.md` included, shows
    its path inside the skill folder (`ails/workflows/heal.md`).
    """
    p = Path(filepath)
    if skill_dir:
        try:
            inside = PurePosixPath(filepath).relative_to(skill_dir).as_posix()
        except ValueError:
            inside = ""
        if inside not in ("", ".", "SKILL.md"):
            return f"{PurePosixPath(skill_dir).name}/{inside}"
    if ":" in tag:
        return tag.split(":", 1)[1]
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
                return "~/" + PurePosixPath(*p.parts[idx:]).as_posix()
            return "~/" + rel
        except ValueError:
            pass
    parts = p.parts
    if "memory" in parts:
        idx = parts.index("memory")
        return PurePosixPath(*parts[idx:]).as_posix()
    for i, part in enumerate(parts):
        if part in (".claude", "tests"):
            return PurePosixPath(*parts[i:]).as_posix()
        if part.endswith(".md") and part[:1].isupper():
            return PurePosixPath(*parts[i:]).as_posix()
    return p.name


def skill_lookup(ruleset_map: Any, project_root: Path) -> dict[str, str] | None:
    """Project-relative path of each file in a skill -> its skill folder (project-relative).

    Reads the skill each file record carries, and each slot folder of a one-level skills root as
    its own skill; a file with none is a plain file. `None` when there is no ruleset map (the
    path-based tags then decide); empty when the map carries no skills.
    """
    from reporails_cli.core.mapper.skills import skill_membership
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    membership = skill_membership(ruleset_map, project_root)
    if membership is None:
        return None
    return {
        normalize_finding_path(path, project_root): normalize_finding_path(folder, project_root)
        for path, folder in membership.items()
    }


class Element(NamedTuple):
    """A harness element a file belongs to: `key` is its identity (the skill folder, else the file), `name` its
    display name, `kind` skill / agent / rule / command (empty for any other file), `where` its location."""

    key: str
    name: str
    kind: str
    where: str

    @property
    def base(self) -> str:
        """The name as written: a command carries its slash."""
        return f"/{self.name}" if self.kind == "command" else self.name

    @property
    def label(self) -> str:
        return f"{self.base} ({self.kind})" if self.kind else self.base


def element_namer(ruleset_map: Any, project_root: Path | None) -> Callable[[str], Element]:
    """Resolve a file to the harness element it belongs to.

    A file in a skill folder is that skill (every file of the folder is one element); an agent
    definition, rule file and command are named by their file stem, by the type the ruleset map
    records for the file. Any other file is named by its project-relative path.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    root = project_root if project_root is not None else Path.cwd()
    skill_of = skill_lookup(ruleset_map, root) or {}
    type_by_path = {normalize_finding_path(fr.path, root): fr.type for fr in getattr(ruleset_map, "files", ())}
    kinds = {"agents": "agent", "rules": "rule", "commands": "command"}
    from reporails_cli.core.discovery.agent_discovery import MEMORY_INDEX_FILENAME, MEMORY_SURFACES

    def element(path: str) -> Element:
        norm = normalize_finding_path(path, root)
        folder = skill_of.get(norm)
        if folder:
            return Element(folder, PurePosixPath(folder).name, "skill", folder)
        ftype = type_by_path.get(norm, "")
        if ftype in MEMORY_SURFACES:
            index = PurePosixPath(norm).name == MEMORY_INDEX_FILENAME
            return Element(
                norm,
                MEMORY_INDEX_FILENAME if index else PurePosixPath(norm).stem,
                "memory index" if index else "memory",
                norm,
            )
        if kind := kinds.get(ftype):
            return Element(norm, PurePosixPath(norm).stem, kind, norm)
        outside = PurePosixPath(norm).is_absolute() or project_root is None
        return Element(norm, short_path(path) if outside else norm, "", norm)

    return element


def partner_list(partners: list[str], limit: int = 3) -> str:
    """A summary line's partners, the first `limit` named and the rest counted."""
    more = [f"+{len(partners) - limit} more"] if len(partners) > limit else []
    return ", ".join([*partners[:limit], *more])


def partner_resolver(result: Any, project_root: Path) -> Callable[[str, str], str]:
    """Resolve the shortened file name a server overlap message carries to the partner's full path.

    The name is looked up among the overlap pairs that include the card's file; exactly one path equal to
    the name, or ending in `/<name>`, resolves it; anything else leaves the name as sent.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path, overlapping_pairs

    partners: dict[str, set[str]] = {}
    for left, right in overlapping_pairs(result.cross_file, getattr(result, "cross_file_coordinates", ())):
        l_norm, r_norm = normalize_finding_path(left, project_root), normalize_finding_path(right, project_root)
        partners.setdefault(l_norm, set()).add(r_norm)
        partners.setdefault(r_norm, set()).add(l_norm)

    def resolve(filepath: str, name: str) -> str:
        found = {
            p
            for p in partners.get(normalize_finding_path(filepath, project_root), ())
            if p == name or p.endswith("/" + name)
        }
        return found.pop() if len(found) == 1 else name

    return resolve


def element_labels(elements: Iterable[Element]) -> dict[str, str]:
    """Display label per element identity; two identities sharing a label each add their location."""
    by_key = {e.key: e for e in elements}
    shared = Counter(e.label for e in by_key.values())
    return {
        k: e.label if shared[e.label] == 1 else f"{e.base} ({e.kind + ', ' if e.kind else ''}{e.where})"
        for k, e in by_key.items()
    }


def group_element_pairs(pairs: list[tuple[Element, Element]]) -> list[tuple[str, list[str]]]:
    """Collapse element pairs (heaviest first) and group them: one `(head, partners)` per element.

    Pairs are keyed on element identity; a pair inside one element is dropped. A pair joins the
    group of an element that already heads one; otherwise its first element heads a new group, so
    no pair is listed twice. A partner of its head's kind drops the kind suffix.
    """
    label = element_labels(e for pair in pairs for e in pair)
    seen: set[frozenset[str]] = set()
    heads: dict[str, Element] = {}
    groups: dict[str, list[Element]] = {}
    for left, right in pairs:
        key = frozenset((left.key, right.key))
        if len(key) < 2 or key in seen:
            continue
        seen.add(key)
        head, partner = (right, left) if right.key in groups and left.key not in groups else (left, right)
        heads[head.key] = head
        groups.setdefault(head.key, []).append(partner)

    def partner_text(head: Element, p: Element) -> str:
        return p.base if p.kind == head.kind and label[p.key] == p.label else label[p.key]

    return [(label[k], [partner_text(heads[k], p) for p in ps]) for k, ps in groups.items()]


def path_tag(filepath: str, skill_of: dict[str, str] | None, norm: str | None = None) -> str:
    """Tag of a path: `skills:<name>` for a file in a skill folder, else the path-based tag.

    With a skill lookup (a ruleset map is present) membership alone decides what is a skill: a
    `SKILL.md` outside every skill folder is a plain `file`. Without one (`None`), the path-based
    tag decides. `norm` is the project-relative form of `filepath` the lookup is keyed by.
    """
    if skill_of is None:
        return classify_file(filepath)
    skill_dir = skill_of.get(filepath if norm is None else norm)
    if skill_dir is not None:
        return f"skills:{PurePosixPath(skill_dir).name}"
    tag = classify_file(filepath)
    return "file" if tag.split(":")[0] == "skills" else tag


def file_type_summary(filepaths: set[str], skill_of: dict[str, str] | None = None) -> str:
    """Build a compact type breakdown like '1 main, 8 rules, 3 skills'; a skill folder counts once."""
    type_counts: Counter[str] = Counter()
    seen: set[str] = set()
    for fp in filepaths:
        key = (skill_of or {}).get(fp, fp)
        if key in seen:
            continue
        seen.add(key)
        type_counts[path_tag(fp, skill_of).split(":")[0]] += 1

    parts = []
    for t in _TYPE_ORDER:
        n = type_counts.get(t, 0)
        if n > 0:
            one, many = _TYPE_LABELS.get(t, (t, t))
            parts.append(f"{n} {many if n > 1 else one}")
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


def counted(n: int, noun: str) -> str:
    """`1 error` / `2 errors`, thousands grouped."""
    return f"{n:,} {noun}{'' if n == 1 else 's'}"


NAMED_OVERLAP_PAIRS = 3  # pair lines a Cross-file list names (Summary and free-tier section); the rest are counted
OVERLAP_HINT = "ails check -v shows each file's overlaps"


def more_pairs_line(hidden: int) -> str:
    """The count of Cross-file pairs a list does not name, with the hint that lists them."""
    return f"+{counted(hidden, 'more pair')} \u00b7 {OVERLAP_HINT}"


def conventions_phrase(n: int) -> str:
    """The counted line for the findings that only ask a file to document something."""
    return f"{counted(n, 'documentation convention')} not present"
