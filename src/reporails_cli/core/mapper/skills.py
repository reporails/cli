"""Skill membership: which mapped files form one skill.

A skill is a folder holding a `SKILL.md` where an agent of the run loads one (the
`entry_patterns` of that agent's `skills` file type). Every `skills` or `generic` file at any
depth below that folder belongs to the outermost such folder; a `SKILL.md` below another skill's
folder is one of that skill's files. Decided once per run and recorded on each `FileRecord`
(`skill`, `type`).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any


def outermost_folder(path: str | Path, folders: Iterable[Path]) -> Path | None:
    """The outermost of `folders` that `path` sits at or below, None when none holds it.

    `folders` holds Paths; a set or dict is used as given.

    Purely lexical: nothing is resolved, so a symlinked file or folder stays in the folder it
    was found in."""
    held = folders if isinstance(folders, (set, frozenset, dict)) else {Path(f) for f in folders}
    if not held:
        return None
    p = Path(path)
    hit: Path | None = None
    for candidate in (p, *p.parents):
        if candidate in held:
            hit = candidate  # parents run innermost to outermost; the last hit is the outermost
    return hit


def _entry_patterns(registry: dict[str, dict[str, Any]], agent: str) -> list[str]:
    """The `entry_patterns` globs of `agent`'s `skills` file type: where a skill's `SKILL.md` may sit."""
    from reporails_cli.core.discovery.agents import _extract_patterns

    ft = ((registry.get(agent) or {}).get("file_types") or {}).get("skills")
    return _extract_patterns(ft, "entry_patterns") if isinstance(ft, dict) else []


def entry_pattern(path: Path, root: Path, patterns: list[str]) -> str | None:
    """The first of `patterns` that `path` matches, anchored the way file-type `patterns` are; None when none does."""
    from reporails_cli.core.discovery.plugin_roots import config_pattern_hits

    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    return next((p for p in patterns if config_pattern_hits(path, rel, p, root)), None)


def skill_entry_folder(cf: Any) -> Path | None:
    """The skill folder a classified file is the entry file of: it is a `SKILL.md` sitting directly in
    the folder its `skill` property records. None for any other file."""
    folder = cf.properties.get("skill")
    if isinstance(folder, str) and Path(cf.path).name == "SKILL.md" and Path(cf.path).parent == Path(folder):
        return Path(folder)
    return None


def skill_type(base: str, path: str | Path, folders: Iterable[Path] | dict[Path, Any]) -> str:
    """The type a file of type `base` takes given the recorded skill `folders`: a `skills` or
    `generic` file at or below one is `skills`, a `skills` file in none is `generic`, any other
    type is unchanged. Folder membership is lexical."""
    if base not in ("skills", "generic"):
        return base
    if outermost_folder(path, folders) is not None:
        return "skills"
    return "generic" if base == "skills" else base


def record_skills(
    ruleset_map: Any,
    agents: Iterable[str],
    root: Path,
    registry: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Decide each record's skill once and record it in place (`skill`, `type`, and for a file
    joining a skill the entry's `loading` / `scope` / `globs` / `agent`).

    A `SKILL.md` typed `skills` is an entry when its path matches the `entry_patterns` of the
    `skills` file type of the run's `agents`, the core agent, or its own record's agent. A folder
    whose `SKILL.md` the map does not carry is a skill folder too when that file exists on disk
    and matches those patterns. Every `skills` or `generic` record at or below a skill folder
    belongs to the outermost such folder and is typed `skills` (taking the entry record's
    `loading` / `scope` / `globs` / `agent` when the map has it); a `skills` record in no skill
    folder becomes `generic`. Records of other types keep their type and belong to no skill. Running it again gives
    the same records.
    """
    from reporails_cli.core.mapper.inspect import _load_registry

    files = getattr(ruleset_map, "files", None)
    if not files:
        return
    folders = _SkillFolders(files, agents, root, _load_registry() if registry is None else registry)
    for rec in files:
        rec.skill = ""
        if rec.type not in ("skills", "generic"):
            continue
        folder = next((f for f in reversed(Path(rec.path).parents) if folders.is_skill(f, rec.agent)), None)
        was = rec.type
        rec.type = skill_type(was, rec.path, () if folder is None else (folder,))
        if folder is None:
            continue
        rec.skill = folder.as_posix()
        if was != "skills":
            _join_skill(rec, folders.entries.get(folder))


class _SkillFolders:
    """Which folders are skill folders for one run, each answer computed once."""

    def __init__(
        self, files: Iterable[Any], agents: Iterable[str], root: Path, registry: dict[str, dict[str, Any]]
    ) -> None:
        self.root = root
        self.registry = registry
        self.base = {*agents, *(a for a, cfg in registry.items() if cfg.get("core"))}
        self._patterns: dict[str, list[str]] = {}
        self._on_disk: dict[tuple[Path, str], bool] = {}
        files = list(files)
        self.by_path = {rec.path for rec in files}
        self.entries: dict[Path, Any] = {}  # folder -> the map's own entry record
        for rec in files:
            path = Path(rec.path)
            if rec.type == "skills" and path.name == "SKILL.md" and self._matches(path, rec.agent):
                self.entries[path.parent] = rec

    def _matches(self, path: Path, agent: str) -> bool:
        for a in (*self.base, agent):
            if a not in self._patterns:
                self._patterns[a] = _entry_patterns(self.registry, a)
        return any(entry_pattern(path, self.root, self._patterns[a]) is not None for a in (*self.base, agent))

    def is_skill(self, folder: Path, agent: str) -> bool:
        """Whether `folder/SKILL.md` is a skill's entry file: the map's own verdict when it carries
        that record, else a match on the agents' entry patterns plus the file existing on disk."""
        candidate = folder / "SKILL.md"
        if candidate.as_posix() in self.by_path:
            return folder in self.entries
        key = (folder, agent)
        if key not in self._on_disk:
            self._on_disk[key] = self._matches(candidate, agent) and _has_file(folder, "SKILL.md")
        return self._on_disk[key]


def _join_skill(rec: Any, owner: Any | None) -> None:
    """A record that was not yet a skill file takes the entry record's load fields."""
    if owner is not None:
        rec.loading, rec.scope, rec.globs, rec.agent = owner.loading, owner.scope, owner.globs, owner.agent


def _has_file(folder: Path, name: str) -> bool:
    """Whether `folder` lists a non-directory entry called `name`."""
    from reporails_cli.core.discovery.walk import list_dir

    listed = list_dir(str(folder))
    return any(e.name == name and not e.is_dir for e in listed or ())


def skill_membership(
    ruleset_map: Any, root: Path | None = None, registry: dict[str, dict[str, Any]] | None = None
) -> dict[str, str] | None:
    """`FileRecord.path` -> its recorded skill folder, for every record in a skill; None without a map.

    With a project `root`, each slot folder (see `skill_slot_folders`) also maps to itself."""
    if ruleset_map is None:
        return None
    members = {rec.path: rec.skill for rec in getattr(ruleset_map, "files", ()) if rec.skill}
    if root is not None:
        members.update({slot.as_posix(): slot.as_posix() for slot in skill_slot_folders(ruleset_map, root, registry)})
    return members


def skill_slot_folders(ruleset_map: Any, root: Path, registry: dict[str, dict[str, Any]] | None = None) -> set[Path]:
    """Direct subfolders of a one-level skills root that are not a recorded skill folder: the slots
    a skill should fill but does not. A root is the parent of a recorded skill folder whose entry file matches an
    entry pattern of its agent or the core agent that names no `**` below the skills folder."""
    from reporails_cli.core.mapper.inspect import _load_registry

    reg = _load_registry() if registry is None else registry
    core = [a for a, cfg in reg.items() if cfg.get("core")]
    entries = [
        (Path(rec.path), [p for a in (rec.agent, *core) for p in _entry_patterns(reg, a)])
        for rec in getattr(ruleset_map, "files", ())
        if rec.skill and Path(rec.path).name == "SKILL.md" and Path(rec.path).parent == Path(rec.skill)
    ]
    slots: set[Path] = set()
    filled = {Path(rec.skill) for rec in getattr(ruleset_map, "files", ()) if rec.skill}
    for skills_root in skills_roots(entries, root):
        slots.update(set(slot_subfolders(skills_root)) - filled)
    return slots


def slot_subfolders(skills_root: Path) -> list[Path]:
    """The non-hidden subfolders directly in `skills_root`, sorted."""
    from reporails_cli.core.discovery.walk import list_dir

    return sorted(Path(e.path) for e in list_dir(str(skills_root)) or () if e.is_dir and not e.name.startswith("."))


def _one_level(pattern: str) -> bool:
    """Whether an entry pattern names no `**` below the skills folder: a skill sits one level deep."""
    return "**" not in pattern.removeprefix("**/")


def skill_entry_paths(classified_files: Iterable[Any]) -> set[Path] | None:
    """Resolved paths of the classified files that are a skill's entry file (the file sits directly
    in the skill folder its `skill` property records); None when no classified file records a skill."""
    from reporails_cli.core.discovery.walk import safe_resolve

    entries: set[Path] = set()
    recorded = False
    for cf in classified_files:
        if not isinstance(cf.properties.get("skill"), str):
            continue
        recorded = True
        if skill_entry_folder(cf) is not None:
            entries.add(safe_resolve(cf.path))
    return entries if recorded else None


def skills_roots(entries: Iterable[tuple[Path, list[str]]], root: Path) -> set[Path]:
    """Folders whose every direct subfolder is meant to be a skill: the parent of each skill folder
    whose entry file (path, entry patterns) matches an entry pattern that names no `**` below the
    skills folder (an any-depth pattern lets a subfolder be a category holding skills, so it has no such root)."""
    roots: set[Path] = set()
    for path, patterns in entries:
        hit = entry_pattern(path, root, patterns)
        if hit is not None and _one_level(hit):
            roots.add(path.parent.parent)
    return roots


def one_level_skills_roots(classified_files: Iterable[Any], root: Path) -> set[Path]:
    """`skills_roots` of the classified skill entry files and their `skill_entry_patterns`."""
    return skills_roots(
        (
            (Path(cf.path), cf.properties["skill_entry_patterns"])
            for cf in classified_files
            if skill_entry_folder(cf) is not None and isinstance(cf.properties.get("skill_entry_patterns"), list)
        ),
        root,
    )
