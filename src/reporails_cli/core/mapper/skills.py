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


def _matches_entry_pattern(path: Path, root: Path, patterns: list[str]) -> bool:
    """Whether `path` matches any of `patterns`, anchored the way file-type `patterns` are
    (a plugin-scope pattern from the plugin root, any other from `root`)."""
    from reporails_cli.core.discovery.plugin_roots import matches_plugin_pattern
    from reporails_cli.core.mapper.inspect import _pattern_matches

    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    for pattern in patterns:
        plugin_hit = matches_plugin_pattern(path, root, pattern, _pattern_matches)
        if plugin_hit if plugin_hit is not None else _pattern_matches(rel, pattern):
            return True
    return False


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
        if folder is None:
            if rec.type == "skills":
                rec.type = "generic"
            continue
        rec.skill = str(folder)
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
        return any(_matches_entry_pattern(path, self.root, self._patterns[a]) for a in (*self.base, agent))

    def is_skill(self, folder: Path, agent: str) -> bool:
        """Whether `folder/SKILL.md` is a skill's entry file: the map's own verdict when it carries
        that record, else a match on the agents' entry patterns plus the file existing on disk."""
        candidate = folder / "SKILL.md"
        if str(candidate) in self.by_path:
            return folder in self.entries
        key = (folder, agent)
        if key not in self._on_disk:
            self._on_disk[key] = self._matches(candidate, agent) and _has_file(folder, "SKILL.md")
        return self._on_disk[key]


def _join_skill(rec: Any, owner: Any | None) -> None:
    """Type `rec` `skills`; a record that was not yet one takes the entry record's load fields."""
    if rec.type == "skills":
        return
    rec.type = "skills"
    if owner is not None:
        rec.loading, rec.scope, rec.globs, rec.agent = owner.loading, owner.scope, owner.globs, owner.agent


def _has_file(folder: Path, name: str) -> bool:
    """Whether `folder` lists a non-directory entry called `name`."""
    from reporails_cli.core.discovery.walk import list_dir

    listed = list_dir(str(folder))
    return any(e.name == name and not e.is_dir for e in listed or ())


def skill_membership(ruleset_map: Any) -> dict[str, str] | None:
    """`FileRecord.path` -> its recorded skill folder, for every record in a skill; None without a map."""
    if ruleset_map is None:
        return None
    return {rec.path: rec.skill for rec in getattr(ruleset_map, "files", ()) if rec.skill}


def skill_entry_paths(classified_files: Iterable[Any]) -> set[Path] | None:
    """Resolved paths of the classified files that are a skill's entry file (the file sits directly
    in the skill folder its `skill` property records); None when no classified file records a skill."""
    from reporails_cli.core.discovery.walk import safe_resolve

    entries: set[Path] = set()
    recorded = False
    for cf in classified_files:
        folder = cf.properties.get("skill")
        if not isinstance(folder, str):
            continue
        recorded = True
        if str(Path(cf.path).parent) == folder:
            entries.add(safe_resolve(cf.path))
    return entries if recorded else None
