"""Plain records of file discovery: agent definitions, detected agents, the exclusion set of a run, read-gate
results, memory entries and directory listings."""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Literal, NamedTuple

from reporails_cli.core.platform.dto.exclusion import FolderValue
from reporails_cli.core.platform.dto.hooks import HookConfig
from reporails_cli.core.platform.dto.results import ProjectConfig

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        # VCS
        ".git",
        ".svn",
        ".hg",
        # Python
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        # JS/TS
        "node_modules",
        # Build output
        "dist",
        "build",
        "target",
        "out",
        # Data / artifacts (instruction files never live here)
        "data",
        "datasets",
        # Vendored
        "vendor",
        # IDE / OS
        ".idea",
        # `.vscode` is deliberately absent: Copilot declares real config/mcp
        # surfaces there (`.vscode/{settings,mcp}.json`), pre-filtered out otherwise.
    }
)

# How a file's text reaches the agent through another file: the same file under another
# name (`link`) or a separate file with exactly the same text (`copy`).
AliasHow = Literal["link", "copy"]

SkipReason = Literal["claude_md_present", "subdir_has_claude_md", "setting_off", "never_read"]


@dataclass(frozen=True)
class AgentType:
    """Definition of a coding agent's file conventions."""

    id: str
    name: str
    instruction_patterns: tuple[str, ...]  # Root-level marker patterns for fast detection
    config_patterns: tuple[str, ...]  # Glob patterns for config files
    rule_patterns: tuple[str, ...]  # Glob patterns for rule/snippet files
    directory_patterns: tuple[tuple[str, str], ...] = ()  # (label, dir_path) pairs
    core: bool = False  # the shared standard every other agent also reads (the default agent)
    home_dir: str = ""  # the dot-folder holding the agent's own files (`.claude`)
    shared_names: tuple[str, ...] = ()  # root file names several agents read; each points at no one agent


@dataclass
class DetectedAgent:
    """An agent detected in a project."""

    agent_type: AgentType
    instruction_files: list[Path] = field(default_factory=list)
    config_files: list[Path] = field(default_factory=list)
    rule_files: list[Path] = field(default_factory=list)
    detected_directories: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RunExclusions:
    """What a run leaves out.

    `dirs` and `files` are the user's folders and file globs (command line plus config).
    `prunes` is what directory walks ask: it adds the built-in defaults to the user's folders.
    `named` holds the resolved files the user named; they are never left out.
    `roots` is the root as given and, when different, resolved.
    """

    root: Path
    roots: tuple[Path, ...]
    dirs: tuple[FolderValue, ...] = ()
    files: tuple[str, ...] = ()
    named: frozenset[Path] = frozenset()

    @cached_property
    def prefixes(self) -> tuple[str, ...]:
        """The root as given and resolved, each as a string ending in a separator."""
        return tuple(dict.fromkeys(os.fspath(root).rstrip(os.sep) + os.sep for root in self.roots))

    @cached_property
    def named_homes(self) -> frozenset[str]:
        """Every named file and every folder above one."""
        return frozenset(str(item) for path in self.named for item in (path, *path.parents))

    def views(self, path: str, real: str) -> tuple[str, ...]:
        """The root-relative posix forms of `path` (as given) and `real` (canonical) that a folder rule is tested on.

        Each is tried against the root as given and resolved. A form outside both roots, and the
        root itself, give nothing.
        """
        views: dict[str, None] = {}
        for form in (path,) if real == path else (path, real):
            for prefix in self.prefixes:
                if form.startswith(prefix) and len(form) > len(prefix):
                    rel = form[len(prefix) :]
                    views[rel if os.sep == "/" else rel.replace(os.sep, "/")] = None
        return tuple(views)

    @staticmethod
    def folder_hit(views: tuple[str, ...], dirs: tuple[FolderValue, ...]) -> bool:
        """True when a folder rule in `dirs` leaves out any of the root-relative `views`."""
        return any(d.holds(view) for d in dirs for view in views)

    @staticmethod
    def default_pruned(name: str) -> bool:
        """True when the listed folder `name` is a built-in default."""
        return name in DEFAULT_EXCLUDE_DIRS

    def user_pruned(self, path: str, real: str) -> bool:
        """True when a user folder rule holds the folder `path` (canonical `real`) and it holds no named file."""
        if not self.dirs or not self.folder_hit(self.views(path, real), self.dirs):
            return False
        return not (self.named and (path in self.named_homes or real in self.named_homes))

    def prunes(self, path: str, name: str, real: str) -> bool:
        """True when a walk skips the listed folder `path` named `name` (`real` is its canonical path).

        The built-in defaults are skipped by name. A folder the user left out is skipped too, unless
        it holds a file the user named.
        """
        return self.default_pruned(name) or self.user_pruned(path, real)


@dataclass(frozen=True)
class OwnAccountOnly:
    """A pruner that also skips the synced-skills folder of every account but the signed-in one, so a walk of the
    user's skills folder never lists another account's files. `account` is the signed-in account's folder name,
    None when no account is signed in."""

    inner: RunExclusions
    account: str | None

    def prunes(self, path: str, name: str, real: str) -> bool:
        """True when `inner` prunes the folder, or it is another account's folder under `skills/synced/`."""
        if self.inner.prunes(path, name, real):
            return True
        return Path(path).parts[-2:] == ("skills", "synced") and name != self.account


@dataclass
class AgentScope:
    """What one agent's discovery run shares across its file types."""

    target: Path
    agent_id: str
    project_config: ProjectConfig | None
    exclusions: RunExclusions
    repo_scoped: bool
    user_dir: Path | None
    exclude_globs: list[str]
    plugin_roots: dict[str, list[Path]] = field(default_factory=dict)
    installed_plugins: Sequence[Path] = ()


@dataclass
class SurfaceScan:
    """What one feature detection shares: the project's excluded folders and the plugin
    roots already found, so each plugin marker is searched for once."""

    exclusions: RunExclusions
    roots_by_marker: dict[str, list[Path]] = field(default_factory=dict)
    hook_configs: dict[Path, HookConfig | None] = field(default_factory=dict)


@dataclass(frozen=True)
class MemoryEntry:
    """One enumerable memory record per agent's memory locator.

    `path` is the file holding the entry (always a real Path). `body` is
    the entry text: the file content.
    """

    agent: str
    path: Path
    body: str


@dataclass(frozen=True)
class SkippedFile:
    """An `AGENTS.md` Claude Code does not read, and why; `cause` is the `CLAUDE.md`-family file that made
    it skip the file (`claude_md_present`, `subdir_has_claude_md`), None for the other reasons."""

    path: Path
    reason: SkipReason
    cause: Path | None


@dataclass(frozen=True)
class AliasFile:
    """An `AGENTS.md` whose text reaches Claude through a `CLAUDE.md` it reads: `link` when it is the
    same file under another name, `copy` when it is a separate file with exactly the same text."""

    path: Path
    same_as: Path
    how: AliasHow


@dataclass(frozen=True)
class AgentsMdReads:
    """The `AGENTS.md` files Claude Code loads, the ones it skips, the ones that are a `CLAUDE.md`
    it reads under another name, and the setting that decided."""

    kept: list[Path]
    skipped: list[SkippedFile]
    mode: str
    aliases: list[AliasFile]


class ListedEntry(NamedTuple):
    """One directory entry, resolved once: name, path, whether it resolves to a regular file
    or to a directory (symlinks followed), and whether it is itself a symlink."""

    name: str
    path: str
    is_file: bool
    is_dir: bool
    is_symlink: bool
