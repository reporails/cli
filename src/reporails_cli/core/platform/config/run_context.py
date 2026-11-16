"""The run's read-once memo of what it reads from the user's and the project's config."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.platform.config.bootstrap import (
    get_global_config_path,
    get_local_config_path,
    get_project_config_path,
)
from reporails_cli.core.platform.config.config import get_global_config, get_project_config, read_config_file
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.discovery import DetectedAgent
from reporails_cli.core.platform.dto.results import ConfiguredRoot, GlobalConfig, ProjectConfig


class RunContext:
    """What one run reads from the user's and the project's config, read at most once each.

    The entry point builds one per run and drops it when the run ends, so a new run reads the
    project as it is now. Building one does no I/O.
    """

    def __init__(self) -> None:
        self._global: GlobalConfig | None = None
        self._projects: dict[Path, ProjectConfig] = {}
        self.agents: dict[Path, list[DetectedAgent]] = {}
        self.aliases: dict[Path, dict[Path, list[Path]]] = {}
        self.memory_links: dict[tuple[str, int], frozenset[str]] = {}
        self._documents: dict[Path, tuple[tuple[Path, JsonObject], ...]] = {}

    def global_config(self) -> GlobalConfig:
        """The user's global config, read on first use."""
        if self._global is None:
            self._global = get_global_config()
        return self._global

    def project_config(self, root: Path) -> ProjectConfig:
        """The merged project config of `root`, read on first use per root as spelled."""
        config = self._projects.get(root)
        if config is None:
            config = get_project_config(root)
            self._projects[root] = config
        return config

    def configured_root(self, root: Path) -> ConfiguredRoot:
        """`root` with its project config, read on first use."""
        return ConfiguredRoot(root, self.project_config(root))

    def config_documents(self, root: Path) -> tuple[tuple[Path, JsonObject], ...]:
        """The project, local and global config files of `root` as `read_config_file` reads them, read on
        first use per root. Raises `ConfigUnreadableError` for a file that cannot be read."""
        documents = self._documents.get(root)
        if documents is None:
            paths = (get_project_config_path(root), get_local_config_path(root), get_global_config_path())
            documents = tuple((path, read_config_file(path)) for path in paths)
            self._documents[root] = documents
        return documents
