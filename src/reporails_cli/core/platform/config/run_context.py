"""The run's read-once memo of what it reads from the user's and the project's config."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.platform.config.config import get_global_config, get_project_config
from reporails_cli.core.platform.dto.discovery import DetectedAgent
from reporails_cli.core.platform.dto.results import GlobalConfig, ProjectConfig


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

    def global_config(self) -> GlobalConfig:
        """The user's global config, read on first use."""
        if self._global is None:
            self._global = get_global_config()
        return self._global

    def project_config(self, root: Path) -> ProjectConfig:
        """The merged project config of `root`, read on first use per root."""
        key = root.resolve()
        config = self._projects.get(key)
        if config is None:
            config = get_project_config(root)
            self._projects[key] = config
        return config
