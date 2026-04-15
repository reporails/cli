"""Path helpers and config loading for reporails home directory."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.bundled import get_bundled_package_root, get_bundled_rules_path

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from reporails_cli.core.models import AgentConfig, FileTypeDeclaration, GlobalConfig, ProjectConfig

# Constants
REPORAILS_HOME = Path.home() / ".reporails"


def get_reporails_home() -> Path:
    """Get ~/.reporails directory."""
    return REPORAILS_HOME


def get_rules_path() -> Path:
    """Get path to rules directory.

    Resolution: config override → bundled (package default).
    """
    config = get_global_config()
    if config.framework_path and config.framework_path.is_dir():
        rules_sub = config.framework_path / "rules"
        if rules_sub.is_dir():
            return rules_sub
        return config.framework_path

    bundled = get_bundled_rules_path()
    if bundled is not None:
        return bundled

    # Unreachable when installed correctly, but return a sane default
    return get_reporails_home() / "rules"


def get_framework_root() -> Path:
    """Get the root where schemas/, registry/, sources.yml live.

    Resolution: config override → bundled package root.
    """
    config = get_global_config()
    if config.framework_path and config.framework_path.is_dir():
        return config.framework_path

    bundled_root = get_bundled_package_root()
    if bundled_root is not None:
        return bundled_root

    return get_reporails_home() / "rules"


def get_core_rules_path() -> Path:
    """Get path to core rules directory (~/.reporails/rules/core/)."""
    return get_rules_path() / "core"


def get_agent_rules_path(agent: str) -> Path:
    """Get path to agent-specific rules (~/.reporails/rules/{agent}/)."""
    return get_rules_path() / agent


def get_agent_config_path(agent: str) -> Path:
    """Get path to agent config file.

    The generic agent's config lives in core/ (not a separate directory).
    """
    dir_name = "core" if agent == "generic" else agent
    return get_rules_path() / dir_name / "config.yml"


def get_agent_config(agent: str) -> AgentConfig:
    """Load agent config (excludes + overrides) from framework.

    Delegated to core.config. Re-exported here for backward compatibility.
    """
    from reporails_cli.core.config import get_agent_config as _get_agent_config

    return _get_agent_config(agent)


def get_agent_file_types(
    agent: str = "claude",
    rules_paths: list[Path] | None = None,
) -> list[FileTypeDeclaration]:
    """Load file type declarations from agent config.

    Args:
        agent: Agent identifier (default: claude)
        rules_paths: Optional rules directories to search first

    Returns:
        List of FileTypeDeclaration from the agent's config.yml file_types section
    """
    from reporails_cli.core.classification import load_file_types

    return load_file_types(agent, rules_paths)


def get_schemas_path() -> Path:
    """Get path to rule schemas (schemas/ under framework root)."""
    return get_framework_root() / "schemas"


def get_global_packages_path() -> Path:
    """Get path to global packages directory (~/.reporails/packages/)."""
    return get_reporails_home() / "packages"


def get_recommended_package_path() -> Path:
    """Get path to recommended package.

    Returns local override from global config if set, otherwise
    ~/.reporails/packages/recommended/.
    """
    config = get_global_config()
    if config.recommended_path and config.recommended_path.is_dir():
        return config.recommended_path
    return get_global_packages_path() / "recommended"


def get_version_file() -> Path:
    """Get path to version file (~/.reporails/version)."""
    return get_reporails_home() / "version"


def get_global_config_path() -> Path:
    """Get path to global config file (~/.reporails/config.yml)."""
    return get_reporails_home() / "config.yml"


def get_global_config() -> GlobalConfig:
    """Load global configuration from ~/.reporails/config.yml.

    Delegated to core.config. Re-exported here for backward compatibility.
    """
    from reporails_cli.core.config import get_global_config as _get_global_config

    return _get_global_config()


def get_project_config(project_root: Path) -> ProjectConfig:
    """Load project configuration from .ails/config.yml.

    Delegated to core.config. Re-exported here for backward compatibility.
    """
    from reporails_cli.core.config import get_project_config as _get_project_config

    return _get_project_config(project_root)


def get_package_paths(project_root: Path, packages: list[str]) -> list[Path]:
    """Resolve package names to directories.

    Checks project-local (.ails/packages/<name>) first, then falls back
    to global (~/.reporails/packages/<name>). Project-local overrides global
    for the same package name. Silently skips packages not found in either.

    Args:
        project_root: Root directory of the project
        packages: List of package names

    Returns:
        List of existing package directory paths
    """
    global_base = get_global_packages_path()
    paths: list[Path] = []
    for name in packages:
        # Project-local takes priority
        local_dir = project_root / ".ails" / "packages" / name
        if local_dir.is_dir():
            paths.append(local_dir)
            continue
        # Fall back to global
        global_dir = global_base / name
        if global_dir.is_dir():
            paths.append(global_dir)
    return paths


def get_installed_version() -> str | None:
    """Read installed framework version from ~/.reporails/version."""
    version_file = get_version_file()
    if not version_file.exists():
        return None
    try:
        return version_file.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def get_installed_recommended_version() -> str | None:
    """Read installed recommended package version from ~/.reporails/packages/recommended/.version."""
    version_file = get_recommended_package_path() / ".version"
    if not version_file.exists():
        return None
    try:
        return version_file.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def is_initialized() -> bool:
    """Check if rules are available (installed, config override, or bundled)."""
    rules_path = get_rules_path()
    return rules_path.is_dir() and (rules_path / "core").is_dir()
