"""Path helpers and config loading for reporails home directory."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from reporails_cli.core.models import AgentConfig, GlobalConfig, ProjectConfig

# Constants
REPORAILS_HOME = Path.home() / ".reporails"
FRAMEWORK_REPO = "reporails/reporails-rules"
FRAMEWORK_RELEASE_URL = f"https://github.com/{FRAMEWORK_REPO}/releases/download"


def get_reporails_home() -> Path:
    """Get ~/.reporails directory."""
    return REPORAILS_HOME


def get_opengrep_bin() -> Path:
    """Get path to OpenGrep binary."""
    home = get_reporails_home()
    if platform.system().lower() == "windows":
        return home / "bin" / "opengrep.exe"
    return home / "bin" / "opengrep"


def get_rules_path() -> Path:
    """Get path to rules directory.

    Prefers local ./checks/ directory if it has .yml files (development mode),
    otherwise uses ~/.reporails/rules/ (installed mode).
    """
    # Check for local checks directory (development mode)
    local_checks = Path.cwd() / "checks"
    if local_checks.exists() and any(local_checks.rglob("*.yml")):
        return local_checks

    # Fall back to global directory
    return get_reporails_home() / "rules"


def get_core_rules_path() -> Path:
    """Get path to core rules directory (~/.reporails/rules/core/)."""
    return get_rules_path() / "core"


def get_agent_rules_path(agent: str) -> Path:
    """Get path to agent-specific rules (~/.reporails/rules/agents/{agent}/rules/)."""
    return get_rules_path() / "agents" / agent / "rules"


def get_agent_config_path(agent: str) -> Path:
    """Get path to agent config file (~/.reporails/rules/agents/{agent}/config.yml)."""
    return get_rules_path() / "agents" / agent / "config.yml"


def get_agent_config(agent: str) -> AgentConfig:
    """Load agent config (excludes + overrides) from framework.

    Args:
        agent: Agent identifier (e.g., "claude")

    Returns:
        AgentConfig with excludes and overrides, or defaults if missing/malformed
    """
    from reporails_cli.core.models import AgentConfig

    config_path = get_agent_config_path(agent)
    if not config_path.exists():
        return AgentConfig()

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        return AgentConfig(
            agent=data.get("agent", ""),
            excludes=data.get("excludes", []),
            overrides=data.get("overrides", {}),
        )
    except (yaml.YAMLError, OSError):
        return AgentConfig()


def get_agent_vars(
    agent: str = "claude",
    rules_paths: list[Path] | None = None,
) -> dict[str, str | list[str]]:
    """Load template variables from agent config.

    Args:
        agent: Agent identifier (default: claude)
        rules_paths: Optional rules directories to search first (before default path)

    Returns:
        Dict of template variables from the agent's config.yml vars section
    """
    # Build candidate config paths: explicit rules_paths first, then default
    candidates: list[Path] = []
    if rules_paths:
        candidates.extend(rules_dir / "agents" / agent / "config.yml" for rules_dir in rules_paths)
    candidates.append(get_agent_config_path(agent))

    for config_path in candidates:
        if not config_path.exists():
            continue
        try:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            vars_data = data.get("vars", {})
            # Ensure all values are str or list[str]
            result: dict[str, str | list[str]] = {}
            for key, value in vars_data.items():
                if isinstance(value, list):
                    result[key] = [str(v) for v in value]
                else:
                    result[key] = str(value)
            return result
        except (yaml.YAMLError, OSError):
            continue
    return {}


def get_schemas_path() -> Path:
    """Get path to rule schemas (~/.reporails/rules/schemas/)."""
    return get_rules_path() / "schemas"


def get_global_packages_path() -> Path:
    """Get path to global packages directory (~/.reporails/packages/)."""
    return get_reporails_home() / "packages"


def get_recommended_package_path() -> Path:
    """Get path to recommended package (~/.reporails/packages/recommended/)."""
    return get_global_packages_path() / "recommended"


def get_version_file() -> Path:
    """Get path to version file (~/.reporails/version)."""
    return get_reporails_home() / "version"


def get_global_config_path() -> Path:
    """Get path to global config file (~/.reporails/config.yml)."""
    return get_reporails_home() / "config.yml"


def get_global_config() -> GlobalConfig:
    """Load global configuration from ~/.reporails/config.yml.

    Returns default config if file doesn't exist.
    """
    from reporails_cli.core.models import GlobalConfig

    config_path = get_global_config_path()
    if not config_path.exists():
        return GlobalConfig()

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        framework_path = data.get("framework_path")
        return GlobalConfig(
            framework_path=Path(framework_path) if framework_path else None,
            auto_update_check=data.get("auto_update_check", True),
        )
    except (yaml.YAMLError, OSError):
        return GlobalConfig()


def get_project_config(project_root: Path) -> ProjectConfig:
    """Load project configuration from .reporails/config.yml.

    Returns default config if file doesn't exist or is malformed.

    Args:
        project_root: Root directory of the project

    Returns:
        ProjectConfig with loaded or default values
    """
    from reporails_cli.core.models import ProjectConfig

    config_path = project_root / ".reporails" / "config.yml"
    if not config_path.exists():
        return ProjectConfig()

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        return ProjectConfig(
            framework_version=data.get("framework_version"),
            packages=data.get("packages", []),
            disabled_rules=data.get("disabled_rules", []),
            overrides=data.get("overrides", {}),
            experimental=data.get("experimental", False),
            recommended=data.get("recommended", True),
            exclude_dirs=data.get("exclude_dirs", []),
        )
    except (yaml.YAMLError, OSError):
        return ProjectConfig()


def get_package_paths(project_root: Path, packages: list[str]) -> list[Path]:
    """Resolve package names to directories.

    Checks project-local (.reporails/packages/<name>) first, then falls back
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
        local_dir = project_root / ".reporails" / "packages" / name
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
    """Check if reporails has been initialized (opengrep + rules)."""
    return get_opengrep_bin().exists() and get_rules_path().exists()


# Legacy alias for backward compatibility
def get_checks_path() -> Path:
    """Legacy alias for get_rules_path()."""
    return get_rules_path()
