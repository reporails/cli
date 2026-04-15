"""Config loading — agent, global, and project configuration.

Split from bootstrap.py to separate config loading (YAML → dataclass)
from path resolution (filesystem layout knowledge).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from reporails_cli.core.utils import load_yaml_file

if TYPE_CHECKING:
    from reporails_cli.core.models import AgentConfig, GlobalConfig, ProjectConfig

logger = logging.getLogger(__name__)


def get_agent_config(agent: str) -> AgentConfig:
    """Load agent config (excludes + overrides) from framework.

    Args:
        agent: Agent identifier (e.g., "claude")

    Returns:
        AgentConfig with excludes and overrides, or defaults if missing/malformed
    """
    from reporails_cli.core.bootstrap import get_agent_config_path
    from reporails_cli.core.models import AgentConfig

    config_path = get_agent_config_path(agent)
    if not config_path.exists():
        return AgentConfig()

    try:
        data = load_yaml_file(config_path)
        if not data:
            msg = f"Agent config is empty: {config_path}"
            raise ValueError(msg)
        return AgentConfig(
            agent=data.get("agent", ""),
            prefix=data.get("prefix", ""),
            name=data.get("name", ""),
            core=data.get("core", False),
            excludes=data.get("excludes", []),
            overrides=data.get("overrides", {}),
        )
    except (yaml.YAMLError, OSError, ValueError) as exc:
        logger.warning("Failed to parse agent config %s: %s", config_path, exc)
        return AgentConfig()


def get_global_config() -> GlobalConfig:
    """Load global configuration from ~/.reporails/config.yml.

    Returns default config if file doesn't exist.
    """
    from reporails_cli.core.bootstrap import get_global_config_path
    from reporails_cli.core.models import GlobalConfig

    config_path = get_global_config_path()
    if not config_path.exists():
        return GlobalConfig()

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        framework_path = data.get("framework_path")
        recommended_path = data.get("recommended_path")
        return GlobalConfig(
            framework_path=Path(framework_path) if framework_path else None,
            recommended_path=Path(recommended_path) if recommended_path else None,
            auto_update_check=data.get("auto_update_check", True),
            default_agent=data.get("default_agent", ""),
            recommended=data.get("recommended", True),
            tier=data.get("tier", ""),
        )
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse global config %s: %s", config_path, exc)
        return GlobalConfig()


def get_project_config(project_root: Path) -> ProjectConfig:
    """Load project configuration from .ails/config.yml.

    Returns default config if file doesn't exist or is malformed.

    Args:
        project_root: Root directory of the project

    Returns:
        ProjectConfig with loaded or default values
    """
    from reporails_cli.core.models import ProjectConfig

    config_path = project_root / ".ails" / "config.yml"
    if not config_path.exists():
        global_cfg = get_global_config()
        return ProjectConfig(
            default_agent=global_cfg.default_agent,
            recommended=global_cfg.recommended,
        )

    try:
        data = load_yaml_file(config_path)
        if not data:
            msg = f"Project config is empty: {config_path}"
            raise ValueError(msg)
        has_recommended = "recommended" in data
        config = ProjectConfig(
            framework_version=data.get("framework_version"),
            packages=data.get("packages", []),
            disabled_rules=data.get("disabled_rules", []),
            overrides=data.get("overrides", {}),
            recommended=data.get("recommended", True),
            exclude_dirs=data.get("exclude_dirs", []),
            default_agent=data.get("default_agent", ""),
        )
        # Apply global defaults where project doesn't override
        global_cfg = get_global_config()
        if not config.default_agent:
            config.default_agent = global_cfg.default_agent
        if not has_recommended:
            config.recommended = global_cfg.recommended
        return config
    except (yaml.YAMLError, OSError, ValueError) as exc:
        logger.warning("Failed to parse project config %s: %s", config_path, exc)
        global_cfg = get_global_config()
        return ProjectConfig(
            default_agent=global_cfg.default_agent,
            recommended=global_cfg.recommended,
        )
