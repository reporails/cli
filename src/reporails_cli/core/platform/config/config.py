"""Config loading — agent, global, and project configuration.

Split from bootstrap.py to separate config loading (YAML → dataclass)
from path resolution (filesystem layout knowledge).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from reporails_cli.core.platform.utils.utils import load_yaml_file

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.models import AgentConfig, GlobalConfig, ProjectConfig

logger = logging.getLogger(__name__)


def get_agent_config(agent: str) -> AgentConfig:
    """Load agent config (excludes + overrides) from framework.

    Args:
        agent: Agent identifier (e.g., "claude")

    Returns:
        AgentConfig with excludes and overrides, or defaults if missing/malformed
    """
    from reporails_cli.core.platform.config.bootstrap import get_agent_config_path
    from reporails_cli.core.platform.dto.models import AgentConfig

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
    from reporails_cli.core.platform.config.bootstrap import get_global_config_path
    from reporails_cli.core.platform.dto.models import GlobalConfig

    config_path = get_global_config_path()
    if not config_path.exists():
        return GlobalConfig()

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        framework_path = data.get("framework_path")
        return GlobalConfig(
            framework_path=Path(framework_path) if framework_path else None,
            auto_update_check=data.get("auto_update_check", True),
            default_agent=data.get("default_agent", ""),
            tier=data.get("tier", ""),
        )
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse global config %s: %s", config_path, exc)
        return GlobalConfig()


def _deep_merge_config(base: dict[str, object], overlay: dict[str, object]) -> dict[str, object]:
    """Deep-merge `overlay` onto `base` for project config layering.

    Object keys merge recursively. Array keys extend (overlay appended after
    base). Scalar keys are replaced by overlay. Used to layer
    `.ails/config.local.yml` on top of `.ails/config.yml`.
    """
    if not overlay:
        return base
    if not base:
        return dict(overlay)
    merged: dict[str, object] = dict(base)
    for key, ov in overlay.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(ov, dict):
            merged[key] = _deep_merge_config(existing, ov)
        elif isinstance(existing, list) and isinstance(ov, list):
            merged[key] = list(existing) + [v for v in ov if v not in existing]
        else:
            merged[key] = ov
    return merged


def _load_yaml_dict(config_path: Path) -> dict[str, object] | None:
    """Read a YAML file and return its top-level dict, or None on error/missing."""
    if not config_path.exists():
        return None
    try:
        data = load_yaml_file(config_path)
        if not data:
            return None
        if not isinstance(data, dict):
            logger.warning("Config file %s did not parse to a mapping", config_path)
            return None
        return data
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse project config %s: %s", config_path, exc)
        return None


def get_project_config(project_root: Path) -> ProjectConfig:
    """Load project configuration from .ails/config.yml + .ails/config.local.yml.

    `.ails/config.local.yml` (gitignored) layers on top of the committed
    `.ails/config.yml` for personal/CI-specific overrides.

    Returns default config if neither file exists or both are malformed.

    Args:
        project_root: Root directory of the project

    Returns:
        ProjectConfig with loaded or default values
    """
    from reporails_cli.core.platform.dto.models import ProjectConfig

    base = _load_yaml_dict(project_root / ".ails" / "config.yml") or {}
    local = _load_yaml_dict(project_root / ".ails" / "config.local.yml") or {}
    data = _deep_merge_config(base, local)

    if not data:
        global_cfg = get_global_config()
        return ProjectConfig(default_agent=global_cfg.default_agent)

    def _str_list(key: str) -> list[str]:
        val = data.get(key)
        return list(val) if isinstance(val, list) else []

    def _str_dict(key: str) -> dict[str, dict[str, object]]:
        val = data.get(key)
        return dict(val) if isinstance(val, dict) else {}

    fw = data.get("framework_version")
    fw_str = fw if isinstance(fw, str) else None
    da = data.get("default_agent", "")
    da_str = da if isinstance(da, str) else ""
    ovr = data.get("overrides", {})
    ovr_dict: dict[str, dict[str, str]] = ovr if isinstance(ovr, dict) else {}

    rt = data.get("rule_thresholds", {})
    rt_dict: dict[str, dict[str, int]] = {}
    if isinstance(rt, dict):
        for rule_id, args in rt.items():
            if isinstance(args, dict):
                rt_dict[str(rule_id)] = {str(k): int(v) for k, v in args.items() if isinstance(v, (int, float))}

    generic_scanning_raw = data.get("generic_scanning", False)
    generic_scanning = bool(generic_scanning_raw) if isinstance(generic_scanning_raw, bool) else False

    config = ProjectConfig(
        framework_version=fw_str,
        packages=_str_list("packages"),
        disabled_rules=_str_list("disabled_rules"),
        overrides=ovr_dict,
        exclude_dirs=_str_list("exclude_dirs"),
        default_agent=da_str,
        agents=_str_dict("agents"),
        surfaces=_str_dict("surfaces"),
        rule_thresholds=rt_dict,
        generic_scanning=generic_scanning,
    )
    # Apply global defaults where project doesn't override
    global_cfg = get_global_config()
    if not config.default_agent:
        config.default_agent = global_cfg.default_agent
    return config
