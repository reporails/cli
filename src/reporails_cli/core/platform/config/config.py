"""Config loading — agent, global, and project configuration.

Split from bootstrap.py to separate config loading (YAML → dataclass)
from path resolution (filesystem layout knowledge).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

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


def _data_str_list(data: dict[str, object], key: str) -> list[str]:
    """Coerce `data[key]` to a list of strings, or empty when absent / wrong shape."""
    val = data.get(key)
    return list(val) if isinstance(val, list) else []


def _data_str_dict(data: dict[str, object], key: str) -> dict[str, dict[str, object]]:
    """Coerce `data[key]` to a `dict[str, dict]`, or empty when absent / wrong shape."""
    val = data.get(key)
    return dict(val) if isinstance(val, dict) else {}


def _coerce_rule_thresholds(raw: object) -> dict[str, dict[str, int]]:
    """Coerce `rule_thresholds` raw YAML data to `{rule_id: {arg: int}}`."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, int]] = {}
    for rule_id, args in raw.items():
        if isinstance(args, dict):
            out[str(rule_id)] = {str(k): int(v) for k, v in args.items() if isinstance(v, (int, float))}
    return out


def get_global_config() -> GlobalConfig:
    """Load global configuration from `~/.reporails/config.yml`.

    Returns default config if the file doesn't exist. Reads every field
    that mirrors `ProjectConfig` so `get_project_config` can merge globals
    under per-project settings (list fields extend; dict fields deep-merge
    under the project layer). `generic_scanning` parses as `None` when
    absent — `None` signals "no global preference" so the project layer
    can keep its default semantics.
    """
    from reporails_cli.core.platform.config.bootstrap import get_global_config_path
    from reporails_cli.core.platform.dto.models import GlobalConfig

    config_path = get_global_config_path()
    if not config_path.exists():
        return GlobalConfig()

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        data: dict[str, object] = raw if isinstance(raw, dict) else {}
        framework_path = data.get("framework_path")
        gs_raw = data.get("generic_scanning")
        generic_scanning = bool(gs_raw) if isinstance(gs_raw, bool) else None
        overrides_raw = data.get("overrides", {})
        overrides: dict[str, dict[str, str]] = overrides_raw if isinstance(overrides_raw, dict) else {}
        return GlobalConfig(
            framework_path=Path(framework_path) if isinstance(framework_path, str) else None,
            auto_update_check=bool(data.get("auto_update_check", True)),
            default_agent=str(data.get("default_agent", "")) if isinstance(data.get("default_agent"), str) else "",
            tier=str(data.get("tier", "")) if isinstance(data.get("tier"), str) else "",
            disabled_rules=_data_str_list(data, "disabled_rules"),
            exclude_dirs=_data_str_list(data, "exclude_dirs"),
            overrides=overrides,
            rule_thresholds=_coerce_rule_thresholds(data.get("rule_thresholds")),
            generic_scanning=generic_scanning,
            packages=_data_str_list(data, "packages"),
            agents=_data_str_dict(data, "agents"),
            surfaces=_data_str_dict(data, "surfaces"),
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
    """Load project configuration from `.ails/config.yml` + `.ails/config.local.yml`.

    `.ails/config.local.yml` (gitignored) layers on top of the committed
    `.ails/config.yml` for personal / CI-specific overrides.

    Global defaults from `~/.reporails/config.yml` then merge under the
    project layer: list fields (`disabled_rules`, `exclude_dirs`,
    `packages`) extend with global entries the project didn't already
    declare; dict fields (`overrides`, `rule_thresholds`, `agents`,
    `surfaces`) deep-merge under project values; `default_agent` and
    `generic_scanning` use the project value when set, otherwise inherit
    from the global layer.

    Returns default config if neither file exists or both are malformed,
    still applying global defaults.

    Args:
        project_root: Root directory of the project

    Returns:
        ProjectConfig with loaded or default values, layered with globals.
    """
    from reporails_cli.core.platform.dto.models import ProjectConfig

    base = _load_yaml_dict(project_root / ".ails" / "config.yml") or {}
    local = _load_yaml_dict(project_root / ".ails" / "config.local.yml") or {}
    data = _deep_merge_config(base, local)
    global_cfg = get_global_config()

    if not data:
        return _apply_globals(ProjectConfig(), global_cfg)

    fw = data.get("framework_version")
    da = data.get("default_agent", "")
    ovr = data.get("overrides", {})
    gs_raw = data.get("generic_scanning")
    has_gs_in_project = isinstance(gs_raw, bool)

    config = ProjectConfig(
        framework_version=fw if isinstance(fw, str) else None,
        packages=_data_str_list(data, "packages"),
        disabled_rules=_data_str_list(data, "disabled_rules"),
        overrides=ovr if isinstance(ovr, dict) else {},
        exclude_dirs=_data_str_list(data, "exclude_dirs"),
        default_agent=da if isinstance(da, str) else "",
        agents=_data_str_dict(data, "agents"),
        surfaces=_data_str_dict(data, "surfaces"),
        rule_thresholds=_coerce_rule_thresholds(data.get("rule_thresholds")),
        generic_scanning=bool(gs_raw) if has_gs_in_project else False,
    )
    return _apply_globals(config, global_cfg, has_project_generic_scanning=has_gs_in_project)


def _apply_globals(
    config: ProjectConfig,
    global_cfg: GlobalConfig,
    has_project_generic_scanning: bool = False,
) -> ProjectConfig:
    """Layer `~/.reporails/config.yml` defaults under per-project values.

    Project values win on conflict. List fields extend with global entries
    the project didn't already declare. Dict fields deep-merge under the
    project layer. `generic_scanning` inherits from globals only when the
    project YAML didn't explicitly set it.
    """
    if not config.default_agent:
        config.default_agent = global_cfg.default_agent
    config.disabled_rules = _extend_unique(config.disabled_rules, global_cfg.disabled_rules)
    config.exclude_dirs = _extend_unique(config.exclude_dirs, global_cfg.exclude_dirs)
    config.packages = _extend_unique(config.packages, global_cfg.packages)
    config.overrides = _merge_under(config.overrides, global_cfg.overrides)
    config.rule_thresholds = _merge_under(config.rule_thresholds, global_cfg.rule_thresholds)
    config.agents = _merge_under(config.agents, global_cfg.agents)
    config.surfaces = _merge_under(config.surfaces, global_cfg.surfaces)
    if not has_project_generic_scanning and global_cfg.generic_scanning is not None:
        config.generic_scanning = global_cfg.generic_scanning
    return config


def _extend_unique(project: list[str], globals_: list[str]) -> list[str]:
    """Append globals entries not already present in the project list."""
    if not globals_:
        return project
    seen = set(project)
    out = list(project)
    for entry in globals_:
        if entry not in seen:
            out.append(entry)
            seen.add(entry)
    return out


def _merge_under(project: dict[str, Any], globals_: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge `globals_` UNDER `project` — project wins on conflicting keys."""
    if not globals_:
        return project
    if not project:
        return dict(globals_)
    merged: dict[str, Any] = dict(globals_)
    for key, project_val in project.items():
        global_val = merged.get(key)
        if isinstance(project_val, dict) and isinstance(global_val, dict):
            merged[key] = _merge_under(project_val, global_val)
        else:
            merged[key] = project_val
    return merged
