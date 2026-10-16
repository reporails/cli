"""Config loading — agent, global, and project configuration.

Split from bootstrap.py to separate config loading (YAML → dataclass)
from path resolution (filesystem layout knowledge).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import get_type_hints

import yaml

from reporails_cli.core.platform.config.bootstrap import (
    get_global_config_path,
    get_local_config_path,
    get_project_config_path,
    get_reporails_home,
)
from reporails_cli.core.platform.config.bundled import get_bundled_package_root, get_bundled_rules_path
from reporails_cli.core.platform.contract.errors import ConfigUnreadableError
from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    JsonValue,
    as_object,
    as_str,
    str_list,
)
from reporails_cli.core.platform.dto.results import (
    AgentConfig,
    GlobalConfig,
    HookFact,
    MapperConfig,
    ProjectConfig,
    SubagentHooks,
)
from reporails_cli.core.platform.utils.utils import (
    load_yaml_file,
    non_text_items,
    unreadable_file_problem,
    value_reading,
    yaml_error_line,
)

logger = logging.getLogger(__name__)


def get_agent_config(agent: str, rules_root: Path | None = None) -> AgentConfig:
    """Load agent config (excludes + overrides) from framework.

    Args:
        agent: Agent identifier (e.g., "claude")
        rules_root: Rules root to read from; the resolved default rules path when None

    Returns:
        AgentConfig with excludes and overrides, or defaults if missing/malformed
    """

    data = read_agent_config(get_agent_config_path(agent, rules_root))
    if data is None:
        return AgentConfig()
    return AgentConfig(
        prefix=as_str(data.get("prefix", "")),
        name=as_str(data.get("name", "")),
        excludes=str_list(data.get("excludes", [])),
        overrides={key: as_object(val) for key, val in as_object(data.get("overrides", {})).items()},
        subagent_hooks=_subagent_hooks(data.get("subagent_hooks")),
        intercept_events=_intercept_events(data.get("intercept_events")),
    )


def read_agent_config(config_path: Path) -> JsonObject | None:
    """Read an agent `config.yml` as its top-level mapping.

    An absent file reads as None. A file that cannot be read, is not UTF-8, is not valid YAML, is
    empty or is not a mapping is logged as a warning on each read and also reads as None.
    """
    if not config_path.exists():
        return None
    try:
        data = load_yaml_file(config_path)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        problem = unreadable_file_problem(exc)
    else:
        if not data:
            problem = "is empty"
        elif not isinstance(data, dict):
            problem = "is not a mapping"
        else:
            return data
    logger.warning("Skipping agent config %s: %s", config_path, problem)
    return None


def _hook_fact(raw: object) -> HookFact:
    """One `subagent_hooks` fact; a missing or malformed one reads as `unconfirmed`."""

    if not isinstance(raw, dict):
        return HookFact()
    value = str(raw.get("value", "unconfirmed"))
    fields = raw.get("fields")
    return HookFact(
        value=value if value in ("yes", "no") else "unconfirmed",
        source=str(raw.get("source", "")),
        fields=tuple(str(f) for f in fields) if isinstance(fields, list) else (),
    )


def _intercept_events(raw: object) -> dict[str, tuple[str, ...]]:
    """The optional top-level `intercept_events:` key: event name to the file tools it gates."""
    if not isinstance(raw, dict):
        return {}
    return {str(event): tuple(str(tool) for tool in tools) for event, tools in raw.items() if isinstance(tools, list)}


def _subagent_hooks(raw: object) -> SubagentHooks:
    """The optional top-level `subagent_hooks:` key of an agent's config.yml."""

    facts = raw if isinstance(raw, dict) else {}
    return SubagentHooks(
        fire_in_subagents=_hook_fact(facts.get("fire_in_subagents")),
        identifies_agent=_hook_fact(facts.get("identifies_agent")),
        extension_opt_out=_hook_fact(facts.get("extension_opt_out")),
    )


_SEGMENTATION_MODES = frozenset({"legacy", "structure-aware"})


def _coerce_segmentation(raw: object) -> str | None:
    """Coerce a `segmentation` value to a known mode, or None when absent/invalid."""
    if isinstance(raw, str) and raw in _SEGMENTATION_MODES:
        return raw
    if raw is not None:
        logger.warning("Unknown segmentation mode %r; falling back to 'legacy'", raw)
    return None


def _data_str_list(data: JsonObject, key: str) -> list[str]:
    """Coerce `data[key]` to a list of strings, or empty when absent / wrong shape."""
    return str_list(data.get(key))


def _data_str_dict(data: JsonObject, key: str) -> dict[str, dict[str, object]]:
    """Coerce `data[key]` to a `dict[str, dict]`, or empty when absent / wrong shape."""
    return {name: {**as_object(val)} for name, val in as_object(data.get(key)).items()}


def _coerce_rule_thresholds(raw: object) -> dict[str, dict[str, int]]:
    """Coerce `rule_thresholds` raw YAML data to `{rule_id: {arg: int}}`."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, int]] = {}
    for rule_id, args in raw.items():
        if isinstance(args, dict):
            out[str(rule_id)] = {str(k): v for k, v in args.items() if isinstance(v, int) and not isinstance(v, bool)}
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

    data = read_config_file(get_global_config_path())
    framework_path = data.get("framework_path")
    gs_raw = data.get("generic_scanning")
    generic_scanning = bool(gs_raw) if isinstance(gs_raw, bool) else None
    config = GlobalConfig(
        framework_path=Path(framework_path) if isinstance(framework_path, str) else None,
        default_agent=str(data.get("default_agent", "")) if isinstance(data.get("default_agent"), str) else "",
        tier=str(data.get("tier", "")) if isinstance(data.get("tier"), str) else "",
        rule_thresholds=_coerce_rule_thresholds(data.get("rule_thresholds")),
        generic_scanning=generic_scanning,
        agents=_data_str_dict(data, "agents"),
        surfaces=_data_str_dict(data, "surfaces"),
        segmentation=_coerce_segmentation(data.get("segmentation")),
    )
    for key in _GLOBAL_LIST_KEYS:
        setattr(config, key, _data_str_list(data, key))
    return config


def _deep_merge_config(base: JsonObject, overlay: JsonObject) -> JsonObject:
    """Deep-merge `overlay` onto `base` for project config layering.

    Object keys merge recursively. Array keys extend (overlay appended after
    base). Scalar keys are replaced by overlay. Used to layer
    `.ails/config.local.yml` on top of `.ails/config.yml`.
    """
    if not overlay:
        return base
    if not base:
        return dict(overlay)
    merged: JsonObject = dict(base)
    for key, ov in overlay.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(ov, dict):
            merged[key] = _deep_merge_config(existing, ov)
        elif isinstance(existing, list) and isinstance(ov, list):
            merged[key] = list(existing) + [v for v in ov if v not in existing]
        else:
            merged[key] = ov
    return merged


def read_config_file(config_path: Path, check_items: bool = True) -> JsonObject:
    """Read a config file's top-level mapping; an absent or empty file reads as an empty mapping.

    Raises ConfigUnreadableError naming the file and the problem (with its line)
    when the file cannot be read, is not UTF-8, is not valid YAML, or is not a mapping.
    With `check_items` (the default) it also raises for a setting of the wrong shape: a list
    holding a non-text item, an `agents` / `surfaces` entry that is not a mapping, or a
    `rule_thresholds` value that is not a whole number. A caller
    that is about to replace such a setting passes False and gets the mapping as written.
    """
    if not config_path.exists():
        return {}
    try:
        data = load_yaml_file(config_path)
    except (yaml.YAMLError, OSError, ValueError) as exc:  # ValueError: not UTF-8
        raise ConfigUnreadableError(f"{config_path}: {yaml_error_line(exc)}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigUnreadableError(f"{config_path}: the file is not a mapping of settings")
    if check_items:
        for key in TEXT_LIST_KEYS:
            _check_text_list(config_path, key, data.get(key))
        for key in _MAPPING_KEYS:
            _check_mapping(config_path, key, data.get(key))
        _check_thresholds(config_path, data.get("rule_thresholds"))
    return data


def _list_keys(config_cls: type) -> tuple[str, ...]:
    """The fields of a config dataclass that hold a list of names, read from the field types."""
    return tuple(name for name, kind in get_type_hints(config_cls).items() if kind == list[str])


# Config keys that hold a list of names: every such field of `ProjectConfig`; `GlobalConfig` carries a subset.
TEXT_LIST_KEYS = _list_keys(ProjectConfig)
_GLOBAL_LIST_KEYS = _list_keys(GlobalConfig)
_MAPPING_KEYS = ("agents", "surfaces")


def _check_text_list(config_path: Path, key: str, value: JsonValue) -> None:
    """Raise ConfigUnreadableError when `key` holds anything but a list of text items."""
    if value is None:
        return
    if not isinstance(value, list):
        raise ConfigUnreadableError(f"{config_path}: {key} must be a list of text items")
    for _, reading in non_text_items(value)[:1]:
        raise ConfigUnreadableError(f"{config_path}: {key}: {reading}")


def _check_mapping(config_path: Path, key: str, value: JsonValue) -> None:
    """Raise ConfigUnreadableError when `key` or one of its entries is not a mapping."""
    if value is None:
        return
    if not isinstance(value, dict):
        raise ConfigUnreadableError(f"{config_path}: {key} must be a mapping")
    for name, entry in value.items():
        if entry is not None and not isinstance(entry, dict):
            raise ConfigUnreadableError(f"{config_path}: {key}.{name} must be a mapping")


def _check_thresholds(config_path: Path, value: JsonValue) -> None:
    """Raise ConfigUnreadableError when `rule_thresholds` holds anything but whole numbers per rule."""
    if value is None:
        return
    if not isinstance(value, dict):
        raise ConfigUnreadableError(f"{config_path}: rule_thresholds must be a mapping")
    for rule, entry in value.items():
        if entry is None:
            continue
        if not isinstance(entry, dict):
            raise ConfigUnreadableError(f"{config_path}: rule_thresholds.{rule} must be a mapping")
        for key, number in entry.items():
            if isinstance(number, int) and not isinstance(number, bool):
                continue
            reading = value_reading(number)
            problem = f"{reading}; give a whole number" if number is None else f"{reading}, not a whole number"
            raise ConfigUnreadableError(f"{config_path}: rule_thresholds.{rule}.{key}: {problem}")


def get_project_config(project_root: Path) -> ProjectConfig:
    """Load project configuration from `.ails/config.yml` + `.ails/config.local.yml`.

    `.ails/config.local.yml` (gitignored) layers on top of the committed
    `.ails/config.yml` for personal / CI-specific overrides.

    Global defaults from `~/.reporails/config.yml` then merge under the
    project layer: list fields (`disabled_rules`, `exclude_dirs`,
    `packages`) extend with global entries the project didn't already
    declare; dict fields (`rule_thresholds`, `agents`, `surfaces`)
    deep-merge under project values; `default_agent` and
    `generic_scanning` use the project value when set, otherwise inherit
    from the global layer.

    Returns default config if neither file exists, still applying global
    defaults. Raises ConfigUnreadableError when any config file is unreadable.

    Args:
        project_root: Root directory of the project

    Returns:
        ProjectConfig with loaded or default values, layered with globals.
    """

    base = read_config_file(get_project_config_path(project_root))
    local = read_config_file(get_local_config_path(project_root))
    data = _deep_merge_config(base, local)
    global_cfg = get_global_config()

    if not data:
        return _apply_globals(ProjectConfig(), global_cfg)

    da = data.get("default_agent", "")
    gs_raw = data.get("generic_scanning")
    has_gs_in_project = isinstance(gs_raw, bool)
    seg = _coerce_segmentation(data.get("segmentation"))

    config = ProjectConfig(
        default_agent=da if isinstance(da, str) else "",
        agents=_data_str_dict(data, "agents"),
        surfaces=_data_str_dict(data, "surfaces"),
        rule_thresholds=_coerce_rule_thresholds(data.get("rule_thresholds")),
        generic_scanning=bool(gs_raw) if has_gs_in_project else False,
        mapper=MapperConfig(segmentation=seg or "legacy"),
    )
    for key in TEXT_LIST_KEYS:
        setattr(config, key, _data_str_list(data, key))
    return _apply_globals(
        config,
        global_cfg,
        has_project_generic_scanning=has_gs_in_project,
        has_project_segmentation=seg is not None,
    )


def _apply_globals(
    config: ProjectConfig,
    global_cfg: GlobalConfig,
    has_project_generic_scanning: bool = False,
    has_project_segmentation: bool = False,
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
    config.exclude_files = _extend_unique(config.exclude_files, global_cfg.exclude_files)
    config.packages = _extend_unique(config.packages, global_cfg.packages)
    config.rule_thresholds = _merge_thresholds(config.rule_thresholds, global_cfg.rule_thresholds)
    config.agents = _merge_under(config.agents, global_cfg.agents)
    config.surfaces = _merge_under(config.surfaces, global_cfg.surfaces)
    if not has_project_generic_scanning and global_cfg.generic_scanning is not None:
        config.generic_scanning = global_cfg.generic_scanning
    if not has_project_segmentation and global_cfg.segmentation is not None:
        config.mapper.segmentation = global_cfg.segmentation
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


def _merge_objects(project: dict[str, object], globals_: dict[str, object]) -> dict[str, object]:
    """Deep-merge `globals_` UNDER `project` — project wins on conflicting keys."""
    if not globals_:
        return project
    if not project:
        return dict(globals_)
    merged = dict(globals_)
    for key, project_val in project.items():
        global_val = merged.get(key)
        if isinstance(project_val, dict) and isinstance(global_val, dict):
            merged[key] = _merge_objects(project_val, global_val)
        else:
            merged[key] = project_val
    return merged


def _merge_under(
    project: dict[str, dict[str, object]], globals_: dict[str, dict[str, object]]
) -> dict[str, dict[str, object]]:
    """Merge `globals_` UNDER `project` per key — project wins on conflicting keys."""
    merged = dict(globals_)
    for key, project_val in project.items():
        merged[key] = _merge_objects(project_val, merged[key]) if key in merged else project_val
    return merged


def _merge_thresholds(
    project: dict[str, dict[str, int]], globals_: dict[str, dict[str, int]]
) -> dict[str, dict[str, int]]:
    """Merge `globals_` thresholds UNDER `project` per rule — project wins on conflicting args."""
    merged = dict(globals_)
    for rule_id, args in project.items():
        merged[rule_id] = {**merged.get(rule_id, {}), **args}
    return merged


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


def get_agent_config_path(agent: str, rules_root: Path | None = None) -> Path:
    """Get path to agent config file under ``rules_root`` (default rules path when None).

    The generic agent's config lives in core/ (not a separate directory).
    """
    dir_name = "core" if agent == "generic" else agent
    return (rules_root if rules_root is not None else get_rules_path()) / dir_name / "config.yml"


def iter_agent_configs(rules_dir: Path) -> Iterator[tuple[Path, JsonObject]]:
    """Each readable `*/config.yml` under `rules_dir`, in path order, as `(folder, parsed mapping)`.

    A config that `read_agent_config` cannot read is skipped.
    """
    for config_path in sorted(rules_dir.glob("*/config.yml")):
        data = read_agent_config(config_path)
        if data is not None:
            yield config_path.parent, data


def is_initialized() -> bool:
    """Check if rules are available (installed, config override, or bundled)."""
    rules_path = get_rules_path()
    return rules_path.is_dir() and (rules_path / "core").is_dir()
