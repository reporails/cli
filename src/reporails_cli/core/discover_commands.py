"""Command detection for backbone v3 discovery engine.

Detects build/test/lint/format commands from task runners, manifest scripts,
Makefiles, and tool config files. Data-driven from bundled/project-types.yml.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.discover import (
    _get_project_types,
    _read_json,
    _read_toml,
    _traverse_dotpath,
)


def _detect_task_runner_commands(
    target: Path,
    commands: dict[str, str | None],
) -> None:
    """Fill commands from YAML-declared task runners (mutates commands dict)."""
    pt = _get_project_types()
    pyproject = target / "pyproject.toml"
    if not pyproject.exists():
        return
    data = _read_toml(pyproject)

    for runner in pt["task_runners"]:
        tasks = _traverse_dotpath(data, runner["config_path"])
        if not tasks or not isinstance(tasks, dict):
            continue
        prefix = runner["command_prefix"]
        for key in list(commands):
            if key in tasks:
                task = tasks[key]
                if isinstance(task, str) or (isinstance(task, dict) and task.get("cmd")):
                    commands[key] = f"{prefix} {key}"
        # Test aliases (e.g., "qa" → test fallback)
        for alias in runner.get("test_aliases", []):
            if not commands["test"] and alias in tasks:
                commands["test"] = f"{prefix} {alias}"


def _detect_script_source_commands(
    target: Path,
    commands: dict[str, str | None],
) -> None:
    """Fill commands from YAML-declared script sources (mutates commands dict)."""
    pt = _get_project_types()
    for source in pt["script_sources"]:
        if source.get("type") == "makefile":
            _detect_makefile_commands(target, commands, source["command_prefix"])
            continue

        source_file = target / source["file"]
        if not source_file.exists():
            continue

        scripts_path = source.get("scripts_path")
        if not scripts_path:
            continue

        data = _read_json(source_file)
        scripts = _traverse_dotpath(data, scripts_path)
        if not isinstance(scripts, dict):
            continue

        prefix = source["command_prefix"]
        for key in commands:
            if not commands[key] and key in scripts:
                commands[key] = f"{prefix} {key}"


def _detect_makefile_commands(
    target: Path,
    commands: dict[str, str | None],
    prefix: str,
) -> None:
    """Fill commands from Makefile targets (mutates commands dict)."""
    makefile = target / "Makefile"
    if not makefile.exists():
        return
    try:
        content = makefile.read_text(encoding="utf-8")
    except OSError:
        return
    command_keys = set(commands)
    for line in content.splitlines():
        if line and not line[0].isspace() and ":" in line:
            make_target = line.split(":")[0].strip()
            if make_target in command_keys and not commands[make_target]:
                commands[make_target] = f"{prefix} {make_target}"


def _infer_tool_commands(target: Path, commands: dict[str, str | None]) -> None:
    """Infer remaining commands from YAML-declared tool config checks."""
    pt = _get_project_types()
    tool_cmds: dict[str, list[dict[str, Any]]] = pt.get("tool_commands", {})

    for cmd_key, probes in tool_cmds.items():
        if commands.get(cmd_key):
            continue  # Already filled by higher-priority source
        for probe in probes:
            if _probe_matches(target, probe):
                commands[cmd_key] = probe["command"]
                break


def _probe_matches(target: Path, probe: dict[str, Any]) -> bool:
    """Check if a tool command probe matches the target project."""
    # Direct file check (supports glob patterns like *.sln)
    if "file" in probe and "config_paths" not in probe:
        filename: str = probe["file"]
        if "*" in filename:
            return bool(sorted(target.glob(filename)))
        return (target / filename).exists()

    # Config path check within a file
    if "config_paths" in probe:
        config_file = target / probe.get("config_file", "pyproject.toml")
        if not config_file.exists():
            return False
        data = _read_toml(config_file) if config_file.name.endswith(".toml") else _read_json(config_file)
        return bool(any(_traverse_dotpath(data, cp) is not None for cp in probe["config_paths"]))

    return False


def detect_commands(target: Path) -> dict[str, str | None]:
    """Detect build/test/lint/format commands from task runners and manifests.

    Priority: explicit task runner > manifest scripts > Makefile > inferred from tool configs.
    """
    commands: dict[str, str | None] = {"build": None, "test": None, "lint": None, "format": None}

    # 1. Task runners (poe, taskipy)
    _detect_task_runner_commands(target, commands)

    # 2. Script sources (package.json scripts, Makefile)
    _detect_script_source_commands(target, commands)

    # 3. Infer from tool configs
    _infer_tool_commands(target, commands)

    return commands
