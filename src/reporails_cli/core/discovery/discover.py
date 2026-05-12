"""Project-metadata detection — language, framework, paths, commands, manifests.

Pure-Python primitives that inspect a directory tree against the
`bundled/project-types.yml` registry. Used as building blocks by callers
that need to classify or summarize a project (e.g., scripts driving
external corpus runs). The CLI no longer surfaces these as a command;
add entries to `project-types.yml` to support new languages, frameworks,
and tools without code changes.
"""

from __future__ import annotations

import functools
import json
import tomllib
from pathlib import Path
from typing import Any

import yaml


def _load_project_types() -> dict[str, Any]:
    """Load and cache the bundled project-types.yml."""
    from reporails_cli.bundled import get_project_types_path

    path = get_project_types_path()
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data


@functools.lru_cache(maxsize=1)
def _get_project_types() -> dict[str, Any]:
    """Cached accessor for project types data."""
    return _load_project_types()


def _traverse_dotpath(data: dict[str, Any], path: str) -> Any:
    """Traverse a dot-separated path into nested dicts.

    Given ``"project.dependencies"`` and ``{"project": {"dependencies": [...]}}``,
    returns the list. Returns None if any segment is missing.
    """
    node: Any = data
    for key in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _read_json(path: Path) -> dict[str, Any]:
    """Read a JSON file, returning empty dict on failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _read_toml(path: Path) -> dict[str, Any]:
    """Read a TOML file, returning empty dict on failure."""
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read a YAML file, returning empty dict on failure."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, yaml.YAMLError):
        return {}


def _read_manifest(path: Path, fmt: str) -> dict[str, Any]:
    """Read a manifest file based on its declared format."""
    if fmt == "toml":
        return _read_toml(path)
    if fmt == "json":
        return _read_json(path)
    if fmt == "yaml":
        return _read_yaml(path)
    return {}


def _find_manifests(target: Path) -> list[str]:
    """Return manifest filenames that exist, in priority order.

    Supports glob-based entries (e.g., ``*.sln``) — returns the first
    matching filename for those entries.
    """
    pt = _get_project_types()
    found: list[str] = []
    for m in pt["manifests"]:
        if m.get("glob"):
            matches = sorted(target.glob(m["file"]))
            if matches:
                found.append(matches[0].name)
        elif (target / m["file"]).exists():
            found.append(m["file"])
    return found


def _get_manifest_spec(filename: str) -> dict[str, Any] | None:
    """Look up the manifest spec for a given filename.

    For glob-based entries (e.g., ``*.sln``), matches if the filename
    fits the glob pattern.
    """
    pt = _get_project_types()
    for m in pt["manifests"]:
        if m.get("glob"):
            if Path(filename).match(m["file"]):
                return m  # type: ignore[no-any-return]
        elif m["file"] == filename:
            return m  # type: ignore[no-any-return]
    return None


def _detect_classification(target: Path) -> dict[str, Any]:
    """Detect project type, language, framework, and runtime. Delegates to discover_classify."""
    from reporails_cli.core.discovery.discover_classify import detect_classification

    return detect_classification(target)


def _detect_commands(target: Path) -> dict[str, str | None]:
    """Detect build/test/lint/format commands. Delegates to discover_commands."""
    from reporails_cli.core.discovery.discover_commands import detect_commands

    return detect_commands(target)


def _detect_version_file(target: Path) -> str | None:
    """Detect version file: standalone file or manifest with version field."""
    pt = _get_project_types()

    # Standalone version files
    for candidate in pt["meta"]["version_files"]:
        if (target / candidate).is_file():
            return str(candidate)

    # Fallback: manifest with embedded version
    for manifest in _find_manifests(target):
        spec = _get_manifest_spec(manifest)
        if not spec:
            continue
        version_path = spec.get("version_path")
        if not version_path:
            continue
        data = _read_manifest(target / manifest, spec["format"])
        if _traverse_dotpath(data, version_path):
            return manifest
    return None


def _detect_ci(target: Path) -> str | None:
    """Detect CI system from known file/directory patterns."""
    pt = _get_project_types()
    for pattern in pt["meta"]["ci_patterns"]:
        path = target / pattern["path"]
        if pattern["type"] == "dir":
            if path.is_dir():
                return pattern["display"]  # type: ignore[no-any-return]
        elif path.is_file():
            return pattern["display"]  # type: ignore[no-any-return]
    return None


def _detect_meta(target: Path) -> dict[str, str | None]:
    """Detect meta pointers: version file, changelog, manifest, CI."""
    pt = _get_project_types()
    manifests = _find_manifests(target)

    changelog: str | None = None
    for candidate in pt["meta"]["changelogs"]:
        if (target / candidate).is_file():
            changelog = candidate
            break

    return {
        "version_file": _detect_version_file(target),
        "changelog": changelog,
        "manifest": manifests[0] if manifests else None,
        "ci": _detect_ci(target),
    }


def _detect_paths(target: Path) -> dict[str, str | None]:
    """Detect project directory structure for backbone v3 paths section."""
    pt = _get_project_types()
    paths: dict[str, str | None] = dict.fromkeys(pt["paths"])

    for key, candidates in pt["paths"].items():
        for candidate in candidates:
            candidate_path = target / candidate
            if candidate_path.is_dir():
                children = [c for c in candidate_path.iterdir() if c.is_dir() and not c.name.startswith((".", "__"))]
                if len(children) == 1 and key == "src":
                    paths[key] = children[0].relative_to(target).as_posix() + "/"
                else:
                    paths[key] = candidate + "/"
                break

    return paths


def _strip_nulls(data: Any) -> Any:
    """Recursively strip null values from dicts."""
    if isinstance(data, dict):
        return {k: _strip_nulls(v) for k, v in data.items() if v is not None}
    if isinstance(data, list):
        return [_strip_nulls(item) for item in data]
    return data
