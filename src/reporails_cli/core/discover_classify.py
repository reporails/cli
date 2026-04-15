"""Classification detection for backbone v3 discovery engine.

Detects project type, language, framework, and runtime.
Data-driven from bundled/project-types.yml.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.discover import (
    _find_manifests,
    _get_manifest_spec,
    _get_project_types,
    _read_manifest,
    _traverse_dotpath,
)


def _normalize_pypi_dep(dep: str) -> str:
    """Extract bare package name from a PEP 508 dependency string."""
    return dep.lower().split(">")[0].split("<")[0].split("=")[0].split("[")[0].strip()


def _collect_deps_from_manifest(target: Path, manifest: str) -> list[str]:
    """Collect lowercased dependency names from a manifest file."""
    spec = _get_manifest_spec(manifest)
    if not spec:
        return []

    dep_paths: list[str] = spec.get("dependency_paths", [])
    if not dep_paths:
        return []

    data = _read_manifest(target / manifest, spec["format"])
    deps: list[str] = []
    for dotpath in dep_paths:
        raw = _traverse_dotpath(data, dotpath)
        if raw is None:
            continue
        if isinstance(raw, list):
            # PEP 508 strings (pyproject.toml)
            if spec.get("language") == "python":
                deps.extend(_normalize_pypi_dep(d) for d in raw)
            else:
                deps.extend(str(d).lower() for d in raw)
        elif isinstance(raw, dict):
            deps.extend(str(d).lower() for d in raw)
    return deps


def _detect_js_runtime(target: Path, spec: dict[str, Any]) -> str:
    """Detect JavaScript runtime from lockfiles declared in manifest spec."""
    lockfiles: dict[str, list[str]] = spec.get("runtime_lockfiles", {})
    for runtime, files in lockfiles.items():
        if not files:
            continue
        if any((target / f).exists() for f in files):
            return runtime
    # Default: last entry with empty file list, or "node"
    for runtime, files in lockfiles.items():
        if not files:
            return runtime
    return "node"


def _detect_project_type(target: Path, manifests: list[str]) -> str | None:
    """Infer project type from directory shape and manifest entries."""
    if not manifests:
        return None

    if _detect_monorepo(target, manifests):
        return "monorepo"

    if (target / "app").is_dir():
        return "app"

    has_src = (target / "src").is_dir()
    has_tests = (target / "tests").is_dir() or (target / "test").is_dir()

    if has_src and has_tests and _has_cli_entry_points(target, manifests):
        return "cli"
    if has_src:
        return "library"
    return None


def _detect_monorepo(target: Path, manifests: list[str]) -> bool:
    """Check if project uses workspaces."""
    for manifest in manifests:
        spec = _get_manifest_spec(manifest)
        if not spec:
            continue
        workspace_path = spec.get("workspace_path")
        if not workspace_path:
            continue
        data = _read_manifest(target / manifest, spec["format"])
        if _traverse_dotpath(data, workspace_path):
            return True
    return False


def _has_cli_entry_points(target: Path, manifests: list[str]) -> bool:
    """Check if any manifest declares CLI entry points."""
    for manifest in manifests:
        spec = _get_manifest_spec(manifest)
        if not spec:
            continue
        cli_path = spec.get("cli_entry_path")
        if not cli_path:
            continue
        data = _read_manifest(target / manifest, spec["format"])
        if _traverse_dotpath(data, cli_path):
            return True
    return False


def detect_classification(target: Path) -> dict[str, Any]:
    """Detect project type, language, framework, and runtime."""
    manifests = _find_manifests(target)
    languages: list[str] = []
    runtime: str | None = None
    dep_strings: list[str] = []

    for manifest in manifests:
        spec = _get_manifest_spec(manifest)
        if not spec:
            continue

        lang = spec["language"]

        # TypeScript override
        ts_marker = spec.get("typescript_marker")
        if ts_marker and (target / ts_marker).exists():
            lang = "typescript"

        languages.append(lang)

        # Runtime detection
        if spec.get("runtime"):
            runtime = runtime or spec["runtime"]
        elif spec.get("runtime_lockfiles") and (not runtime or runtime == "cpython"):
            runtime = _detect_js_runtime(target, spec)

        dep_strings.extend(_collect_deps_from_manifest(target, manifest))

    # Framework detection
    pt = _get_project_types()
    framework: str | None = None
    for fw in pt["frameworks"]:
        if any(fw["match"] in d for d in dep_strings):
            framework = fw["name"]
            break

    return {
        "type": _detect_project_type(target, manifests),
        "language": languages or None,
        "framework": framework,
        "runtime": runtime,
    }
