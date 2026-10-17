"""A file the user left out is never linted or healed as its own file, on `ails check` and MCP `validate`."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.interfaces.cli.main import app
from reporails_cli.interfaces.mcp import tools

runner = CliRunner()

_has_onnx_model = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
).exists()
requires_model = pytest.mark.skipif(not _has_onnx_model, reason="Bundled ONNX model not available")

_LEFT_OUT = ("ext/notes.md", "ext/ref.md")

# (id, config body, command-line flags, surfaces that run it)
_CASES = [
    ("flag-folder", "", ["--exclude-dirs", "ext"], ("cli",)),
    ("config-folder", "exclude_dirs: [ext]\n", [], ("cli", "mcp")),
    ("flag-glob", "", ["--exclude-files", "ext/*.md"], ("cli",)),
    ("config-glob", "exclude_files: ['ext/*.md']\n", [], ("cli", "mcp")),
]
_PARAMS = [(c[0], c[1], c[2], surface) for c in _CASES for surface in c[3]]


@pytest.fixture(autouse=True)
def _offline_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.api_client.AilsClient.lint", lambda self, *args, **kwargs: None
    )
    clear_agent_cache()


def _project(tmp_path: Path, config: str) -> Path:
    project = tmp_path / "proj"
    (project / "ext").mkdir(parents=True)
    (project / ".ails").mkdir()
    (project / ".ails" / "config.yml").write_text("generic_scanning: true\n" + config, encoding="utf-8")
    (project / "CLAUDE.md").write_text(
        "# Proj\n\nAlways run the tests before pushing.\n\n@ext/notes.md\n\nSee [ref](ext/ref.md).\n",
        encoding="utf-8",
    )
    (project / "ext" / "notes.md").write_text(
        "You might maybe want to try to possibly consider things.\n\nAlways use tabs.\n", encoding="utf-8"
    )
    (project / "ext" / "ref.md").write_text(
        "Perhaps try stuff, it is good to be nice. Never skip tests.\n", encoding="utf-8"
    )
    return project


def _cli(project: Path, *args: str) -> dict[str, Any]:
    cwd = os.getcwd()
    os.chdir(project)
    try:
        result = runner.invoke(app, ["check", ".", "--agent", "claude", "-f", "json", *args])
    finally:
        os.chdir(cwd)
    assert result.exit_code in (0, 1), result.output
    return json.loads(result.output)  # type: ignore[no-any-return]


def _named_paths(payload: dict[str, Any]) -> set[str]:
    named = set(payload.get("files", {}))
    for entry in payload.get("files", {}).values():
        named.update(f["file"] for f in entry.get("findings", []) if "file" in f)
    named.update(c["file"] for c in payload.get("cross_file", []) if isinstance(c, dict) and "file" in c)
    return named


@requires_model
@pytest.mark.integration
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("case", "config", "flags", "surface"), _PARAMS, ids=[f"{p[0]}-{p[3]}" for p in _PARAMS])
def test_left_out_files_are_not_checked(tmp_path: Path, case: str, config: str, flags: list[str], surface: str) -> None:
    project = _project(tmp_path, config)
    payload = _cli(project, *flags) if surface == "cli" else tools.run_pipeline_for_path(str(project), full=True)[0]
    named = _named_paths(payload)
    assert "CLAUDE.md" in named
    assert not named & set(_LEFT_OUT), sorted(named)
    assert payload["excluded"]["dirs"] or payload["excluded"]["files"]
